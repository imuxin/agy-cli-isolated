import { execFileSync } from "node:child_process"
import { randomBytes } from "node:crypto"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"

export class ProfileError extends Error {
  constructor(message) {
    super(`agy profile: ${message}`)
    this.name = "ProfileError"
  }
}

// Binary discovery keeps the real home. Only agy and security receive this home.
export function accountProfile(env = process.env, platform = process.platform, home = os.homedir()) {
  const mode = env.AGY_BRIDGE_PROFILE || (platform === "darwin" ? "isolated" : "shared")
  if (!["isolated", "shared"].includes(mode)) throw new ProfileError("AGY_BRIDGE_PROFILE must be isolated or shared")
  if (mode === "shared") {
    if (env.AGY_BRIDGE_PROFILE_DIR) throw new ProfileError("AGY_BRIDGE_PROFILE_DIR requires isolated mode")
    return null
  }
  if (platform !== "darwin") throw new ProfileError("isolated mode currently requires macOS")
  const root = env.AGY_BRIDGE_PROFILE_DIR || path.join(env.XDG_STATE_HOME || path.join(home, ".local", "state"), "magpie-agy-bridge", "profile")
  if (!path.isAbsolute(root)) throw new ProfileError("AGY_BRIDGE_PROFILE_DIR must be an absolute path")
  const profile = {
    root: path.resolve(root),
    home: path.join(root, "home"),
    gemini: path.join(root, "home", ".gemini"),
    stateFile: path.join(root, "state", "sessions.json"),
    keychain: path.join(root, "home", "Library", "Keychains", "account.keychain-db"),
    passwordFile: path.join(root, "keychain-password"),
  }
  const overrides = {
    AGY_BRIDGE_GEMINI_DIR: profile.gemini,
    AGY_BRIDGE_STATE_FILE: profile.stateFile,
    AGY_BRIDGE_CONVERSATIONS_DIR: path.join(profile.gemini, "antigravity-cli", "conversations"),
  }
  for (const [name, expected] of Object.entries(overrides)) {
    if (env[name] && path.resolve(env[name]) !== expected) throw new ProfileError(`${name} conflicts with the profile; remove it or use ${expected}`)
  }
  if (env.AGY_BRIDGE_STORED_SIGNIN === "skip") throw new ProfileError("AGY_BRIDGE_STORED_SIGNIN=skip is incompatible with isolated mode")
  return profile
}

export function profileEnv(env, profile) {
  if (!profile) return { ...env }
  const result = {
    ...env,
    AGY_BRIDGE_PROFILE_DIR: profile.root,
    HOME: profile.home,
    XDG_CONFIG_HOME: path.join(profile.home, ".config"),
    XDG_CACHE_HOME: path.join(profile.home, ".cache"),
    XDG_DATA_HOME: path.join(profile.home, ".local", "share"),
    XDG_STATE_HOME: path.join(profile.root, "state"),
  }
  // These select a different authentication source instead of the profile's Google account.
  for (const name of ["GEMINI_API_KEY", "GOOGLE_API_KEY", "AGY_ADC_AUTH", "GOOGLE_GENAI_USE_VERTEXAI", "GOOGLE_APPLICATION_CREDENTIALS"]) delete result[name]
  return result
}

const PREPARE_TTL_MS = 30_000
const preparedProfiles = new Map()

export function forgetPreparedProfiles() {
  preparedProfiles.clear()
}

function runSecurity(args, env, timeout) {
  try {
    return execFileSync("/usr/bin/security", args, { env, encoding: "utf8", timeout, stdio: ["ignore", "pipe", "pipe"] })
  } catch {
    // execFileSync errors contain the command, including a keychain password.
    throw new ProfileError(`security ${args[0]} failed; no agy process was started`)
  }
}

function keychainPaths(output) {
  return [...String(output).matchAll(/"([^"]+)"/g)].map(match => fs.realpathSync(match[1]))
}

function stateSignature(keychain, preferences, password) {
  let kc, pref
  try {
    kc = fs.lstatSync(keychain)
    pref = fs.lstatSync(preferences)
  } catch (error) {
    if (error.code === "ENOENT") return null
    throw error
  }
  if (!kc.isFile() || !pref.isFile()) return null
  return `${fs.realpathSync(keychain)}\0${kc.dev}:${kc.ino}\0${pref.dev}:${pref.ino}:${pref.size}:${pref.mtimeMs}\0${password}`
}

// All credential-bearing directories are real, private directories. Never mirror the host home.
export function prepareProfile(profile, env = process.env, { security = runSecurity, deadline = Date.now() + 10_000, fresh = false } = {}) {
  const run = (args, child) => {
    const remaining = deadline - Date.now()
    if (remaining <= 0) throw new ProfileError("keychain preparation timed out")
    return security(args, child, Math.max(1, Math.min(remaining, 10_000)))
  }
  if (!profile) return profileEnv(env, null)
  if (deadline - Date.now() <= 0) {
    preparedProfiles.delete(profile.root)
    throw new ProfileError("keychain preparation timed out")
  }
  try {
    for (const directory of [profile.root, profile.home, profile.gemini, path.dirname(profile.stateFile), path.dirname(profile.keychain), path.join(profile.home, "Library", "Preferences")]) {
      const relative = path.relative(profile.root, directory)
      let current = profile.root
      for (const part of ["", ...relative.split(path.sep).filter(Boolean)]) {
        if (part) current = path.join(current, part)
        fs.mkdirSync(current, { recursive: true, mode: 0o700 })
        const info = fs.lstatSync(current)
        if (!info.isDirectory()) throw new ProfileError(`${current} must be a real directory`)
        fs.chmodSync(current, 0o700)
      }
    }
    const preferences = path.join(profile.home, "Library", "Preferences", "com.apple.security.plist")
    for (const file of [profile.keychain, profile.passwordFile, preferences]) {
      let info
      try { info = fs.lstatSync(file) } catch (error) { if (error.code !== "ENOENT") throw error }
      if (info && !info.isFile()) throw new ProfileError(`${file} must be a real file`)
    }
    let password
    if (fs.existsSync(profile.passwordFile)) {
      password = fs.readFileSync(profile.passwordFile, "utf8")
      if (!/^[a-f0-9]{64}$/.test(password)) throw new ProfileError("invalid keychain-password file")
      fs.chmodSync(profile.passwordFile, 0o600)
    } else {
      if (fs.existsSync(profile.keychain)) throw new ProfileError("keychain-password is missing; restore the profile backup")
      password = randomBytes(32).toString("hex")
      fs.writeFileSync(profile.passwordFile, password, { flag: "wx", mode: 0o600 })
    }
    const child = profileEnv(env, profile)
    const signature = !fresh ? stateSignature(profile.keychain, preferences, password) : null
    const cached = signature ? preparedProfiles.get(profile.root) : null
    if (cached && cached.security === security && cached.signature === signature && Date.now() - cached.at < PREPARE_TTL_MS) {
      return child
    }
    if (!fs.existsSync(profile.keychain)) {
      run(["create-keychain", "-p", password, profile.keychain], child)
    }
    // Keep background token renewal usable for long-lived ACP processes. The random
    // password is kept locally (0600); the keychain stays unlocked for the OS session.
    run(["set-keychain-settings", profile.keychain], child)
    run(["list-keychains", "-d", "user", "-s", profile.keychain], child)
    run(["default-keychain", "-d", "user", "-s", profile.keychain], child)
    run(["unlock-keychain", "-p", password, profile.keychain], child)
    const expected = fs.realpathSync(profile.keychain)
    for (const command of ["default-keychain", "list-keychains"]) {
      const paths = keychainPaths(run([command, "-d", "user"], child))
      if (paths.length !== 1 || paths[0] !== expected) throw new ProfileError(`private ${command} verification failed`)
    }
    if (!fs.lstatSync(preferences).isFile()) throw new ProfileError("private keychain preferences were not created")
    const verifiedSignature = stateSignature(profile.keychain, preferences, password)
    if (verifiedSignature) {
      preparedProfiles.set(profile.root, { security, signature: verifiedSignature, at: Date.now() })
    }
    return child
  } catch (error) {
    preparedProfiles.delete(profile.root)
    if (error instanceof ProfileError) throw error
    throw new ProfileError(`cannot prepare ${profile.root} (${error.code || "invalid profile"})`)
  }
}

// Called after the caller's environment overrides have been merged, so host auth
// variables cannot be introduced again by a later merge with process.env.
export function agyEnvironment(env = process.env, options) {
  return prepareProfile(accountProfile(env), env, options)
}
