/*
 * Manual macOS integration check; intentionally not a .test file.
 * From agy-cli, explicitly run either:
 *   node test/macos-profile.mjs
 *   bun test/macos-profile.mjs
 *
 * Creates two temporary profiles with real prepareProfile/security calls.
 * Uses only synthetic gemini/antigravity tokens and a temporary fake agy;
 * never starts the installed agy, signs in to Google, or reads host credentials.
 * Host reads are limited to default/list keychain metadata and security plist
 * metadata/bytes (including ByHost variants). Keep host keychain settings idle
 * during this check: any concurrent change also fails the equality checks.
 * Output contains booleans only; failures exit nonzero without error details.
 * finally attempts every private keychain deletion, removes the temporary tree,
 * and independently rechecks host settings, including after cleanup failures.
 */
import { execFileSync } from "node:child_process"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { accountProfile, prepareProfile, profileEnv } from "../profile.mjs"
import { readStoredSignIn, storedEmail } from "../signin.mjs"
import { spawnAgy } from "../platform.mjs"

function ensure(condition) {
  if (!condition) throw new Error("verification failed")
}

function runSecurity(args, env) {
  try {
    return execFileSync("/usr/bin/security", args, {
      env, encoding: "utf8", timeout: 10_000,
      stdio: ["ignore", "pipe", "pipe"],
    })
  } catch {
    // Never propagate execFileSync's command, password, stdout, or stderr.
    throw new Error("security failed")
  }
}

function syntheticToken(email, revision) {
  return "go-keyring-base64:" + Buffer.from(JSON.stringify({
    token: {
      access_token: `synthetic-access-${email}-${revision}`,
      refresh_token: `synthetic-refresh-${email}-${revision}`,
      expiry: "2099-01-01T00:00:00Z",
      expires_in: 3600,
      token_type: "Bearer",
    },
    auth_method: "consumer",
    id_token_email: email,
  })).toString("base64")
}

function verifyPrivateSearch(keychain, env) {
  const expected = fs.realpathSync(keychain)
  for (const command of ["default-keychain", "list-keychains"]) {
    const output = runSecurity([command, "-d", "user"], env)
    const paths = [...output.matchAll(/"([^"]+)"/g)].map(match => fs.realpathSync(match[1]))
    ensure(paths.length === 1 && paths[0] === expected)
  }
}

// Serialized into a standalone temporary .mjs, run in a fresh Node/Bun process.
function fakeAgy() {
  const [home, keychain, email, previousText, nextText] = process.argv.slice(2)
  const previous = Number(previousText)
  const next = Number(nextText)
  ensure(fs.realpathSync(process.env.HOME) === home)
  ensure(fs.realpathSync(process.env.AGY_BRIDGE_GEMINI_DIR) === path.join(home, ".gemini"))
  // Verify metadata BEFORE any implicit credential read, so a broken search
  // configuration fails without reading a real host gemini credential.
  verifyPrivateSearch(keychain, process.env)
  const file = path.join(process.env.HOME, ".gemini", "fake-agy.json")
  const record = JSON.parse(fs.readFileSync(file, "utf8"))
  ensure(record.email === email && record.revision === previous)
  const find = ["find-generic-password", "-s", "gemini", "-a", "antigravity", "-w"]
  ensure(runSecurity(find, process.env).trim() === syntheticToken(email, previous))
  if (next !== previous) {
    // Both find and add intentionally omit a keychain, like go-keyring.
    runSecurity(["add-generic-password", "-U", "-s", "gemini", "-a", "antigravity",
      "-w", syntheticToken(email, next)], process.env)
    fs.writeFileSync(file, JSON.stringify({ email, revision: next }), { mode: 0o600 })
  }
  ensure(runSecurity(find, process.env).trim() === syntheticToken(email, next))
  const written = JSON.parse(fs.readFileSync(file, "utf8"))
  ensure(written.email === email && written.revision === next)
}

function securityPreferences(home) {
  const preferences = path.join(home, "Library", "Preferences")
  const files = []
  for (const directory of [preferences, path.join(preferences, "ByHost")]) {
    let names
    try { names = fs.readdirSync(directory) } catch (error) {
      if (error.code === "ENOENT") continue
      throw error
    }
    for (const name of names.sort()) {
      if (!/^com\.apple\.security(?:[.-][^/]+)?\.plist$/.test(name)) continue
      const file = path.join(directory, name)
      const info = fs.lstatSync(file)
      ensure(info.isFile())
      files.push({ file, mode: info.mode, uid: info.uid, gid: info.gid, bytes: fs.readFileSync(file) })
    }
  }
  return files
}

function hostSnapshot(env, home) {
  return {
    defaultKeychain: runSecurity(["default-keychain", "-d", "user"], env),
    keychains: runSecurity(["list-keychains", "-d", "user"], env),
    preferences: securityPreferences(home),
  }
}

function sameHost(before, after) {
  return Boolean(before && after && before.defaultKeychain === after.defaultKeychain &&
    before.keychains === after.keychains && before.preferences.length === after.preferences.length &&
    before.preferences.every((file, index) => {
      const other = after.preferences[index]
      return file.file === other.file && file.mode === other.mode && file.uid === other.uid &&
        file.gid === other.gid && file.bytes.equals(other.bytes)
    }))
}

function runFake(file, entry, previous, next, cwd) {
  return new Promise((resolve, reject) => {
    // spawnAgy really calls prepareProfile again; it is not mocked here.
    const child = spawnAgy(process.execPath,
      [file, entry.profile.home, entry.profile.keychain, entry.email, String(previous), String(next)],
      { env: entry.env, cwd, stdio: "ignore" })
    const timer = setTimeout(() => child.kill("SIGKILL"), 30_000)
    child.once("error", () => {
      clearTimeout(timer)
      reject(new Error("fake agy failed"))
    })
    child.once("close", (code, signal) => {
      clearTimeout(timer)
      if (code === 0 && !signal) resolve()
      else reject(new Error("fake agy failed"))
    })
  })
}

async function signIn(entry) {
  const value = await readStoredSignIn({ env: entry.env })
  ensure(value.state === "present" && value.canRenew && !value.expired)
  ensure(await storedEmail({ env: entry.env }) === entry.email)
  return value
}

function homeRecord(entry) {
  return fs.readFileSync(path.join(entry.profile.home, ".gemini", "fake-agy.json"))
}

async function main() {
  const result = {
    macOS: process.platform === "darwin",
    profilesPrepared: false,
    distinctSignIns: false,
    homeIsolation: false,
    restartPersistence: false,
    privateRefreshIsolation: false,
    hostUnchangedBeforeCleanup: false,
    keychainsDeleted: false,
    temporaryDirectoryRemoved: false,
    hostUnchangedAfterCleanup: false,
    success: false,
  }
  if (!result.macOS) {
    console.log(JSON.stringify(result))
    process.exitCode = 1
    return
  }

  let temporary
  let hostEnv
  let hostHome
  let before
  let completed = false
  let failed = false
  const entries = []
  try {
    hostHome = fs.realpathSync(os.homedir())
    hostEnv = { ...process.env, HOME: hostHome }
    before = hostSnapshot(hostEnv, hostHome)
    temporary = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "agy-macos-profile-"))
    // /var and /private/var must compare as the same root on macOS.
    temporary = fs.realpathSync(temporary)
    fs.chmodSync(temporary, 0o700)
    for (const name of ["alpha", "beta"]) {
      const directory = path.join(temporary, name)
      fs.mkdirSync(directory, { mode: 0o700 })
      const root = fs.realpathSync(directory)
      const env = {
        ...process.env,
        AGY_BRIDGE_PROFILE: "isolated",
        AGY_BRIDGE_PROFILE_DIR: root,
        AGY_BRIDGE_GEMINI_DIR: path.join(root, "home", ".gemini"),
        AGY_BRIDGE_STATE_FILE: path.join(root, "state", "sessions.json"),
        AGY_BRIDGE_CONVERSATIONS_DIR: path.join(root, "home", ".gemini", "antigravity-cli", "conversations"),
        AGY_BRIDGE_STORED_SIGNIN: "",
      }
      const profile = accountProfile(env)
      const entry = { profile, env, email: `${name}@example.invalid` }
      // Register before preparing: even partial creation must be cleaned up.
      entries.push(entry)
      entry.env = prepareProfile(profile, env)
      verifyPrivateSearch(profile.keychain, entry.env)
      ensure(sameHost(before, hostSnapshot(hostEnv, hostHome)))
      runSecurity(["add-generic-password", "-s", "gemini", "-a", "antigravity",
        "-w", syntheticToken(entry.email, 0), profile.keychain], entry.env)
      fs.writeFileSync(path.join(profile.gemini, "fake-agy.json"),
        JSON.stringify({ email: entry.email, revision: 0 }), { flag: "wx", mode: 0o600 })
    }
    result.profilesPrepared = true
    const [alpha, beta] = entries
    const alphaInitial = await signIn(alpha)
    const betaInitial = await signIn(beta)
    ensure(alpha.email !== beta.email && alphaInitial.fp !== betaInitial.fp)
    result.distinctSignIns = true

    const fake = path.join(temporary, "fake-agy.mjs")
    fs.writeFileSync(fake, [
      'import { execFileSync } from "node:child_process"',
      'import fs from "node:fs"',
      'import path from "node:path"',
      ...[ensure, runSecurity, syntheticToken, verifyPrivateSearch, fakeAgy].map(fn => fn.toString()),
      'try { fakeAgy() } catch { process.exitCode = 1 }',
    ].join("\n"), { flag: "wx", mode: 0o600 })

    const betaUntouched = homeRecord(beta)
    await runFake(fake, alpha, 0, 1, temporary)
    ensure(homeRecord(beta).equals(betaUntouched))
    ensure((await signIn(beta)).fp === betaInitial.fp)
    const alphaUntouched = homeRecord(alpha)
    const alphaOnce = await signIn(alpha)
    await runFake(fake, beta, 0, 1, temporary)
    ensure(homeRecord(alpha).equals(alphaUntouched))
    ensure((await signIn(alpha)).fp === alphaOnce.fp)
    result.homeIsolation = true

    const betaBeforeRefresh = await signIn(beta)
    const betaFileBeforeRefresh = homeRecord(beta)
    // A second independent process reads revision 1 and writes revision 2.
    await runFake(fake, alpha, 1, 2, temporary)
    ensure((await signIn(alpha)).fp !== alphaOnce.fp)
    ensure(homeRecord(beta).equals(betaFileBeforeRefresh))
    ensure((await signIn(beta)).fp === betaBeforeRefresh.fp)
    result.privateRefreshIsolation = true
    // Restart beta too, checking persistence without refreshing its token.
    await runFake(fake, beta, 1, 1, temporary)
    ensure(homeRecord(beta).equals(betaFileBeforeRefresh))
    ensure((await signIn(beta)).fp === betaBeforeRefresh.fp)
    result.restartPersistence = true
    completed = true
  } catch {
    // Imported profile helpers and child errors are never printed either.
    failed = true
  } finally {
    try {
      result.hostUnchangedBeforeCleanup = sameHost(before, hostSnapshot(hostEnv, hostHome))
    } catch { failed = true }

    let deleted = true
    for (const entry of entries) {
      try {
        if (fs.existsSync(entry.profile.keychain)) {
          // Do not prepare again here or pass the host HOME to deletion.
          runSecurity(["delete-keychain", entry.profile.keychain], profileEnv(entry.env, entry.profile))
        }
        ensure(!fs.existsSync(entry.profile.keychain))
      } catch {
        deleted = false
        failed = true
      }
    }
    result.keychainsDeleted = entries.length === 2 && deleted
    try {
      if (temporary) {
        fs.rmSync(temporary, { recursive: true, force: true })
        result.temporaryDirectoryRemoved = !fs.existsSync(temporary)
      }
    } catch { failed = true }
    // This must run independently of every deletion/removal outcome above.
    try {
      result.hostUnchangedAfterCleanup = sameHost(before, hostSnapshot(hostEnv, hostHome))
    } catch { failed = true }
  }
  result.success = completed && !failed && Object.entries(result)
    .filter(([name]) => name !== "success").every(([, value]) => value)
  console.log(JSON.stringify(result))
  if (!result.success) process.exitCode = 1
}

await main().catch(() => {
  // Last resort: never let a runtime print an exception with captured secrets.
  console.log(JSON.stringify({ success: false }))
  process.exitCode = 1
})
