// No real security process is started here. The macOS integration check is
// explicitly opt-in: see test/macos-profile.mjs (do not run it via bun test).
import { afterEach, expect, test } from "bun:test"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { isDeepStrictEqual } from "node:util"
import { accountProfile, agyEnvironment, forgetPreparedProfiles, prepareProfile, profileEnv, ProfileError } from "./profile.mjs"
import { backgroundBlocked, forgetStoredSignIn, readStoredSignIn, storedEmail, storedSignIn } from "./signin.mjs"

const temporary = []
const AUTH = {
  GEMINI_API_KEY: "synthetic-gemini-key",
  GOOGLE_API_KEY: "synthetic-google-key",
  AGY_ADC_AUTH: "1",
  GOOGLE_GENAI_USE_VERTEXAI: "true",
  GOOGLE_APPLICATION_CREDENTIALS: "/synthetic/credentials.json",
}
const CANARY = "synthetic-secret-must-not-escape"
const STORED = "go-keyring-base64:" + Buffer.from(JSON.stringify({
  token: { access_token: "synthetic-access", refresh_token: "synthetic-refresh", expiry: "2099-01-01T00:00:00Z" },
  auth_method: "consumer",
  id_token_email: "private@example.invalid",
})).toString("base64")

function fixture() {
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "agy-profile-unit-")))
  temporary.push(base)
  const env = {
    HOME: path.join(base, "host"),
    PATH: "/synthetic/bin",
    AGY_BRIDGE_PROFILE: "isolated",
    AGY_BRIDGE_PROFILE_DIR: path.join(base, "private account"),
  }
  const profile = accountProfile(env, "darwin", env.HOME)
  return { base, env, profile }
}

function preferences(profile) {
  return path.join(profile.home, "Library", "Preferences", "com.apple.security.plist")
}

// Real empty files matter: prepareProfile canonicalizes quoted security output
// with realpathSync and requires a regular private preferences file.
function fakeSecurity(profile, { failAt = -1, output, createKeychain = true, createPreferences = true } = {}) {
  const calls = []
  const security = (args, env) => {
    const index = calls.length
    calls.push({ args: [...args], env: { ...env } })
    if (index === failAt) {
      const password = fs.readFileSync(profile.passwordFile, "utf8")
      const error = new Error(`security ${args.join(" ")} ${password} ${CANARY}`)
      error.code = "ESECURITY"
      error.stdout = CANARY
      error.stderr = password
      throw error
    }
    if (args[0] === "create-keychain" && createKeychain) fs.writeFileSync(profile.keychain, "", { mode: 0o600 })
    if (["list-keychains", "default-keychain"].includes(args[0])) {
      if (args.includes("-s")) {
        if (createPreferences) fs.writeFileSync(preferences(profile), "synthetic preferences", { mode: 0o600 })
      } else {
        return output ? output(args[0]) : `    "${profile.keychain}"\n`
      }
    }
    return ""
  }
  return { security, calls }
}

function caught(fn) {
  try { fn() } catch (error) { return error }
  throw new Error("expected preparation to fail")
}

function expectSafe(error, password = "") {
  expect(error instanceof ProfileError).toBe(true)
  const text = [String(error), error.stack, JSON.stringify(error)].join("\n")
  // Boolean assertions keep a failing assertion from printing any password.
  expect(text.includes(CANARY)).toBe(false)
  if (password) expect(text.includes(password)).toBe(false)
  expect(error.cause).toBeUndefined()
}

afterEach(() => {
  forgetStoredSignIn({ dead: true })
  forgetPreparedProfiles()
  for (const directory of temporary.splice(0)) fs.rmSync(directory, { recursive: true, force: true })
})

test("macOS and Linux default to isolated; other platforms default to shared", () => {
  const home = path.resolve(os.tmpdir(), "synthetic-host")
  const root = path.join(home, ".local", "state", "magpie-agy-bridge", "profile")
  expect(accountProfile({}, "darwin", home).root).toBe(root)
  expect(accountProfile({}, "linux", home).root).toBe(root)
  for (const platform of ["win32", "freebsd"]) {
    expect(accountProfile({}, platform, home)).toBeNull()
    expect(() => accountProfile({ AGY_BRIDGE_PROFILE: "isolated" }, platform, home)).toThrow(ProfileError)
  }
  expect(accountProfile({ AGY_BRIDGE_PROFILE: "shared" }, "darwin", home)).toBeNull()
  const state = path.join(home, "custom-state")
  expect(accountProfile({ XDG_STATE_HOME: state }, "darwin", home).root)
    .toBe(path.join(state, "magpie-agy-bridge", "profile"))
})

test("Linux agy uses a private SSH-session token file while preserving desktop D-Bus", async () => {
  const { env } = fixture()
  const parent = { ...env, ...AUTH, DBUS_SESSION_BUS_ADDRESS: "unix:path=/desktop/bus" }
  const opts = { env: parent, platform: "linux" }
  const profile = accountProfile(parent, "linux")
  const child = prepareProfile(profile, parent)
  expect(child.HOME).toBe(profile.home)
  expect(child.SSH_CONNECTION).toBe("127.0.0.1 0 127.0.0.1 0")
  expect(child.DBUS_SESSION_BUS_ADDRESS).toBe(parent.DBUS_SESSION_BUS_ADDRESS)
  expect(child.GEMINI_API_KEY).toBeUndefined()
  expect(fs.existsSync(path.join(profile.home, "Library"))).toBe(false)
  expect(await readStoredSignIn(opts)).toEqual({ state: "missing" })
  fs.writeFileSync(profile.tokenFile, JSON.stringify({ token: { refresh_token: "synthetic" }, id_token_email: "one@example.invalid" }), { mode: 0o644 })
  expect((await readStoredSignIn(opts)).state).toBe("present")
  expect(await storedEmail(opts)).toBe("one@example.invalid")
  expect(fs.statSync(profile.tokenFile).mode & 0o777).toBe(0o600)
  fs.writeFileSync(profile.tokenFile, "broken")
  await expect(readStoredSignIn(opts)).rejects.toThrow(ProfileError)
  fs.unlinkSync(profile.tokenFile)
  fs.symlinkSync("/invalid", profile.tokenFile)
  await expect(storedEmail(opts)).rejects.toThrow(ProfileError)
})

test("an isolated profile fixes every credential and session path under its root", () => {
  const { base, env, profile } = fixture()
  const root = env.AGY_BRIDGE_PROFILE_DIR
  expect(profile).toEqual({
    root,
    home: path.join(root, "home"),
    gemini: path.join(root, "home", ".gemini"),
    stateFile: path.join(root, "state", "sessions.json"),
    keychain: path.join(root, "home", "Library", "Keychains", "account.keychain-db"),
    passwordFile: path.join(root, "keychain-password"),
  })
  const overrides = {
    AGY_BRIDGE_GEMINI_DIR: profile.gemini,
    AGY_BRIDGE_STATE_FILE: profile.stateFile,
    AGY_BRIDGE_CONVERSATIONS_DIR: path.join(profile.gemini, "antigravity-cli", "conversations"),
  }
  expect(accountProfile({ ...env, XDG_STATE_HOME: path.join(base, "ignored-state"), ...overrides }, "darwin")).toEqual(profile)
  for (const name of Object.keys(overrides)) {
    expect(() => accountProfile({ ...env, [name]: path.join(base, "elsewhere") }, "darwin")).toThrow(ProfileError)
  }
})

test("invalid modes, shared directory conflicts, relative roots and skipped private auth are rejected", () => {
  const { env } = fixture()
  for (const overrides of [
    { AGY_BRIDGE_PROFILE: "invalid" },
    { AGY_BRIDGE_PROFILE: "shared" },
    { AGY_BRIDGE_PROFILE_DIR: "relative/profile" },
    { AGY_BRIDGE_STORED_SIGNIN: "skip" },
  ]) expect(() => accountProfile({ ...env, ...overrides }, "darwin")).toThrow(ProfileError)
  expect(() => accountProfile({ XDG_STATE_HOME: "relative/state" }, "darwin")).toThrow(ProfileError)
})

test("profileEnv removes every alternate auth source and redirects HOME/XDG without changing the host", () => {
  const { env, profile } = fixture()
  const host = Object.freeze({ ...env, ...AUTH, XDG_CONFIG_HOME: "/host/config", XDG_CACHE_HOME: "/host/cache", XDG_DATA_HOME: "/host/data", XDG_STATE_HOME: "/host/state", KEEP: "kept" })
  const before = { ...process.env }
  const child = profileEnv(host, profile)
  expect(child).toEqual({
    ...env,
    HOME: profile.home,
    XDG_CONFIG_HOME: path.join(profile.home, ".config"),
    XDG_CACHE_HOME: path.join(profile.home, ".cache"),
    XDG_DATA_HOME: path.join(profile.home, ".local", "share"),
    XDG_STATE_HOME: path.join(profile.root, "state"),
    KEEP: "kept",
  })
  for (const name of Object.keys(AUTH)) {
    expect(Object.hasOwn(child, name)).toBe(false)
    expect(host[name]).toBe(AUTH[name])
  }
  expect(host.HOME).toBe(env.HOME)
  expect(isDeepStrictEqual({ ...process.env }, before)).toBe(true)
  const shared = profileEnv(host, null)
  expect(shared).toEqual(host)
  expect(shared).not.toBe(host)
})

test("shared prepareProfile and agyEnvironment copy the merged environment without running security", () => {
  const env = Object.freeze({ ...AUTH, HOME: "/synthetic/host", AGY_BRIDGE_PROFILE: "shared" })
  let calls = 0
  const child = prepareProfile(null, env, { security() { calls++; throw new Error("must not run") } })
  expect(child).toEqual(env)
  expect(child).not.toBe(env)
  expect(calls).toBe(0)
  expect(agyEnvironment(env)).toEqual(env)
  expect(agyEnvironment(env)).not.toBe(env)
  // Invalid final overrides must fail before any default security implementation.
  expect(() => agyEnvironment({ ...env, AGY_BRIDGE_PROFILE: "invalid" })).toThrow(ProfileError)
  expect(() => agyEnvironment({ ...env, AGY_BRIDGE_PROFILE_DIR: "/conflict" })).toThrow(ProfileError)
})

test("private keychain creation uses a fresh nonempty random password and only private HOME", () => {
  const { env, profile } = fixture()
  const host = Object.freeze({ ...env, ...AUTH })
  const before = { ...process.env }
  const { security, calls } = fakeSecurity(profile)
  const child = prepareProfile(profile, host, { security })
  const password = fs.readFileSync(profile.passwordFile, "utf8")
  expect(/^[a-f0-9]{64}$/.test(password)).toBe(true)
  expect(new Set(password).size > 1).toBe(true)
  expect(calls.filter(call => call.args.includes("-p")).every(call => call.args[2] === password)).toBe(true)
  const commands = calls.map(({ args }) => args.map((value, index) => args[index - 1] === "-p" ? "<password>" : value))
  expect(commands).toEqual([
    ["create-keychain", "-p", "<password>", profile.keychain],
    ["set-keychain-settings", profile.keychain],
    ["list-keychains", "-d", "user", "-s", profile.keychain],
    ["default-keychain", "-d", "user", "-s", profile.keychain],
    ["unlock-keychain", "-p", "<password>", profile.keychain],
    ["default-keychain", "-d", "user"],
    ["list-keychains", "-d", "user"],
  ])
  expect(child).toEqual(profileEnv(host, profile))
  for (const call of calls) expect(call.env).toEqual(child)
  expect(fs.statSync(profile.keychain).isFile()).toBe(true)
  expect(fs.statSync(preferences(profile)).isFile()).toBe(true)
  for (const directory of [profile.root, profile.home, profile.gemini, path.dirname(profile.stateFile), path.join(profile.home, "Library"), path.dirname(profile.keychain), path.dirname(preferences(profile))]) {
    expect(fs.lstatSync(directory).mode & 0o777).toBe(0o700)
  }
  expect(fs.statSync(profile.passwordFile).mode & 0o777).toBe(0o600)
  expect(host.HOME).toBe(env.HOME)
  expect(isDeepStrictEqual({ ...process.env }, before)).toBe(true)
  const second = fixture()
  prepareProfile(second.profile, second.env, fakeSecurity(second.profile))
  expect(fs.readFileSync(second.profile.passwordFile, "utf8") !== password).toBe(true)
})

test("restart reuses the persisted password, repairs permissions, and never recreates the keychain", () => {
  const { env, profile } = fixture()
  prepareProfile(profile, env, fakeSecurity(profile))
  const password = fs.readFileSync(profile.passwordFile, "utf8")
  fs.chmodSync(profile.passwordFile, 0o644)
  fs.chmodSync(profile.home, 0o755)
  const restarted = accountProfile({ ...env }, "darwin")
  const { security, calls } = fakeSecurity(restarted)
  prepareProfile(restarted, env, { security })
  expect(fs.readFileSync(profile.passwordFile, "utf8") === password).toBe(true)
  expect(calls.some(call => call.args[0] === "create-keychain")).toBe(false)
  const unlock = calls.find(call => call.args[0] === "unlock-keychain")
  expect(unlock.args[2] === password).toBe(true)
  expect(calls.length).toBe(6)
  expect(fs.statSync(profile.passwordFile).mode & 0o777).toBe(0o600)
  expect(fs.statSync(profile.home).mode & 0o777).toBe(0o700)
})

const steps = ["create", "settings", "search list", "default", "unlock", "verify default", "verify list"]
for (const [failAt, name] of steps.entries()) {
  test(`security failure at ${name} throws without exposing command/password or continuing`, () => {
    const { env, profile } = fixture()
    const { security, calls } = fakeSecurity(profile, { failAt })
    const error = caught(() => prepareProfile(profile, env, { security }))
    expectSafe(error, fs.readFileSync(profile.passwordFile, "utf8"))
    expect(calls.length).toBe(failAt + 1)
  })
}

for (const command of ["default-keychain", "list-keychains"]) {
  for (const kind of ["empty", "unquoted", "wrong", "multiple", "nonexistent"]) {
    test(`${command} verification rejects ${kind} paths`, () => {
      const { base, env, profile } = fixture()
      const other = path.join(base, "other.keychain-db")
      fs.writeFileSync(other, "")
      const outputs = {
        empty: "",
        unquoted: profile.keychain,
        wrong: `"${other}"`,
        multiple: `"${profile.keychain}"\n "${other}"`,
        nonexistent: `"${path.join(base, "missing.keychain-db")}"`,
      }
      const { security, calls } = fakeSecurity(profile, { output: name => name === command ? outputs[kind] : `"${profile.keychain}"` })
      expectSafe(caught(() => prepareProfile(profile, env, { security })), fs.readFileSync(profile.passwordFile, "utf8"))
      expect(calls.at(-1).args).toEqual([command, "-d", "user"])
    })
  }
}

for (const missing of ["keychain", "preferences"]) {
  test(`security success without creating the actual ${missing} still fails closed`, () => {
    const { env, profile } = fixture()
    const { security } = fakeSecurity(profile, { createKeychain: missing !== "keychain", createPreferences: missing !== "preferences" })
    expectSafe(caught(() => prepareProfile(profile, env, { security })), fs.readFileSync(profile.passwordFile, "utf8"))
  })
}

for (const corrupt of ["root-file", "keychain-directory", "password-directory", "preferences-directory", "empty-password", "short-password", "nonhex-password", "orphan-keychain"]) {
  test(`corrupt profile ${corrupt} is rejected before security`, () => {
    const { env, profile } = fixture()
    if (corrupt === "root-file") fs.writeFileSync(profile.root, CANARY)
    else {
      fs.mkdirSync(path.dirname(profile.keychain), { recursive: true })
      fs.mkdirSync(path.dirname(preferences(profile)), { recursive: true })
      if (corrupt === "keychain-directory") fs.mkdirSync(profile.keychain)
      if (corrupt === "password-directory") fs.mkdirSync(profile.passwordFile)
      if (corrupt === "preferences-directory") fs.mkdirSync(preferences(profile))
      if (corrupt === "orphan-keychain") fs.writeFileSync(profile.keychain, "")
      const passwords = { "empty-password": "", "short-password": CANARY, "nonhex-password": "z".repeat(64) }
      if (Object.hasOwn(passwords, corrupt)) fs.writeFileSync(profile.passwordFile, passwords[corrupt])
    }
    const { security, calls } = fakeSecurity(profile)
    expectSafe(caught(() => prepareProfile(profile, env, { security })))
    expect(calls).toEqual([])
  })
}

for (const location of ["root", "home", "gemini", "state", "library", "keychains", "preferences", "keychain-file", "password-file", "preferences-file"]) {
  test(`symlink at ${location} cannot redirect preparation outside the profile`, () => {
    const { base, env, profile } = fixture()
    const files = {
      root: profile.root, home: profile.home, gemini: profile.gemini,
      state: path.dirname(profile.stateFile), library: path.join(profile.home, "Library"),
      keychains: path.dirname(profile.keychain), preferences: path.dirname(preferences(profile)),
      "keychain-file": profile.keychain, "password-file": profile.passwordFile, "preferences-file": preferences(profile),
    }
    const outside = path.join(base, "outside")
    if (location.endsWith("-file")) fs.writeFileSync(outside, CANARY, { mode: 0o644 })
    else {
      fs.mkdirSync(outside, { mode: 0o755 })
      fs.writeFileSync(path.join(outside, "marker"), CANARY)
    }
    const mode = fs.statSync(outside).mode
    fs.mkdirSync(path.dirname(files[location]), { recursive: true })
    fs.symlinkSync(outside, files[location], location.endsWith("-file") ? "file" : "dir")
    const { security, calls } = fakeSecurity(profile)
    expectSafe(caught(() => prepareProfile(profile, env, { security })))
    expect(calls).toEqual([])
    expect(fs.statSync(outside).mode).toBe(mode)
    expect(fs.readFileSync(location.endsWith("-file") ? outside : path.join(outside, "marker"), "utf8")).toBe(CANARY)
  })
}

test("private signin prepares first and reads exactly its keychain despite inherited auth variables", async () => {
  const { env, profile } = fixture()
  const host = Object.freeze({ ...env, ...AUTH })
  const calls = []
  const opts = {
    platform: "darwin", env: host,
    prepare(actual, original) {
      expect(actual).toEqual(profile)
      expect(original).toBe(host)
      calls.push("prepare")
      return profileEnv(original, actual)
    },
    exec: async (file, args, options) => {
      calls.push("exec")
      expect(file).toBe("/usr/bin/security")
      expect(args).toEqual(["find-generic-password", "-s", "gemini", "-a", "antigravity", "-w", profile.keychain])
      expect(options.env).toEqual(profileEnv(host, profile))
      return { code: 0, stdout: STORED + "\n" }
    },
  }
  const state = await readStoredSignIn(opts)
  expect(state.state).toBe("present")
  expect(state.canRenew).toBe(true)
  expect(await storedEmail(opts)).toBe("private@example.invalid")
  expect(calls).toEqual(["prepare", "exec", "prepare", "exec"])
  expect(fs.existsSync(profile.root)).toBe(false)
  expect(host.HOME).toBe(env.HOME)
})

for (const read of [readStoredSignIn, storedEmail]) {
  test(`${read.name} treats only private item-not-found as missing and rejects read/format failures`, async () => {
    const { env, profile } = fixture()
    for (const result of [
      { code: 51, stdout: CANARY },
      { code: -1, stdout: CANARY },
      { code: 0, stdout: "" },
      { code: 0, stdout: CANARY },
      { code: 0, stdout: JSON.stringify({ api_key: CANARY }) },
    ]) {
      const opts = {
        platform: "darwin", env,
        prepare: (actual, original) => profileEnv(original, actual),
        exec: async () => result,
      }
      let failure
      try { await read(opts) } catch (error) { failure = error }
      expectSafe(failure)
    }
    let executions = 0
    const opts = {
      platform: "darwin", env,
      prepare: (actual, original) => profileEnv(original, actual),
      exec: async (_file, args) => {
        executions++
        expect(args.at(-1)).toBe(profile.keychain)
        return { code: 44, stdout: "" }
      },
    }
    expect(await read(opts)).toEqual(read === storedEmail ? "" : { state: "missing" })
    expect(executions).toBe(1)
    const failure = new ProfileError("synthetic preparation failure")
    await expect(read({ ...opts, prepare() { throw failure } })).rejects.toBe(failure)
    expect(executions).toBe(1)
  })
}

test("cached reads propagate ProfileError to all waiters and background callers, and allow retry", async () => {
  forgetStoredSignIn({ dead: true })
  const failure = new ProfileError("synthetic private failure")
  let reads = 0
  const read = async () => { reads++; throw failure }
  const results = await Promise.allSettled([storedSignIn({ read }), storedSignIn({ read }), backgroundBlocked({ read })])
  expect(reads).toBe(1)
  for (const result of results) {
    expect(result.status).toBe("rejected")
    expect(result.reason).toBe(failure)
  }
  const value = { state: "present", fp: "synthetic", canRenew: true, expiresAt: 0, expired: false }
  expect(await storedSignIn({ read: async () => { reads++; return value } })).toEqual(value)
  expect(reads).toBe(2)
  await expect(storedSignIn({ fresh: true, read })).rejects.toBe(failure)
  expect(reads).toBe(3)
  expect(await storedSignIn({ read: async () => { reads++; return { state: "missing" } } })).toEqual({ state: "missing" })
  expect(reads).toBe(4)
  expect(await storedSignIn({ fresh: true, read: async () => { throw new Error("ordinary failure") } })).toEqual({ state: "unknown" })
})

test("keychain preparation shares one deadline across security commands", () => {
  const { env, profile } = fixture()
  let calls = 0
  const fake = fakeSecurity(profile)
  const originalNow = Date.now
  let clock = originalNow()
  try {
    Date.now = () => clock
    expect(() => prepareProfile(profile, env, {
      deadline: clock + 10,
      security(args, child, timeout) {
        calls++
        expect(timeout).toBe(10)
        const result = fake.security(args, child)
        clock += 11
        return result
      },
    })).toThrow(/timed out/)
    expect(calls).toBe(1)
  } finally {
    Date.now = originalNow
  }
})

test("prepareProfile reuses verified keychain state within TTL while still enforcing filesystem checks", () => {
  const { base, env, profile } = fixture()
  const { security, calls } = fakeSecurity(profile)
  const originalNow = Date.now
  let clock = originalNow()
  try {
    Date.now = () => clock
    prepareProfile(profile, env, { security })
    expect(calls.length).toBe(7)

    // Back-to-back preparation with unchanged files skips security subprocesses
    // while still repairing directory/file permissions on every call.
    fs.chmodSync(profile.home, 0o755)
    fs.chmodSync(profile.passwordFile, 0o644)
    clock += 1_000
    prepareProfile(profile, env, { security })
    expect(calls.length).toBe(7)
    expect(fs.statSync(profile.home).mode & 0o777).toBe(0o700)
    expect(fs.statSync(profile.passwordFile).mode & 0o777).toBe(0o600)

    // Modifying preferences invalidates the cached signature immediately.
    fs.writeFileSync(preferences(profile), "modified preferences", { mode: 0o600 })
    prepareProfile(profile, env, { security })
    expect(calls.length).toBe(13)

    // Explicit fresh=true bypasses the TTL cache.
    prepareProfile(profile, env, { security, fresh: true })
    expect(calls.length).toBe(19)

    // Advancing past the 30s TTL re-verifies with security.
    clock += 30_001
    prepareProfile(profile, env, { security })
    expect(calls.length).toBe(25)

    // A symlink swap within the TTL window is still caught immediately before any cache hit.
    const outside = path.join(base, "outside-prefs")
    fs.writeFileSync(outside, CANARY, { mode: 0o600 })
    fs.rmSync(preferences(profile))
    fs.symlinkSync(outside, preferences(profile))
    expectSafe(caught(() => prepareProfile(profile, env, { security })))
    expect(calls.length).toBe(25)
  } finally {
    Date.now = originalNow
  }
})
