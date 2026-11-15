import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"
import { test } from "node:test"
import { baseBody, continueWithToolResults, createBridgeKit, modelsOutput, readSse, MESSAGES_URL } from "./testkit.mjs"

const isolated = {
  platform: "darwin",
  storedSignIn: "missing",
  sessionResume: true,
  env: { AGY_BRIDGE_PROFILE: "isolated", AGY_BRIDGE_STEP_USAGE: "0" },
}
const saved = result => ({ type: "api", key: result.key, metadata: result.metadata })
const send = (loader, body) => loader.fetch(MESSAGES_URL, { method: "POST", body: JSON.stringify(body) })

async function signIn(plugin, email) {
  const login = await plugin.auth.methods[0].authorize()
  assert.equal(login.method, "code")
  const result = await login.callback(email)
  assert.equal(result.type, "success", result.error)
  assert.equal(result.metadata.email, email)
  return saved(result)
}

test("two accounts keep login, models, usage, tools and resumed sessions separate", async () => {
  const kit = await createBridgeKit({
    ...isolated,
    usageReport: env => ({
      status: "SUCCESS", command: { name: "usage", data: { groups: [{
        name: env.AGY_BRIDGE_PROFILE_DIR.includes("accounts") ? "Account Model" : "Default Model",
        buckets: [{ id: "weekly", name: "Weekly", window: "weekly", remaining_fraction: 0.75 }],
      }] } },
    }),
  })
  try {
    const hostEnv = { ...kit.env }
    assert.equal(kit.plugin.auth.single, false)
    const pending = await Promise.all([
      kit.plugin.auth.methods[0].authorize(),
      kit.plugin.auth.methods[0].authorize(),
    ])
    assert.equal(kit.loginSpawns.length, 2)
    assert.ok(kit.loginSpawns.every(({ child }) => !child.closed), "another account must not cancel this login")
    const roots = kit.loginSpawns.map(({ env }) => env.AGY_BRIDGE_PROFILE_DIR)
    assert.notEqual(roots[0], roots[1])
    kit.modelsBehavior = ({ env }) => ({ stdout: modelsOutput([
      [env.AGY_BRIDGE_PROFILE_DIR === roots[0] ? "gemini-account-a-high" : "gemini-account-b-high", "Account Model (High)"],
    ]) })
    const accounts = await Promise.all(pending.map(async (login, i) => {
      const result = await login.callback(`${i}@example.invalid`)
      assert.equal(result.type, "success", result.error)
      assert.equal(result.metadata.email, `${i}@example.invalid`)
      return saved(result)
    }))
    assert.notEqual(accounts[0].key, accounts[1].key)
    const getters = accounts.map(auth => async () => auth)
    const loaders = await Promise.all(getters.map(get => kit.plugin.auth.loader(get)))
    const catalogs = await Promise.all(accounts.map(auth => kit.plugin.provider.models({}, { auth })))
    assert.ok(catalogs[0]["gemini-account-a-high"])
    assert.equal(catalogs[0]["gemini-account-b-high"], undefined)
    assert.ok(catalogs[1]["gemini-account-b-high"])
    const usage = await Promise.all(getters.map(get => kit.plugin.auth.usage(get)))
    for (const report of usage) assert.equal(report.error, undefined, report.error)
    assert.deepEqual(usage.map(u => u.windows[0]?.models), [
      ["gemini-account-a", "gemini-account-a-high"],
      ["gemini-account-b", "gemini-account-b-high"],
    ])
    assert.deepEqual(usage.map(u => u.windows[0].used), [25, 25])

    // Identical messages and client tool names still belong to two sessions.
    kit.defaultPrompt = async agent => {
      const reply = await agent.tool("Read", { path: "same.txt" })
      await agent.text(JSON.stringify(reply))
    }
    const body = baseBody({ model: "gemini-4-argon" })
    const first = await Promise.all(loaders.map(async loader => readSse(await send(loader, body))))
    assert.ok(first.every(result => result.content.some(block => block.type === "tool_use")))
    const followups = first.map((result, i) => continueWithToolResults(body, result, () => `account-${i}-result`))
    const finished = await Promise.all(loaders.map(async (loader, i) => readSse(await send(loader, followups[i]))))
    for (let i = 0; i < 2; i++) {
      const text = finished[i].content.filter(b => b.type === "text").map(b => b.text).join("")
      assert.ok(text.includes(`account-${i}-result`))
      assert.ok(!text.includes(`account-${1 - i}-result`))
    }
    const prompts = kit.acpLog.filter(entry => entry.method === "session/prompt")
    assert.equal(prompts.length, 2)
    assert.notEqual(prompts[0].sessionId, prompts[1].sessionId)
    const state = roots.map(root => JSON.parse(fs.readFileSync(path.join(root, "state", "sessions.json"), "utf8")))
    assert.notEqual(state[0].entries[0].sessionId, state[1].entries[0].sessionId)
    assert.deepEqual(kit.env, hostEnv)
    const running = kit.acpSpawns.filter(({ env }) => env.AGY_BRIDGE_TOKEN)
    assert.deepEqual(new Set(running.map(({ env }) => env.HOME)), new Set(roots.map(root => path.join(root, "home"))))

    // Recreate account runtimes from saved auth; resume only their own files.
    await kit.finishChildren()
    const restarted = await kit.module.AntigravityBridgePlugin()
    kit.defaultPrompt = async agent => { await agent.text("resumed") }
    const resumedLoaders = await Promise.all(getters.map(get => restarted.auth.loader(get)))
    const next = followups.map((request, i) => ({
      ...request, messages: [...request.messages, { role: "assistant", content: finished[i].content }, { role: "user", content: "next" }],
    }))
    await Promise.all(resumedLoaders.map(async (loader, i) => readSse(await send(loader, next[i]))))
    const resumes = kit.acpLog.filter(entry => entry.method === "session/resume")
    assert.deepEqual(new Set(resumes.map(entry => entry.params.sessionId)), new Set(state.map(s => s.entries[0].sessionId)))
  } finally { await kit.dispose() }
})

test("a missing or failed account cannot use another account's credentials", async () => {
  const kit = await createBridgeKit(isolated)
  try {
    const good = await signIn(kit.plugin, "good@example.invalid")
    const failed = await kit.plugin.auth.methods[0].authorize()
    assert.equal((await failed.callback("invalid")).type, "failed")
    const root = kit.loginSpawns.at(-1).env.AGY_BRIDGE_PROFILE_DIR
    const missing = { type: "api", key: `agy:${path.basename(root)}` }
    const loader = await kit.plugin.auth.loader(async () => missing)
    const before = kit.acpSpawns.length
    const response = await send(loader, baseBody())
    assert.equal(response.status, 401)
    assert.equal(kit.acpSpawns.length, before)
    assert.equal((await kit.plugin.auth.usage(async () => missing)).signIn, "expired")
    kit.defaultPrompt = async agent => { await agent.text("still signed in") }
    const validLoader = await kit.plugin.auth.loader(async () => good)
    assert.equal((await readSse(await send(validLoader, baseBody()))).stopReason, "end_turn")
    await assert.rejects(kit.plugin.auth.loader(async () => ({ key: "agy:../../outside" })), /unrecognized account/)
  } finally { await kit.dispose() }
})

test("legacy credentials retain the original profile and shared mode stays single-account", async () => {
  const storedSignIn = JSON.stringify({ token: { refresh_token: "legacy-token" }, id_token_email: "legacy@example.invalid" })
  const kit = await createBridgeKit({ ...isolated, storedSignIn })
  try {
    const login = await kit.plugin.auth.methods[1].authorize()
    assert.equal(login.method, "auto")
    assert.deepEqual(await login.callback(), { type: "success", key: "agy", metadata: { email: "legacy@example.invalid" } })
    const loader = await kit.plugin.auth.loader(async () => ({ type: "api", key: "agy" }))
    kit.defaultPrompt = async agent => { await agent.text("legacy") }
    await readSse(await send(loader, baseBody()))
    const child = kit.acpSpawns.find(({ env }) => env.AGY_BRIDGE_TOKEN)
    assert.equal(child.env.AGY_BRIDGE_PROFILE_DIR, path.join(kit.env.XDG_STATE_HOME, "magpie-agy-bridge", "profile"))
    assert.equal(kit.loginSpawns.length, 0)
  } finally { await kit.dispose() }
  const shared = await createBridgeKit()
  try { assert.equal(shared.plugin.auth.single, true) } finally { await shared.dispose() }
})
