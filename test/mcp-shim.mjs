import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"
import { test } from "node:test"
import { baseBody, createBridgeKit, readSse } from "./testkit.mjs"

async function withShimKit(platform, name, fn) {
  const kit = await createBridgeKit({ platform, versions: { ...process.versions, bun: undefined } })
  kit.defaultPrompt = async (agent) => {
    await agent.text("ok")
    return { stopReason: "end_turn", usage: { inputTokens: 10, outputTokens: 1 } }
  }
  async function start(text) {
    const body = baseBody({ tools: [], messages: [{ role: "user", content: text }] })
    const parsed = await readSse(await kit.request(body))
    assert.equal(parsed.error, null, JSON.stringify(parsed.error))
    assert.equal(parsed.stopReason, "end_turn")
    const dir = kit.acpSpawns.at(-1).env.PATH.split(path.delimiter)[0]
    const file = path.join(dir, name)
    assert.ok(fs.statSync(file).size > 0)
    if (platform !== "win32" && process.platform !== "win32") {
      fs.accessSync(file, fs.constants.X_OK)
    }
    return dir
  }
  try {
    await fn(kit, start)
  } finally {
    await kit.dispose()
  }
}

for (const { platform, name } of [
  { platform: "darwin", name: "nc" },
  { platform: "win32", name: "nc.cmd" },
]) {
  test(`${platform} rebuilds a missing temporary MCP shim before spawning agy`, async () => {
    await withShimKit(platform, name, async (kit, start) => {
      const firstDir = await start("first session")
      fs.unlinkSync(path.join(firstDir, name))
      assert.equal(await start("second session"), firstDir)
      fs.unlinkSync(path.join(firstDir, name))
      fs.rmdirSync(firstDir)
      assert.notEqual(await start("third session"), firstDir)
      assert.equal(kit.acpSpawns.length, 3)
    })
  })
}

test("unix restores execute permission when rebuilding an existing MCP shim", { skip: process.platform === "win32" }, async () => {
  await withShimKit("darwin", "nc", async (kit, start) => {
    const firstDir = await start("first session")
    const file = path.join(firstDir, "nc")
    fs.chmodSync(file, 0o600)
    assert.equal(await start("non-executable shim"), firstDir)
    fs.truncateSync(file, 0)
    fs.chmodSync(file, 0o600)
    assert.equal(await start("truncated non-executable shim"), firstDir)
    assert.equal(kit.acpSpawns.length, 3)
  })
})
