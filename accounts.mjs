import { randomUUID } from "node:crypto"
import path from "node:path"
import { accountProfile, ProfileError } from "./profile.mjs"

// The saved key identifies a local profile, never a Google token. Old "agy"
// credentials keep using the original profile without moving their files.
export function accountEnvironment(auth, env = process.env) {
  const key = auth?.key ?? "agy"
  if (key === "agy") return env
  const match = /^x-agy:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/.exec(key)
  if (!match) throw new ProfileError("unrecognized account; sign in again in Magpie")
  const profile = accountProfile(env)
  if (!profile) throw new ProfileError("multiple accounts require isolated mode")
  const selected = { ...env, AGY_BRIDGE_PROFILE_DIR: path.join(profile.root, "x-agy-accounts", match[1]) }
  // These overrides have already been checked against the original profile.
  // The selected account derives its paths from its own root.
  for (const name of ["AGY_BRIDGE_GEMINI_DIR", "AGY_BRIDGE_STATE_FILE", "AGY_BRIDGE_CONVERSATIONS_DIR"]) delete selected[name]
  return selected
}

export async function createAccountPlugin(createRuntime, defaultRuntime, env = process.env) {
  const original = await defaultRuntime.createPlugin()
  const profile = accountProfile(env)
  if (!profile) return original
  // An explicit Linux "agy" key predates private profiles and names the host
  // sign-in. A discovery call without auth must stay in the private default.
  const defaultKey = profile.tokenFile ? null : "agy"
  const plugins = new Map([[defaultKey, Promise.resolve(original)]])
  function forAccount(auth) {
    const key = auth?.key ?? defaultKey
    if (!plugins.has(key)) {
      const selected = key === "agy"
        ? { ...env, AGY_BRIDGE_PROFILE: "shared", AGY_BRIDGE_PROFILE_DIR: "" }
        : accountEnvironment(auth, env)
      const runtime = createRuntime(() => selected)
      const plugin = runtime.createPlugin()
      plugins.set(key, plugin)
      plugin.catch(() => plugins.delete(key))
    }
    return plugins.get(key)
  }

  return {
    ...original,
    auth: {
      ...original.auth,
      single: false,
      methods: [
        {
          ...original.auth.methods[0],
          authorize: async () => {
            const key = `x-agy:${randomUUID()}`
            const plugin = await forAccount({ key })
            // Always open Google for a new account, using its empty profile.
            const login = await plugin.auth.methods[1].authorize()
            if (typeof login.callback !== "function") return login
            return {
              ...login,
              callback: async (...args) => {
                const result = await login.callback(...args)
                return result?.type === "success" ? { ...result, key } : result
              },
            }
          },
        },
        ...(profile.tokenFile ? [] : [{
          ...original.auth.methods[0],
          label: "Use the existing default profile",
          labels: { zh: "使用原有默认账号", "zh-TW": "使用原有預設帳號", ja: "既存のデフォルトアカウントを使用" },
        }]),
      ],
      loader: async (getAuth, provider) => {
        const auth = await getAuth?.()
        const plugin = await forAccount(auth)
        const options = await plugin.auth.loader(getAuth, provider)
        return { ...options, apiKey: auth?.key ?? "agy" }
      },
    },
    provider: {
      ...original.provider,
      models: async (provider, context) => (await forAccount(context?.auth)).provider.models(provider, context),
      warming: () => Promise.all([...plugins.values()].map(async (plugin) => (await plugin).provider.warming())),
    },
  }
}
