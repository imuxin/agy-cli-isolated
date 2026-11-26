# AGENTS.md

本文件约定 `agy-cli-isolated` 仓库的工程约束与上游同步流程。

## 隔离版不变量

在修改代码或同步上游 `magpie-community/plugins`（`packages/agy-cli`）变更时，必须保持以下隔离特性不被破坏：

1. **包元数据（`package.json`）**
   - `name` 固定为 `"agy-cli-isolated"`。
   - `version` 采用 `<上游版本>-isolated.<修订号>` 格式（例如 `0.1.66-isolated.1`）。
   - 保留隔离版 `description` 与 `magpie.icon`。
   - `files` 中保留隔离新增文件（如 `profile.mjs`）以及同步后使用的上游新增文件。
2. **账号与钥匙串隔离**
   - `profile.mjs` 及相关调用链（`index.mjs`、`platform.mjs`、`signin.mjs`、`install.mjs`、`login.mjs` 等）的隔离逻辑和提示文案不得被上游覆盖丢失。
   - `test/testkit.mjs` 需同时保留 `./profile.mjs` 与上游新增模块的 `sourceModule` 映射。
3. **额度查询**
   - 同步上游时保留隔离版对 `auth.usage` 及 `/usage` 额度查询模块的移除。
4. **测试门禁**
   - 任何改动或合并完成后，必须运行 `bun test` 并确保全部用例通过。

## 上游同步与冲突处理规范

仓库通过 `.github/workflows/sync-upstream.yml` 自动同步上游 `packages/agy-cli` 提交：
- 无冲突时，Action 会在 `sync/upstream-agy-cli` 分支完成合并、保护 `package.json` 元数据、跑通 `bun test` 后自动创建/更新 PR。
- **遇到合并冲突时**，Action 会中止合并并把上游子树历史推送到远端临时分支 `origin/upstream-agy-cli`。此时按以下流程人工解决并**默认采用方式 B 直接合入 `main`**：

### 1. 复现并解决冲突

```sh
git fetch origin
git checkout -B sync/upstream-agy-cli main
git merge --no-edit -X patience origin/upstream-agy-cli
```

解决冲突时：
- 同时保留上游新增能力/修复与本地隔离改造，不直接用一侧覆盖另一侧。
- 检查全仓无残留冲突标记（`<<<<<<<`、`=======`、`>>>>>>>`、`|||||||`）。
- 运行全量测试确认通过：

```sh
bun test
```

- 在 `sync/upstream-agy-cli` 提交合并结果：

```sh
git add -A
git commit -m "chore(sync): merge upstream agy-cli <version> and resolve conflicts"
```

### 2. 合入 `main`、推送与清理（方式 B）

冲突解决并验证 `bun test` 全部通过后，直接快进合入 `main`、推送远端，并清理临时分支（不再额外走 PR）：

```sh
git checkout main && git merge --ff-only sync/upstream-agy-cli
git push origin main
git push origin --delete upstream-agy-cli
git branch -d sync/upstream-agy-cli
```
