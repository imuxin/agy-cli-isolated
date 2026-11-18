# Linux 多账号

Linux 和 macOS 默认启用隔离模式。Magpie 每次“使用 Google 登录”都会创建新的 `x-agy:<UUID>` 账号。更新本地插件、重启 Magpie 后即可使用。显式设置过 `AGY_BRIDGE_PROFILE=shared` 的用户需要移除该设置才能启用多账号。

## 凭证与目录

Linux 采用[上游 agy-cli 的账号环境](https://github.com/magpie-community/plugins/blob/e38f4f39fe92b1fe14bad14ad38e8b557fa61d44/packages/agy-cli/account.mjs)。`profile.mjs` 给 agy 子进程分配私有 HOME 和 XDG 目录，并设置 `SSH_CONNECTION`。agy 1.5 在这种环境中把 Google 登录写到账号 HOME 下的 `.gemini/antigravity-cli/antigravity-oauth-token`。桌面 D-Bus 地址保持原值。macOS 使用已有的私有 Keychain。

账号目录位于 `<profile>/x-agy-accounts/<UUID>/`。默认的 `<profile>` 是 `$XDG_STATE_HOME/magpie-agy-bridge/profile`，未配置 XDG 时使用 `~/.local/state/magpie-agy-bridge/profile`。私有凭证目录权限为 0700，Linux 令牌文件权限为 0600，备份应按可用凭据保管。

`signin.mjs` 从选中账号读取登录状态和邮箱。文件缺失时返回未登录，损坏或读取失败会报告错误。`agy acp --login` 完成后，插件重新读取私有凭证，使用同一 profile 运行 `agy models`，成功后返回账号标识。Google 令牌交由 agy 保存和续期。

## 账号选择

| 保存的标识 | 运行时 |
|---|---|
| `x-agy:<UUID>` | 私有账号，各自持有模型缓存、额度读取器、ACP 进程和会话索引 |
| `agy` | Linux 使用已有的宿主共享登录，macOS 使用原默认私有 profile |
| 无凭据的发现调用 | 私有默认环境 |
| 旧私有标识 `agy:<UUID>` | 隔离模式下提示重新登录。旧 `accounts/` 目录保留在磁盘上 |

`accounts.mjs` 按标识选择运行时。加载请求、列出模型和查询额度都经过同一选择过程。切换账号后的请求使用各自的运行时，重启通过 UUID 重建相同的路径。显式 `shared` 提供单账号行为。

## 验证

- `bun test` 包含 Linux 与 macOS 的模拟双账号并行登录、不同模型和额度、相同对话的工具续接及进程重启后的会话恢复。环境和凭证测试覆盖 Linux 文件缺失、损坏、权限和独立 HOME。
- Linux arm64 容器中，使用经官方 SHA-512 校验的 agy 1.5.11，从插件登录入口并行取得两个 Google 授权链接，确认创建了两个独立 profile。
- 同一版本的 Linux `agy models` 在禁用网络的容器中分别运行于 A、B 两个 HOME。使用合成凭证、Linux inotify 文件打开事件和一个可监听的会话总线套接字，观测到每个进程只打开自己的凭证文件，两个进程均未连接该套接字。
- Omarchy 桌面的最终验收需要两个真实 Google 账号，完成授权码交换，分别发起模型请求和额度查询，重启恢复会话并观察真实令牌续期。
