# HTTP 首段审计：2026-10-10

这是新项目既有原型的验证回执，不是完整 OAuth 原版客户端接入资格。当前范围与后续设计以 [PLAN](../PLAN.md) 为准。

| 项目 | 已取得证据 | 不包含的结论 |
| --- | --- | --- |
| 源码 | 固定 0.160.0 / `a956835d020762cb2b570053af06f643a11c0ecc`；8775 项独立导出逐项核验；导出器 4 项正负例通过 | 全部动态调用分支已覆盖 |
| 资料目录 | 八组 45 项协议种子、35 类 Analytics 与 195 项指标目录重新核验 | 全部事件已经实现或应每次发送 |
| 构建 | Rust 1.97.1、macOS arm64；首轮依赖构建 3 分 8 秒；五个官方网络 crate；当前生产依赖图无 core/TUI/app-server | 官方 1.95 工具链、Linux、多架构镜像资格 |
| Rust 回归 | 27 项模块测试、9 组受控 HTTP 场通过；Clippy 严格警告门与自有源码格式检查通过 | 官方参考端逐请求差分、真实 OAuth 或客户端全场景验收 |
| 独立二进制 | 临时配置、随机 loopback 端口；health、鉴权先于 JSON、无账号拒绝及 SIGINT 退出通过 | 实际账号网络调用；此次检查未读取宿主 auth |
| 运行与交付 | HTTP/SSE 请求投影、typed ID 映射、V2 终态、私有网络事实已有首段实现 | WS、登录刷新、额度切号、持久恢复、官方远端遥测、发布部署 |

原型接入仍要求本地固定 Bearer Key。只改 base URL、保持客户端 ChatGPT OAuth 时，客户端发送的是其 OAuth 凭据；该原型尚未实现本轮收窄后的接入合同。原型只保留有限请求字段，并重新创建精简 metadata，完整官方请求语义与 canonical metadata 待补；原生 Direct 输出无 call_id 的分支也待补。上述既有测试通过不消除这些缺口。

私有原始产物在 `var/verification/`：`foundation-tests.log`、`foundation-clippy.log`、`foundation-format.log`、`initial-build.log`、`vendor-recheck.json`、`vendor-tests.log`、`profile-source-verification.json`、`binary-smoke.json` 与 `runtime-dependencies.txt`。这些产物不提交公开仓库。

只有本作用域已完成响应的精确 reasoning/compaction 密文获来源；外部密文不直接复用。当前外部 compaction 没有明文重建入口，首段明确报错，不能登记为中途加入对话已经无缝接续。所有状态尚在内存，重启不能继承旧 ID 证明。

本轮只修改设计与说明，没有新增运行实现、重跑 Rust 构建或部署；旧生产未迁移。
