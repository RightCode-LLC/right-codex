# OAuth 协议覆盖清单

固定官方基线 `0.160.0` / `a956835d020762cb2b570053af06f643a11c0ecc`。客户端限定原版 Codex、ChatGPT Pro OAuth、默认 OpenAI provider、只改 `openai_base_url`；上游只用池内 ChatGPT Pro OAuth。其它套餐及 API Key 分支不进入覆盖分母。SDK 定义、实际生产调用、运行实现与验收分开登记；历史回执未核套餐时仍只记OAuth证据，不自动重标Pro。

以下源码相对 `../vendor/codex/codex-rs/`，行号对应固定导出；本表是已核实清单，尚不宣称全树动态分支已覆盖。

## 经过模型 base URL 的实际消费者

| 入口 / 用途 | 注册、认证、触发与地址来源 | 实现 / 验收状态 |
| --- | --- | --- |
| base URL 配置 | `core/src/config/mod.rs:3807–3825` → `model-provider-info/src/lib.rs:520–558`；显式 base 优先于 OAuth 默认地址，默认 provider 仍要求 OpenAI auth | 可信网络/OAuth 形状准入已接，客户端原凭据不透传；真实模型目录与业务请求已到达上游，普通与工具真实轮次已通过 |
| OAuth 凭据 | `model-provider/src/provider.rs:507–511`、`model-provider/src/auth.rs:307–323`、`model-provider/src/bearer_auth_provider.rs:31–41`；改 URL 不改认证源，客户端仍发其 OAuth Bearer/账号头 | 私有导入、登录/串行刷新与账号池已实现；管理 token 独立，客户端 Bearer 不作为池内凭据 |
| `responses` HTTP/WS | `core/src/client.rs:1024–1033,1509–1513,1617–1627,1758,1860`；`codex-api/src/endpoint/responses.rs:70–157`、`codex-api/src/endpoint/responses_websocket.rs:393–403`；默认 provider 支持 WS，426 fallback；OAuth HTTP 默认 zstd | 官方 ResponsesClient 与有界原始流观察已接；HTTP 及 WS 预热/中断/恢复有受控回归，真实普通/工具/子代理/resume/review已通过 |
| V2 压缩 | `model-provider/src/provider.rs:461–465`；`core/src/compact_remote_v2_attempt.rs:79–104`、`core/src/compact_remote_v2.rs:386–417`；末尾 trigger 后走同一 client stream，当前不是 `responses/compact` | 受控 trigger/一个 Compaction+completed、下一轮来源闭合、EOF/失败/incomplete 回归通过；真实compact及压缩后继续通过 |
| `models` | `models-manager/src/manager.rs:539–575,665–669`；`model-provider/src/models_endpoint.rs:111–136,156–166`；`codex-api/src/endpoint/models.rs:33–45`；OAuth 在线刷新，经 override provider；有效缓存或静态目录另分支 | 官方 ModelsClient 已接，实际账号目录成功取得；入站 foreign account 头不用于池内选号，未知业务字段保留 |
| hosted search | `core/src/tools/spec_plan.rs:633–647`；搜索工具直接放进 Responses，无独立搜索请求 | 完整 tools 经 Responses 发送；业务字段保留与身份投影受控测试，真实搜索工具通过，独立Search另有真实触发回执 |
| `alpha/search` | `ext/web-search/src/extension.rs:40–53,140–145`、`ext/web-search/src/tool.rs:97–119`；`core/src/tools/spec_plan.rs:1038–1046,1483–1500`；`codex-api/src/endpoint/search.rs:15,43–48`；搜索未禁用、namespace/web-search 能力及 Lite 或 standalone feature，工具实际调用才发；feature 默认 false（`features/src/lib.rs:1129–1133`） | 官方 SearchClient 已接，官方 request/settings 结构受控测试通过；header-only canonical及完整inventory已接；真实原生搜索触发通过 |
| `images/generations`、`images/edits` | 本项目只验Pro OAuth。`app-server/src/extensions.rs:100–103` 安装；`core/src/tools/spec_plan.rs:727–768` 检查图片 feature、套餐、图片/namespace 能力、模型 Image、Codex backend auth；`ext/image-generation/src/extension.rs:43–47,100–103`、`ext/image-generation/src/backend.rs:79–133` 获取配置 provider/OAuth；`codex-api/src/endpoint/images.rs:61–107` 真正发送。图片 feature 默认 true（`features/src/lib.rs:1553–1556`） | 官方 ImagesClient、同会话图片字节别名、编辑 Inline 已实现且受控往返通过；无源字节失败不回传上游ID；测试账号真实生成/编辑及后续原生turn通过；其它套餐不纳入待办 |
| Memory 实际轮次 | `app-server/src/request_processors/turn_processor.rs:686–697`；`memories/write/src/start.rs:24–37,89`、`memories/write/src/phase1.rs:313–315`、`memories/write/src/runtime.rs:325–360,398–422`、`memories/write/src/phase2.rs:302–317`；feature 默认 false，root/non-ephemeral/本地状态与候选历史等条件；clone 配置 provider 后 Responses stream | metadata kind/身份省略、detached与内部整合memgen头细分已测；真实vscode历史触发stage1/no-output及consolidation，未产出有效记忆，逐请求原包归属待验；正文ID/路径原样保留，不新增服务端工具执行器 |
| WebRTC call 与 ExistingCall sideband | `core/src/realtime_conversation.rs:1336–1359,1407–1425,701–706`；`core/src/client.rs:669–695`；`codex-api/src/endpoint/realtime_call.rs:62–78`。WebRTC 使用 configured provider OAuth 创建 HTTP call，路径按 parser/base 为 `realtime/calls` 或 `live`；独立地址覆盖另分支；ExistingCall 不再创建新 call | 创建经模型 base，但 sideband 默认 api.openai.com +客户端 OAuth，绕过模型 base；公开入口创建前双语501，零上游请求，局部SDK测试不授完整支持 |

默认 Realtime `Websocket` 在纯 OAuth、没有 API Key 时先被 `realtime_api_key()` 本地拒绝（`core/src/realtime_conversation.rs:1873–1897`），不发送该请求。此分支排除；不因此排除已核 OAuth WebRTC/ExistingCall。

这不是仅据 SDK 推断的入口：`features/src/lib.rs:1793–1796` 将 `realtime_conversation` 默认开启；`tui/src/chatwidget/realtime.rs:291–311,407–410` 检查 feature、平台与线程后发起语音；`tui/src/app_server_session/realtime.rs:50–51` 明确指定 WebRTC/V3。app-server 在 `request_processors/turn_processor.rs:1236–1272` 转为 core WebRTC 操作，`core/src/realtime_conversation.rs:1417–1424` 不调用 API Key 获取函数，`core/src/client.rs:678–695` 使用 configured provider 及当前 `api_auth` 创建通话。纯 OAuth 此处取当前 ChatGPT 认证；源码链成立不代表私有上游向所有账号开放。当前没有真实 OAuth 完整通话验收，不将 API Key 测试计入分母。

`model-provider-info/src/lib.rs:77,421–439` 定义 OAuth 默认前缀为 `https://chatgpt.com/backend-api/codex`；`codex-client/src/provider.rs:61` 将相对端点拼接到当前前缀。图片同名路径的存在不意味着使用公共模型 API 的认证分支。

`core/src/client.rs:727–739::summarize_memories` 定义了 `memories/trace_summarize`，全树当前仅发现 `core/src/client_tests.rs:1506` 消费。未获实际生产调用证据，登记为保留 SDK 方法，不列当前必接端点。

## Workspace 路由及独立出口

| 范围 | 固定源码与已核行为 | 网关处理边界 |
| --- | --- | --- |
| Responses workspace 路由 | `model-provider/src/provider.rs:250–280`、`model-provider-info/src/lib.rs:612–619`；须 first-party、OAuth、默认 OpenAI base 未设或以 `/backend-api/codex` 结尾。`app-server/src/request_processors/account_processor/workspace_routing.rs:381–403` 另核当前 owner 和 origin；`model-provider/src/workspace_routing.rs:39–75` 改 origin/保留路径并禁止重定向 | 池内发现/修订路由已实现；真实 NO_CONSTRAINT 标记修复并验至模型上游；us/us_cr与非法origin受控测试 |
| OAuth 登录/刷新 | `login/src/server.rs:76,603,717`、`login/src/device_code_auth.rs:165–209`、`login/src/auth/manager.rs:212,1643`；独立 issuer 与 authorize/token/deviceauth | 池内独立 PKCE/Device/取消/到期/刷新已接；回调/轮询/刷新并发受控测试通过，真实新登录待验 |
| 账号检查/额度 | `core/src/config/mod.rs:4420–4423`、`app-server/src/request_processors/account_processor/workspace_routing.rs:296–301`、`app-server/src/request_processors/account_processor.rs:1115–1146`、`backend-client/src/client.rs:403`、`backend-client/src/client/rate_limit_resets.rs:127`；Memory guard `memories/write/src/guard.rs:21–29` | 池内独立账号查询、额度映射与刷新已实现；60秒后台检查并发至多4个，失败保留已观测状态；客户端自身额度不被接管 |
| Apps Files 上传 | `core/src/mcp_openai_file.rs:149–153,247–249`、`codex-api/src/files.rs:149,239,354–366`；OAuth Apps 文件参数触发，chatgpt_base_url/files → signed URL PUT → uploaded | 仅改 model base 不代理客户端上传；普通图片 input 不等于 Files 上传。只取得外部 file_id 时缺源字节，不能冒已镜像 |
| Analytics | `core/src/session/session.rs:1609–1613`、`analytics/src/client.rs:152–154,316–323`；独立 chatgpt_base_url/codex/analytics-events/events | 客户端仍直发；本项目只能登记/生成自己实际来源的网络与事件子集 |
| OTel/Statsig | `otel/src/config.rs:9`、`core/src/config/otel.rs`；独立 exporter 配置与指标出口 | 网关逐账号 MetricsClient 与队列已接；受控OTLP成功，Linux Release真实Statsig HTTP回执1批，逐点消费未获证据；不修改客户端独立出口 |
| MCP/插件/外部工具 | 客户端按各工具配置直接连接 | 不扩大本项目为通用 HTTP 代理；不获取或制造其完整客户端执行事实 |

## 请求语义与复用资格

| 范围 | 官方固定源码 | 当前缺口 |
| --- | --- | --- |
| canonical metadata 与 request_kind | `core/src/responses_metadata.rs:163–182,224–229,325–440,458`；kind 仅 turn/prewarm/compaction/memory，header 是兼容投影；Memory 省略部分线程身份 | 规范字段/用途保留，账号修订内重建身份与兼容投影，Memory省略、标题/Guardian等受控测试通过 |
| 标题/角色/Guardian | `tui/src/app/thread_title.rs:103`；`core/src/responses_metadata.rs:458`；`ext/guardian-v2/src/sync_reviewer/mod.rs:89`；标题 turn+thread_title，review/collab_spawn subagent，Guardian reviewer/classifier 专用头 | 显式标记分类、协议父响应同作用域证明已接；正文ID/路径原样保留，提示词不作唯一分类依据。真实auto_review批准、客户端无害命令及普通轮恢复已验；不伪造审批事实 |
| 业务 input 与工具 | `protocol/src/models.rs`、`core/src/session/turn_input.rs:289–298` | typed ID空间/原子校验已接；真实additional_tools前缀、Direct可选call_id及内部历史规范化已修正；工具及子代理执行通过；自由文本/工具JSON不递归改写 |
| 官方 HTTP/WS 接口 | `codex-api/src/endpoint/responses.rs:70,110`、`codex-api/src/endpoint/responses_websocket.rs:239,393` | HTTP复用官方endpoint、请求准备/压缩/auth/hooks，transport保留实际错误字节；WS保留官方窄拨号、握手校验及扩展协商，在同一TLS socket完整读取拒绝正文；实际帧观察后映射；迟到连接事实不归下一轮 |
| 客户端流程 | `core/src/session/turn.rs:149`、`core/src/compact_remote_v2_attempt.rs:39`、`core/src/responses_retry.rs:56` | 不再调用 run_turn/review/Memory/Guardian 执行器；按最新用户合同不做网关业务重试/401刷新/流中切号；客户端自身重试按新的入站请求记账 |
| 公开网络遥测 | `codex-client/src/telemetry.rs:5–14`、`codex-api/src/telemetry.rs:17–43`；`otel/src/events/session_telemetry.rs:174–195,559–605,723–785,977–1026,1102–1121` | 官方Request/SSE/WS hook、真实usage producer、逐账号producer/exporter与冷队列清空已接，受控整链验证；不借全局metrics冒隔离 |
| Analytics 访问边界 | `analytics/src/lib.rs:15–84`、`analytics/src/client.rs:314–323,490–519,710–841`；`analytics/src/facts.rs:541`、`analytics/src/reducer.rs:205–217`、`analytics/src/events.rs:63–105` 为 crate-private | track_* 公开不等于完整事实取得；客户端开始/结束/审批/耗时与 app-server 生命周期缺入口，不补造 |
| 来源与既有验证 | `vendor/codex-source-lock.json`、根 Cargo.lock、profiles 与 `var/verification/` | 8775项源码锁本轮重验，45种子及35/195目录重验；当前运行成绩见IMPLEMENTATION-AUDIT，不混用首段与新代码资格 |

仅目录统计、字符串检索及受控 HTTP 成功不能证明无遗漏。每新增实际 OAuth 消费者都需补注册条件、wire 合同、身份来源、实现和验收；当前缺口汇总见 [PLAN](../PLAN.md)，历史原型成绩见 [HTTP 首段审计](HTTP-FOUNDATION-AUDIT.md)。

2026-10-10复审修正：上述“已接线/受控通过”不是完整等价结论。现已确认响应控制头缺失、WS回包headers身份未完整处理、官方网络指标语义差异及环境resource注入、路由代次缺失、目录/选号未绑定、交付预记与长期attempt上限问题。具体条件、源码证据及验收项统一维护在PLAN的E01–E10；不新增其它套餐或API Key任务。

2026-10-10错误合同：Responses、WS握手/流、Models/Search/Images和账号发现/额度共用401失效与429冷却策略；HTTP错误业务正文/状态/业务头保留，结构化身份继续隔离。固定`http-client/src/retry_after.rs`的Retry-After在收到头时只解析一次，正文延迟不能重启倒计时。固定tungstenite握手只保存首读tail，网关在同连接补齐Content-Length/chunked/EOF读取，64KiB头/64MiB错误体有界；不发第二个请求获取正文。官方vendor未改。
