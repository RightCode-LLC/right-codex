# right-codex 实施审计

更新：2026-10-10。固定官方版本 **0.160.0**，提交 `a956835d020762cb2b570053af06f643a11c0ecc`。

**最新结论：已按用户决定取消业务自动重试、401刷新重发、429流中切号。上游错误交付后结束；401停止账号调度，429只按真实重置时间冷却。** 完整197项回归、严格Clippy与macOS debug构建通过；最终产物原版客户端受控12案通过。客户端和池账号仍限定ChatGPT Pro OAuth；本轮不等于完整计划全部完成，也不等于原版出站完全等价。未复验真实OAuth、未重建Linux镜像、未发布或部署，旧生产未改动。

## 2026-10-10 错误透传与调度策略

最新用户合同取代旧的自动恢复方案：Responses HTTP/SSE/WS、models、Search、Images及账号路由拒绝均在当前请求内停止，不进行OAuth刷新、换号重放或流中接写。下一次客户端独立请求才重新调度；客户端原有重试属于新入站请求。官方SDK与reqwest协议层的自动重试均显式关闭。

- 401先把账号置为凭据失效，再返回实际错误。失效状态基于workspace与access token的私有指纹；修改代理、出口配置、JSON空白、last_refresh或仅刷新id/refresh token均不解除。新access token解除401，旧修订迟到错误不污染新状态。
- 429仅按有效未来resets_at、resets_in_seconds、Retry-After及官方额度重置头冷却；无时间、已过期或格式错误不添加默认冷却。收到HTTP头时捕获官方Retry-After倒计时，读正文不重启计时。健康额度响应、新access token及进程重启均不提前清除已确认的账号冷却；到时自然恢复。
- 业务错误状态、code/message与业务头保留；已有协议身份隔离继续生效。非JSON、空体、非法UTF-8及无身份改写的JSON保留原字节。截断保留已读前缀并以正文错误结束，不伪造完整成功。
- 固定tungstenite原握手只保留首批tail；新增同socket有界读取，补齐Content-Length/chunked/EOF正文。原库继续生成/校验握手与协商扩展，代理/CA/SNI保留；不为获取错误正文再次发请求。握手非101直接返回真实HTTP错误，删除旧426缓存。
- 已交付文本/工具后遇到错误，交付原错误并结束；WS关闭且不在旧101下重拨或替换账号。闲置错误使用连接自身账号快照，不被会话锁占用或后续会话归属变化阻挡；其它已开连接不能继续给失效账号发送新业务。
- 写盘失败不会把已观察上游错误换成网关502；内存仍阻断新调度，日志登记持久化失败。只有成功写盘的状态才获得重启保留保证。管理页显示凭据失效与冷却截止时间。

| 验证层 | 本轮证据 |
| --- | --- |
| 完整回归 | `error-policy-tests.log`：197通过、0失败；lib49、OAuth15、辅助16、整链遥测1、HTTP18、资源隔离1、metadata11、网络遥测7、正文3、身份32、回包投影8、错误策略13、WS23 |
| 静态与构建 | `error-policy-clippy.log`严格Clippy通过；`error-policy-build.log`macOS debug通过；固定依赖原有unused patch/future-incompat提示保留 |
| 固定源码 | `error-policy-source.log`记录8775项vendor无漂移、45项profile及35/195源码目录核验；官方vendor未改 |
| 原版消费者 | `native-control-header-p9_ylij0/report.json`：最终产物12案通过、4组控制消费者一致；使用独立home/合成Pro/loopback，宿主环境未覆盖。产品SHA `d5b2c8807f349c5a80d4597684ac2015512c2ee404f6170d32f461c29f29e15b` |
| 未执行 | 真实双Pro、生产HTTPS/代理联合、Linux镜像重建、发布与部署均未在本轮执行；既有记录保留各自快照资格 |

E01原先“切号后旧握手标记”的路径已取消，E09改为已选择的零网关重试合同，不再要求恢复官方自动重试。E04路由代次、E05指标语义、E06交付确认、E07目录与选号资格、E08长期归档及E10真实联合资格继续按PLAN单独推进。新代码没有解决或掩盖这些独立事项。

## 2026-10-10 前一P0快照实现与验证

- HTTP/SSE成功与HTTP错误从当前实际响应提取业务控制头；动态额度族仅放官方精确字段，非默认族还须同包存在primary-used-percent。/models返回真实ETag，原版重复同值不再刷新。
- WS先做真实账号选择和上游握手，再向客户端交付101及模型/推理控制头；首个上游426直接为HTTP426，该历史快照429/401仍走旧恢复流程，现已移除。连接记录在私有`state/connections`，实际模型attempt只写`web_socket_connection_used`关联，不把较早101伪记为该轮HTTP响应。
- 统一回包投影处理帧、response/error包络和协议metadata/headers；剔除request-id/cf-ray/账号/路由/sticky等字段，保留业务数据。实际response/item/call/previous-response走会话别名，失败原子回滚。普通文本、错误说明、提示词、工具JSON均不扫描、不改写。WS重拨的非对象JSON错误体不会导致panic，错误转帧保留已投影Retry-After等控制头。
- 指标resource从可信SDK静态来源、固定版本、真实originator/env和系统类型/版本重建，不从被环境污染的旧snapshot挑字段。新批次与冷pending重发都整体替换resource/schema；不设置全局环境变量，不在resource添加共享host/process/安装唯一键。

| 验证层 | 当前证据与限制 |
| --- | --- |
| 完整回归 | `var/verification/p0-final-tests.log`：172通过、0失败；lib47、OAuth15、辅助15、整链遥测1、HTTP16、资源隔离1、metadata11、网络遥测7、正文3、身份32、回包投影8、WS16 |
| 构建/静态 | 测试构建生成当前macOS debug；`p0-final-clippy.log`严格检查通过。固定vendor8775项与45项profile通过，未改官方源码；既有unused patch/future-incompat提示保留 |
| 前一产品SHA | `b009055907b5dd35743d11853383d0e4457d0d62d4ae5fc47d67efcd6522b8ff`，`target/debug/codex-engine-http` |
| 固定原版控制差分 | `native-control-header-5v_gzsh0/report.json`：当前产品SHA，12案全部通过，4组消费者差分一致；脚本`scripts/native-control-header-audit.py`。早期快照报告单独保留 |
| 环境资源反例 | 新批次/污染冷队列、两个合成Pro、真实回环HTTP收包；Statsig JSON、Custom protobuf以及官方URL配置路径均受控验证。不是公网Statsig或真实双Pro验收 |
| 镜像/部署 | 该轮无新Linux镜像、真实OAuth运行或生产部署；下文镜像和158项记录保留为历史证据 |

固定原版的消费者反馈：有推理头（即使字面值false）第二轮上下文token为10，无头为616；HTTP ETag首次generation后刷新一次，第二轮同值不刷新。模型、额度及credits、安全缓冲通知直连与网关一致；WS握手原版仅消费模型/推理，额度/ETag/安全处理仍依赖对应帧。夹具启动时/models次数直连1、网关2，来源未追明，保留在报告，不声称整体网络次数完全相同。

E02固定原版错误诊断：400直连客户端的错误消息含9个结构化协议身份哨兵；网关后的实际RPC错误与trace均不含原始哨兵。403→403→400场验证原版重连诊断会从上游headers追加request ID/CF-Ray，而网关后原始引用消失。两路业务错误说明及400 code/status相同。仅使用隔离原版RPC/stderr，未增加客户端采集器，也未把独立OTel公网交付计为已验。合成Pro凭据前后SHA不变；没有读取或改动宿主真实auth。

**E01范围变更：** 用户已取消流中切号与静默重拨。错误交付后关闭WS，后续客户端新连接取得新握手头；不再要求在旧101下更新推理标记。初次握手预留真实账号、连接与会话身份；非法模型历史仍只保证零模型发送，不代表零连接开销。


## 复审项的当前状态

统一修复与验收计划在 [PLAN](../PLAN.md#复审后的具体收尾顺序)，不另建竞争计划。

| 优先级 | 已核问题 | 影响与证据 |
| --- | --- | --- |
| P0 / E01 | 初始控制链已修；流中切号/静默重拨已按用户决定移除 | 错误后关闭并由下一客户端连接重新握手，本轮重验关闭及错误单次交付 |
| P0 / E02 | 已实现结构化回包身份投影，受控协议回归通过 | 处理明确协议位置，不扫描正文；固定原版400及403重连诊断反例通过。客户端条件OTel出口与默认Analytics分开，不推断私有服务端关联 |
| P0 / E03 | 资源重建及新队列/冷队列隔离已修，受控出口通过 | 不再信任SDK默认环境Resource；实际回环收包验证两个合成Pro，无读取当前宿主环境秘密，无公网接收复验 |
| P1 / E04 | 官方origin/override变化不产生会话/WS绑定路由代次 | 当前路由revision等于认证revision；同认证下旧thread/cache/sticky仍沿用。是同账号跨路由状态问题，不能写成已发现跨账号泄漏 |
| P1 / E05 | 官方网络指标名已复用，事件含义/标签未完全对齐 | WS文本帧统一text/success=true，SSE未知种类归other、EOF记成功，官方timing未完全对齐；401自动恢复已退出范围。终态后的hook被持久账本拒收但仍归原指标实例；“不串轮”不等于“全部迟到事实已保存” |
| P1 / E06 | “已交付”实际先于socket发送完成记账 | HTTP在yield前、WS在send前持久化；不证明客户端收到或执行。需分层记录并补发送失败/退出恢复回归 |
| P1 / E07–E08 | 模型目录与业务选号未绑定；累计256次attempt后无冷归档 | 只考虑两个Pro账号，仍需证明目录资格一致与跨号选号正确。长对话到限持续返回容量错误；受控普通成功差分不覆盖这些条件 |

已做的账号/认证修订隔离仍成立于所测字段：换号确实清空旧映射、密文、资源引用、sticky和cache并创建新身份；正常完成的response/item/call别名已交给客户端，因此不能把客户端独立Analytics笼统说成携带原始池账号response ID。提示词里的ID、目录和路径不列问题、不改写。

只改模型base仍不代理客户端Pro账号的额度查询、Apps Files、Analytics/OTel和外部工具。Memory启动门使用客户端Pro自身额度；池内另一个Pro额度充足不会自动覆盖这道门。OAuth WebRTC的TUI入口与实际OAuth调用链已核实；需要API Key的纯WebSocket已排除。现网关对OAuth通话创建仍501，真实Pro语音未验，因此功能不等价。

真实双Pro联合、历史回执的套餐事实、Memory逐请求原包归属/有效输出、真实新增账号人工授权、长期压力及损坏/跨版本恢复分别待验。本次范围修订不把历史OAuth成功自动提升为Pro全功能资格。

## 既有实现及历史验收

此前主要协议模块快照的完整回归158项及严格Clippy通过；真实客户端主要场景分别通过。收尾发现的HTTP zstd入口、辅助401/429恢复及图片历史容量缺口均已修正并通过专项。用户明确提示词正文中的ID与目录属于普通文本后，已撤回正文改写，重新完成完整回归及双架构构建/启动检查。普通/工具原版差分、备份恢复和真实Linux Release指标HTTP回执按各自源码快照记录，不沿用含正文改写的历史镜像。旧项目和旧生产未改动。

## 实现与隔离

| 模块 | 已实现的行为 |
| --- | --- |
| 纯协议进程 | Rust调用固定官方登录、协议、HTTP、指标库，生产依赖不包含TUI/core/app-server/daemon执行器。官方系统信息库的宿主探测不等于Codex执行载体 |
| OAuth与账号 | 私有凭据/代理/CA，PKCE 1455/1457 loopback、Device Code、串行刷新、401失效停调度及删除排空；宿主导入文件只读 |
| 官方账号路由 | 池内OAuth发现并绑定认证修订；NO_CONSTRAINT保留默认origin，us/us_cr按源码发头，不沿用客户端路由 |
| 准入 | 实际socket peer/CIDR，忽略转发头；客户端OAuth只用于入站形状与私有命名，不作为池内上游认证 |
| Responses | HTTP/SSE/WS、预热、中断、恢复、V2；官方parser与原始事件观察共用同次发送，未知提交不盲重发 |
| 身份与切号 | 分类型item/call/response映射、持久来源与已交付槽；错误后结束当前请求；只有下一独立客户端请求重新选号，换号清理旧密文/缓存/路由并新建身份 |
| 父子对话 | 父协作调用确实由上游产生且已交付时，其message密文才授予子AgentMessage专用证明；不放入reasoning/compaction通用证明；错账号/修订/namespace/用途/密文拒绝 |
| Search | 原生header-only canonical与inventory；Search ID和结构化引用按账号修订持久映射。跨号仅在已观察URL的open/find中转URL，不外发旧账号ref |
| Images | 原生image-turn头按私有namespace和实际业务来源定位；同号对齐turn，换号另建上游turn。图片别名关联源字节，编辑用校验后的Inline字节 |
| 遥测 | 官方Request/SSE/WS hooks、真实完成用量、逐账号MetricsClient与交付队列；官方指标unknown不重发。私有collector至少一次投递，按account_key＋fact_id去重 |
| 管理 | 账号CRUD/排空删除、五档逻辑会话容量、空闲/启动间隔/随机休息；每60秒至多4账号并发检查额度；事实/交付查询清空及单服务容器 |

内部续接历史按固定官方ResponseItem/ContentItem decoder规范化；metadata/logprobs等原版decoder丢弃的字段不进入重放历史，原始客户端交付保持。出口UA、originator、版本、平台来自官方库和真实宿主，不转发客户端值。指标默认资源为dev、实际originator、0.160.0，terminal来自实际检测；网关source保留Custom，不冒称客户端执行器。

## 真实原版客户端

官方0.160.0 arm64客户端与Code Mode host独立安装并校验SHA。每场使用独立home/工作区/网关状态，宿主auth前后SHA相同，原客户端未覆盖。模型按真实目录选用gpt-6.1-sol。

| 场景 | 结果与证据 |
| --- | --- |
| 普通对话、resume | 原生turn完成、同线程恢复标记正确，已通过 |
| 客户端工具 | rollout/JSONL含实际shell完成、退出码和fixture内容，已通过 |
| websearch | 实际原生web_search完成并返回目标仓库URL，最终修正后29.755秒通过 |
| 子代理 | 独立child、正确父归属、子线程实际文件执行、父收到fixture值均通过，26.687秒 |
| V2压缩 | 原版thread/compact/start产生contextCompaction，后续轮取回先前标记，已通过 |
| review | 实际进入/退出review且执行测试工作区命令，已通过 |
| 图片输入 | 原生rollout含图，模型正确回答左红右蓝，已通过；不代表独立生成/编辑权限 |
| 本地文件 | 客户端实际读取附件并返回标记，已通过；不等于Apps Files上传 |
| 中途接入 | 先直连官方，再以同线程resume接网关，标记正确，持久提交input未含先前7个ID；先前密文为0，不算真实外来密文场，也不冒称独立网络抓包证明 |

私有证据在 `var/verification/`，原始内容不进Git：

- `real-final-search-subagent.json` → `real-oauth-20261009T194414Z-274074000/report.json`，最终源码搜索/子代理真执行。
- `real-native-result.json` → `real-oauth-20261009T192727Z/report.json`，工具、RPC初始、compact、after_compact、review通过；该批搜索/子代理失败由上一项复验替代。
- `real-image-result.json` → `real-oauth-20261009T192855Z-3205000/report.json`，图片输入通过。
- `real-supplemental-result.json` → `real-oauth-20261009T192738Z-209613000/report.json`，文件和中途接入通过；该批图片参数错误由独立复验替代。

这是按代码影响范围记录的分批验收，不伪称所有场景来自同一源码快照或同一次进程。

真实独立Images生成和编辑也已通过：`real-native-images-final.json`对应`real-oauth-20261009T195554Z-667985000/report.json`，两个原生ImageGeneration完成、两个实际辅助端点完成，且各自后续turn完成。先前失败场保留：图片工具本身已成功，后续响应被8MiB聚合历史上限拒绝；现为64MiB历史、128MiB持久快照，保存与加载同限，并有图片大小历史恢复测试。

## 历史受控测试与构建

`plaintext-contract-tests.log`：**158通过，0失败**，lib46、OAuth15、辅助15、整链遥测1、HTTP14、metadata11、网络遥测7、正文保留3、身份隔离32、WS14。`plaintext-contract-clippy.log`严格检查通过，`plaintext-contract-build.log`记录macOS arm64 debug构建通过。固定依赖仍打印unused patch/future-incompat提示，未改vendor掩盖提示。Edit响应别名复用由生成→编辑→再次编辑集成验证。该轮debug SHA为`32111e89c69701fed03ad3f22b60781c94781d003242c144c8ac3636fdd7349b`，自有Rust格式和Compose配置检查也通过。旧153项及含正文改写的中间快照日志保留，不当作当前结果。

负例涵盖跨号/外来ID、密文、资源、父来源不足、prepare回滚、并发恢复、unknown、流中及握手429、工具交付防重、EOF/interrupt、迟到WS、停用/删除遥测门、图片未知/异namespace/歧义turn零发送。实际router→受控OAuth上游→OTLP/私有collector核验同wire hash、thread/turn/attempt、状态、用量与交付归属，并断言官方默认资源。

vendor8775项完整性、导出器4项正负例、45种子及35类Analytics/195项指标目录通过。源码完整性不等于官方wire差分，目录统计不是每轮发送数量。

独立空账号管理页验证认证、全局调度保存/刷新、事实和交付读取。另用合成账号验证停用/重新启用、休息显示、页面内保存容量7及刷新、启用账号直接删除与私有auth移除，证据`admin-accounts-final/report.json`和`screenshot.png`；已修复原prompt在内置浏览器中无法输入的问题。单账号即时容量和手动休息不跨进程保存，全局调度设置持久化；真实新增账号的人工浏览器登录未在本场完成。

最终源码快照`docker-native-cross-final-boundary-20261009T204306Z`的amd64/arm64构建、ELF62/183、libssl/crypto、health、UID10001及SIGTERM均通过；构建18.368秒。8806项输入清单SHA为`d8c90f9d1d24e63336d328ffb0d743cb718afce4c6132f7de0e1d8396242f549`，当轮构建后对冻结源码逐项核验无变化。镜像`codex-engine-http-native-final:20261009t204306z`的双架构manifest为`sha256:ce908506c6294a2ab1ae021dc196e1a7682cb8f01ddcbbcf2bc0fcdf3482d52c`；smoke原件SHA `27cb07372d56400524939307575c4ea9a01eaeb189ee66abe0dd13aaba2500b5`。正文改写模块已删除，两架构测试容器已清理。该场验证架构、启动和退出，未重新发送OAuth模型请求；仅本地构建，未发布。

此前`codex-engine-http-native-final:20261009t201443z`的Linux arm64 Release真实OAuth普通轮通过，官方Statsig出口取得HTTP成功回执，宿主auth未变、SIGTERM退出0。证据`linux-release-6728f39f0ad3/report.json`直接由修正后的runner产生；旧ANSI误判原件及重解析报告保留。该场早于Memory头细分修复，普通轮及指标实现未变；它不是最新镜像的OAuth复测。HTTP回执不代表逐点入库，未宣称服务端私有消费行为。


固定官方二进制差分（`native-wire-differential-2hjcdm43/report.json`）已完成普通轮与真实工具往返：两边分别1、2次实际zstd POST及SSE，方法/路径/业务JSON、逐项content_item_kinds、类型化ID映射、池内认证与客户端线程隔离均通过。客户端明确给出的内容分类保留为业务元数据，client turn/time/cell与工具执行声明仍不外发；它不是网关工具事实。UA保留各进程的真实官方构造（CLI有codex_exec后缀），不复制客户端UA。仅验证受控loopback `/v1`分支，不冒称HTTPS工作区域或所有故障时序差分。

该差分也断言上游426：普通和工具场的直连、网关均各1次握手。修复前网关曾重复7次，原报告保留；该历史实现仅缓存真实426，绑定namespace/thread/账号修订/出口，60秒/256条且401、429、未知结果不缓存；当前已删除该缓存。该历史快照首次下游101后封装426的差异已由本轮preconnect修正；新受控回归证明首个HTTP426，不将它推广为所有故障时序等价。

有界并发审计（`bounded-load-20261009T200009Z-1dd2a599/report.json`）在28.139秒完成400请求、48scope、并发16：374客户端completed、14刻意非法请求400、12客户端主动断流；实际386上游请求，无额外重发，持久记录383completed/3unknown。两次进程正常退出并重启恢复。六个身份域分别隔离；RSS原始样本约25.69→46.97MiB、重启后25.55→51.48MiB，状态最终2,141,936字节。它是短时受控负载，不是长周期或真实多账号吞吐结论。

异目录备份恢复（`backup-restore-20261009T201537Z-e4973f92/report.json`）2.613秒通过：停止进程后复制完整state和配置、移除原导入源并退役旧目录，新目录启动仍继承thread/session/cache/window/installation与已完成response别名；先前生成PNG的alias在恢复后编辑时重建原字节。全局调度设置、首JSONL和attempted OTLP原件SHA保持，实际503批次恢复后未重复发送，两次SIGTERM退出0。修复了账号启动对原auth_path的持续依赖；显式reload的身份拒绝仍通过。动态注册来源仅对明确gateway_owned_source记录重定位，3项专项包含该分支。

这场仅验证同版本完整私有备份，不证明部分/腐败或跨版本恢复；管理员HTTP事实列表是当前进程内视图，持久JSONL原件仍在。单账号即时capacity/rest及登录job暂态；本轮新增的401失效/429截止时间已持久化，全局调度配置持久化。未读取宿主真实auth，未访问外网。

## 边界与待验项目

1. OAuth WebRTC sideband绕过模型base且用客户端自身认证，因此创建前双语501、零上游创建；当前接入约束下不宣称完整语音支持。
2. 客户端Analytics/OTel、Apps Files、MCP独立直发。没有采集器就没有完整工具/审批事实，不制造这些事件；收到工具输出不等于观测完整执行。
3. 外部加密历史/file_id缺明文或字节时没有重建依据；跨号不硬转发旧密文或资源。实时SSE无法撤回；用户已取消流中续接，错误交付后结束。
4. 请求64MiB、缓存4096会话、每会话attempt256、历史64MiB及来源表有界；unknown不静默驱逐，长期压力及历史容量迁移待专项。
5. 真实双OAuth额度切号尚缺第二份独立账号验收；下一独立请求切换账号已有受控场。Memory/Guardian实际后台已触发，按用户明确范围保留正文；未宣称阶段1逐请求原包已经捕获。
6. 全分支固定官方wire/客户端恢复/时序差分、长周期压力、真实新账号人工授权及跨版本/损坏备份恢复仍未验。最终双架构、同版本完整备份恢复和Release指标HTTP回执已通过。
7. 私有上游识别规则没有公开证据，不承诺上游绝对无法区别实现。

## 发布与部署

未发布镜像、推送仓库或部署远端，旧服务未迁移。Dockerfile/Compose/deploy.sh面向新项目单服务，不是旧项目自动升级器。当前实施依据为 [PLAN](../PLAN.md)，逐项验收见 [ACCEPTANCE](ACCEPTANCE.md)。

## 后台真实补测与正文处理范围

用户已明确：提示词正文里的ID、用户目录和路径仅作文本，不纳入隔离。instructions、input_text、序列化历史文字和Guardian说明均原样保留；协议头、原生ID/资源引用、原生加密reasoning等仍按来源与账号修订隔离。不把纯文本中的id键当作原生协议字段。此前Guardian正文改写及其拒绝分支已撤回，Memory正文双向映射不属于实施范围；相关历史报告的文本“泄漏”判据不再适用。

Guardian（`native-guardian-20261009T202257Z-653a7fd0/evidence-recheck.json`）28.70秒完成官方auto_review started→approved、默认权限无害命令、工作区marker及普通对话恢复；宿主auth未变。原始report的role过滤过窄已由只读recheck纠正，原件保留。该场正文未改写，符合当前用户要求。后续曾验证正文投影版，`native-guardian-20261009T203720Z-79070695/report.json`的8/8功能成功仍属历史快照，不能把它记为当前源码运行。

Memory（`native-memory-audit-arpamj5x/analysis.json`）使用合格vscode旧线程、官方memories开关、min_rollout_idle_hours=1，extract/consolidation均为gpt-6.1-sol。完整复制home后只重定位复制体SQLite路径，未改变source/updated_at/memory_mode，原件未变。stage1和global consolidation完成，stage1_outputs=0：原生流程成功，无有效记忆产出。最初exec来源误算候选的旧场只到全局空水位，不计提取成功。固定phase1.rs:200–239,262–320确认no-output须经过模型流与结果解析；现有账本没有阶段1逐请求标记或原包，不能把11条Responses中某条凭时间猜为phase1。

Memory协议头修复保留：detached extraction不再由kind=memory获得memgen；官方内部整合须具有正确canonical source、同名subagent及单个精确true入站头。对应11项metadata回归通过；源码判定依据core/client.rs和responses_metadata.rs，而不是任意头透传。正文路径及历史ID保持原文是用户要求的正确行为。

## 2026-10-10 Codex2API 管理接口交付

参照本机codex2api源码完成三项入口：生成OAuth授权URL、回传code兑换并新建/更新Pro账号、lite/codex账号列表。X-Admin-Key与缺省Bearer均验证管理token；PKCE/state/代理绑定，15分钟内存会话、一次兑换、同码回执与本地完成重试，默认1455回调但不占监听端口。官方OAuth数据仍由现有固定0.160.0适配器发送。

账号按workspace识别，整数管理别名持久保存且删除后不复用；邮箱/套餐来自凭据，标签不作身份。新凭据解除401，有效429冷却、管理停用及活动请求旧快照保留；排空删除不被重新授权恢复。真实代理传输、同邮箱不同workspace、同workspace并发导入、错误代理/state、断线及并发重复兑换都已受控验证。注册或ID文件写失败后，保留私有凭据/已注册阶段；同一session只重试本地完成，token POST始终一次。恢复限同进程与会话有效期，逐文件原子写入不宣称跨文件崩溃事务。

最终完整215项测试通过（原197项＋新增18项，其中10项接口集成测试），严格Clippy、定向格式检查、macOS debug构建通过。日志见 `var/verification/codex2api-tests-final.log`、`codex2api-clippy.log`、`codex2api-build.log`；来源与产物摘要见 `codex2api-manifest.json`。初轮旧断言及测试配置缺字段在定向测试中修正，最终全量无失败。

用户明确本轮不做iOS验证，只实现三个服务端接口；未操作iOS工程、宿主凭据或真实账户，未发布/部署。参考项目的其它厂商/完整分页视图、任意回调、全局代理回退及失败后再次兑换不引入本项目；空代理表示直连并清除旧代理，列表以proxy_configured替代带密码proxy_url。E04–E08、E10等既有收尾项不随这次管理接口完成而勾选。
