# right-codex：验收要求

固定 Codex 0.160.0；原版客户端 ChatGPT Pro OAuth、默认 OpenAI provider、只改 openai_base_url；池内账号也只用 ChatGPT Pro OAuth。其它套餐及 API Key 专用功能不列待办、不计验收缺口。服务端不启动 TUI/daemon/login 子进程，不重复客户端工具、Memory、Guardian、review 或压缩准备。

下面分开记录受控实现与真实联合资格。旧项目成绩不算本项目成绩，源码存在不等于真实上游授权。当前总审计见 [IMPLEMENTATION-AUDIT](IMPLEMENTATION-AUDIT.md)。

## 已通过的源码与受控合同

- [x] 固定 Git 导出8775项无漂移；4项导出器正负例；45项种子及同提交35/195资料目录。
- [x] 模型 base 的实际 OAuth 消费者与独立出口清单；图片沿实际生产调用核实，不凭SDK方法存在判范围。
- [x] 可信socket peer/CIDR＋原生OAuth形状准入；忽略转发头，客户端凭据不传池内上游，管理token独立。
- [x] 规范业务字段、canonical metadata、用途、省略与身份统一投影；分类型item/call/response，原子失败回滚，自由JSON不递归改写。
- [x] OAuth PKCE真实loopback/state、Device获取/轮询/取消/到期、显式串行刷新、401停调度、代理、账号修订与排空删除；网络头按API/refresh与rawDevice/PKCE分支核实。
- [x] 官方账号workspace发现与NO_CONSTRAINT特殊值；owner/HTTPSorigin/header门；无副作用候选探测。
- [x] HTTP一次真实zstd发送，原始SSE与官方parser共同观察；实际终态/完整错误体/分片/usage attribution/取消/EOF/重启。
- [x] WS预热、增量/previous response来源、同连接多轮、426 fallback、interrupt/incomplete、取消unknown；迟到metadata/rate-limits归连接而非下一attempt。
- [x] V2仅Responses：恰一个Compaction＋真实completed，EOF/失败不成功，下一轮同源密文复用。
- [x] 历史流中切号与401刷新重发已按最新用户决定移除，不再作为验收目标；下一次独立请求换号仍须新建ID/缓存/turn并保留来源门。
- [x] 持久输入/attempt/密文/资源/response来源；并发lazy恢复同一scope，父来源按账号认证代次校验。
- [x] Models、官方Search形状、Images生成/编辑受控出站；客户端foreign账号头不决定池内账号；图片alias解析真实源字节Inline，缺字节不回传上游ID。
- [x] 官方Request/SSE/WS hooks、真实完成usage histogram、逐账号metrics、unknown投递不盲重试、冷队列查询/清空；缺指标字段不补零。
- [x] 自有运行代码及生产依赖图不包含TUI/core/app-server/daemon执行载体；无MITM CA、无runtime Python。

## 本轮继续验证

- [x] 整个router→实际受控上游→逐账号OTLP/私有collector：同wire hash、thread/turn/attempt、status/usage与交付归属闭环。
- [x] 停用/重新启用、排空删除、认证修订变化后的遥测发送生命周期；停止后不重建已删除账号目录。
- [x] 私有 collector 停用、重新启用、删除排空门；至少一次投递与稳定 fact_id 去重合同。
- [x] 此前完整158项测试及严格Clippy通过；含15项辅助接口、11项metadata和3项正文保留回归。
- [x] 辅助Search/Images/Models改为单次发送，上游错误保留原状态和业务正文；401停调度、带有效重置时间的429冷却，下一独立请求才重新选择账号。
- [x] 原生HTTP zstd入口有界解码；畸形/截断/超限拒绝，原版差分确认HTTP fallback实际消费。
- [x] 两轮图片历史超过旧8MiB限制时正常持久恢复；历史64MiB、快照128MiB保留硬上限。
- [x] 私有账号缺原导入源仍恢复；显式reload拒绝换身份；明确登记的动态账号来源随state迁移，外部路径不猜测重写。
- [x] 管理页认证、调度保存与刷新持久、调用事实/指标交付读取；容量、休息保留既有会话、空闲回收及重启设置回归。
- [x] 400请求/48会话/并发16，断流、身份六域与重启恢复短时负载。
- [x] 隔离合成账号管理页：停用/启用、手动休息显示、页面内容量保存及刷新、启用账号直接删除和私有凭据移除。
- [ ] 长周期资源界限压力、真实新账号浏览器授权人工流程。

## 真实原版客户端与发布资格

- [x] 官方0.160.0测试二进制及Code Mode host独立下载、SHA核验；宿主客户端未覆盖。
- [x] 宿主auth只读导入独立home，前后SHA相同；真实账号路由与模型目录成功。
- [x] 普通对话与同线程resume真实成功。
- [x] 真实客户端工具执行与往返、websearch、子代理实际执行；日志不只验证最后文本。
- [x] 中途加入真实resume与明文标记、私有提交input身份检查；该场外来密文为0，不计密文真测或独立wire抓包证明。
- [x] 原版thread/compact/start、实际contextCompaction、压缩后继续、review实际命令执行。
- [x] 真实图片输入、本地文件读取；不等于独立Images或Apps Files权限验收。
- [x] 独立Images生成/编辑真实端点成功及后续原生turn完成。
- [ ] 两个不同Pro OAuth账号切号联合；当前只有一份真实账号测试来源。历史真实场须核对套餐证据后才能记为Pro验收。
- [x] Guardian真实auto_review→批准→客户端无害命令→普通轮恢复。
- [x] 合格vscode真实历史触发Memory stage1/no-output及consolidation；原home/workspace/auth保持不变。
- [x] 用户明确正文ID/目录/路径均为普通文本，不纳入隔离；已撤回来源文本改写与额外拒绝分支。
- [x] Memory detached/consolidation标头分流；不凭kind=memory补造memgen，官方三事实及重复/错误值反例通过。
- [x] 此前正文保留回归、完整158项测试与该快照双架构构建/启动检查；实际协议字段仍独立映射，不能混淆文本与原生资源/密文字段。
- [ ] Memory stage1逐请求原包/用途归属与有用记忆生成；当前job完成不能替代逐请求原包证明。
- [x] 固定原版普通/工具HTTP差分：真实zstd、SSE消费、业务字段、内容分类、类型化ID映射及账号隔离；loopback `/v1`范围。
- [x] 历史固定原版426回退证据保留。现行网关删除426缓存；每次握手只发一次，上游426直接交付给客户端，后续重连单列新握手。
- [ ] 全分支默认HTTPS路由/故障时序差分；首次426在本轮已改为真实HTTP拒绝，客户端自己的恢复与网关零重试分开结算。
- [x] Linux Release真实OAuth对话＋官方Statsig出口HTTP成功回执；不推断逐点入库。原始日志证据和ANSI解析修正分别保留。
- [x] 此前Linux amd64/arm64镜像及各自运行smoke；冻结构建来源与该轮源码一致，Compose配置检查通过。
- [x] 同版本完整state备份→异目录恢复，继承会话/response别名/图片bytes/调度/事实及未知交付原件，原导入源移除后仍启动。
- [ ] 部分或腐败备份、跨版本恢复、实际生产发布部署；旧生产未迁移。

## 2026-10-10 复审新增待验（只含Pro OAuth）

以下记录复审后继续实现的结果；原有勾选仅覆盖当时所列受控场，真实OAuth及镜像未因本轮受控测试自动升级资格。

- [x] E01首段：HTTP真实响应头及首次WS握手的模型/推理消费者；HTTP额度/ETag/安全处理与固定客户端对照，/models保留ETag。
- [x] E01原流中切号/静默重拨分支退出范围；错误后关闭连接，下一独立WS握手重新取得控制头，不在同一101下替换账号。
- [x] 初始WS握手独立连接记录、模型attempt显式引用connection_id，握手不补造模型请求、不回填成首轮新HTTP响应；重拨错误数组无panic，Retry-After保留且私有头剔除。
- [x] E02受控协议：WS metadata/error/迟到帧、HTTP嵌套错误结构化身份投影；同会话重用、跨账号/修订轮换、原样文本及事务回滚。
- [x] E02原版诊断专项：400与403重连错误的协议身份哨兵在网关后的真实RPC错误/trace中消失，业务说明及code/status保持；未启用公网OTel出口，不计其交付验收。
- [x] 前一产品SHA固定原版12案全部通过、4组控制消费者差分一致，报告`native-control-header-5v_gzsh0/report.json`。
- [x] E03：独立子进程、两个合成Pro、新批次及污染冷队列，实际回环收包证明环境资源被可信静态资源完整替换；Statsig JSON与Custom protobuf及官方URL配置均覆盖，公网官方接收未重验。
- [x] 前一快照完整172项回归与严格Clippy通过；固定8775项vendor无漂移、45项源码profile核验通过。
- [ ] E04：认证不变而origin/override改变，HTTP/WS身份、连接、sticky及迟到事件按路由代次处理。
- [ ] E05：同一SSE/WS输入的官方指标分类、成功/失败、标签、EOF、timing差分；终态后观测落原attempt的独立账本。
- [ ] E06：预记交付后发送失败/进程退出/恢复，区分交付提交、socket写入和客户端执行；不把预记当确认收到。
- [ ] E07：模型目录与实际业务账号资格一致；合成Pro目录差异负例及真实双Pro切换。
- [ ] E08：超过256次请求、压缩、换号、重启后同对话继续，冷归档不丢unknown及来源依赖。
- [x] E09新合同：确定401/429/5xx、transport失败、提交未知、首次426均不由网关自动重试；已验原版400/403错误消费及客户端恢复，原版自身重试单列为新的入站与握手。其它网络故障真实联合仍按独立验收门处理。

## Codex2API 三个管理接口验收

用户指定参考 `<reference>/codex2api`，本轮只实现三个服务端接口，不做iOS联合验证。

- [x] `X-Admin-Key`创建授权、回传code/state、读取lite/codex列表；整数ID与账号稳定对应，管理认证不混入模型入口；支持管理Bearer缺省回退，错误X-Admin-Key不被覆盖。
- [x] 固定默认1455回调，无本机监听依赖；session/PKCE/state/期限/代理绑定，错配、到期、重放、并发及调用方断开不重复兑换；实际HTTP代理兑换与重授权清代理已验。
- [x] 邮箱/Pro套餐取自授权凭据；列表不含token/代理密码、不触发额度或恢复探测，401/429/停用/休息状态正确。
- [x] 整数别名重启保持、删除后不复用；重复workspace更新凭据/代理，旧请求快照、有效冷却、管理停用与删除排空规则保持。
- [x] 服务端受控OAuth正负例、完整215项回归、严格Clippy、格式检查及macOS debug构建；新增18项包含10项接口集成测试。
- [x] token兑换成功后账号注册/整数ID文件写失败，保留私有凭据与已完成阶段；恢复后同session只做本地完成，上游token POST始终一次。

证据：`var/verification/codex2api-tests-final.log`、`codex2api-clippy.log`、`codex2api-build.log`及`codex2api-manifest.json`。本轮按用户要求没有iOS联合或真实OAuth授权，也未部署；逐文件原子写入不等于跨文件崩溃事务。

## 当前接入约束下的明确边界

- 只计实际 OAuth 分支：原版 TUI WebRTC/V3 调用链已核；需要 API Key 的纯 Realtime WebSocket 不属于待实现项，不计缺口。OAuth 通话权限与完整真实语音尚未验收。
- 原生OAuth WebRTC sideband默认绕过模型base，并带客户端自身OAuth；公开calls/live创建前双语501，零上游创建。只有局部SDK测试，不计完整语音资格。
- 客户端Analytics/OTel、Apps Files、MCP独立直发。没有完整客户端工具/审批/app-server事实，不补造这些事件。
- 客户端Pro账号与池内Pro账号的剩余额度独立；Memory的客户端启动门查询客户端账号，不受模型base覆盖。
- 外部密文/file_id缺明文或字节时无法重建；实时SSE不可撤回，原错误返回后结束，已取消切号续接；unknown不得无条件重播。
- 请求与持久来源有明确容量界限，unknown不静默驱逐；不宣称无限历史或私有上游绝对不可区分。

## 本轮错误透传与账号调度验收

- [x] HTTP/SSE、辅助入口上游错误不触发401刷新、429切号或5xx重发；原业务错误与二进制/空/非JSON错误体保留。
- [x] 429只读实际未来重置时间；无时间、已过期、格式错误及文字提示不制造冷却。
- [x] 401按实际访问凭据、429截止时间按账号持久化；重启保留、健康usage和新access token不清有效冷却、旧修订迟到错误忽略。
- [x] 同凭据重新导入、改代理/配置及简单启用不解除401；实际新access token解除401。写盘失败时内存停调度仍成立，原错误继续交付。
- [x] WS拒绝握手分片/长正文/chunked/截断、错误单次交付后关闭、闲置401/response.failed、会话锁占用、其它已开连接停调度及持久化失败反例通过。
- [x] Retry-After在收到头时固定倒计时，正文延迟消耗原等待时长；过期后不重启冷却，正文实际未来resets_at仍独立生效。
- [x] 最终197项回归、严格Clippy和macOS debug构建；最终产物原版受控12案/4组消费者差分通过，报告`native-control-header-p9_ylij0/report.json`。
- [ ] 真实双Pro及生产HTTPS/代理联合、Linux镜像和部署未在本轮执行。

## right-codex 更名验收（2026-10-10）

- [x] 项目目录、Git定位、Cargo包名/库名/程序名、锁文件与当前文档引用一致。
- [x] 管理页标题、health项目名、自有遥测来源名、Docker入口和维护脚本同步；旧镜像及历史证据保留原名称。
- [x] Compose配置、脚本语法、Rust格式、完整215项回归、macOS debug构建与实际进程启动/退出检查通过；未访问真实OAuth或部署。

证据位于 `var/verification/right-codex-rename-*`，更名实施记录见PLAN。

## 公开源码与多架构发行（2026-10-10）

- [x] GitHub公开空仓库及推送权限、Docker Hub本机登录身份已核对；发布范围为本项目源码与运行镜像。
- [x] Apache-2.0与上游NOTICE随源码和镜像保留；个人指令、账号凭据、配置、状态和私有原包排除。
- [x] 发布脚本一次构建amd64/arm64，并校验时间戳和latest的远端索引；Compose改为直接拉取镜像。
- [ ] Git索引与8775项官方vendor清单逐项核对、干净源码发布。
- [ ] 当前源码的Linux amd64与arm64 Release镜像分别启动、架构与健康接口、SIGTERM检查。
- [ ] GitHub公开源码推送、Docker Hub双架构镜像公开拉取、latest与时间戳对应同一索引。

发行不替代真实双Pro及其余协议待验，不执行生产部署。
