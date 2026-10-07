# 防篡改审计链路说明

本服务在现有 FastAPI 入口（`main.py`）之上实现了一条本地可验证的追加式审计链：
每条记录与前驱记录密码学相连，事后的**修改、删除、重排、拼接**都会在校验时
被检出，并给出**可区分的失败码与原因**。

| 模块 | 职责 |
| --- | --- |
| `audit/models.py` | 记录 / 检查点 / 校验结论的数据模型 |
| `audit/normalization.py` | 版本归一化、严格 schema 校验、敏感字段脱敏 |
| `audit/hashing.py` | 确定性 JSON 序列化与 SHA-256 哈希 |
| `audit/integrity.py` | 链的构建（`prev_hash` 链接）与完整性校验 |
| `audit/storage.py` | 持久化 JSONL、fsync、跨进程文件锁、原子重写 |
| `audit/retention.py` | 保留期判定与连续前缀剪枝 |
| `audit/forwarder.py` | 下游转发：HTTP 下游、重试、游标、幂等账本、积压恢复 |
| `audit/service.py` | 门面：并发安全地串联以上组件 |
| `audit/api.py` / `main.py` | HTTP 入口与本地校验 CLI |

## 1. 记录格式与哈希结构

每条落盘记录都是同一套 canonical 形态（`version` 记录来源代次，
v0 旧格式在写入前已归一化，见第 3 节）：

```
version, seq, id, timestamp, actor, action, resource, detail, prev_hash, record_hash
```

- `record_hash = SHA256(canonical_json(除 record_hash 外的全部字段))`，
  规范化 JSON 规则：键按字典序递归排序、无多余空白、非 ASCII 不转义、
  禁止 NaN/Infinity。因此字段书写顺序不影响哈希，但**任何**被覆盖字段的
  改动都会改变哈希。
- `prev_hash` 指向前一条记录的 `record_hash`；首条记录指向 64 个 `0`
  的创世哈希。因为 `prev_hash` 也参与自身哈希，任何位置的记录都与其在
  链中的位置绑定。
- `seq` 在追加锁内单调分配，从 1 开始；剪枝后从 `checkpoint.seq + 1`
  继续。

## 2. 完整性判定语义

`GET /audit/verify`（或 `python main.py verify`）按固定顺序检查，首个
失败立即给出结论，正常与异常结论严格可区分：

| error_code | 含义 / 判定依据 |
| --- | --- |
| `empty_chain` | 无任何记录且无检查点（全新空库） |
| `duplicate_sequence` | 出现重复 `seq`（并发/重复写入） |
| `missing_record` | seq 集合不是从起点开始的连续集合（删除了记录或插入了链外记录），返回 `missing/extra` 明细 |
| `ordering_error` | 物理顺序与 seq 顺序不一致（记录被重排） |
| `hash_mismatch` | 存储的 `record_hash` ≠ 重算值（记录内容被改动），返回两个哈希前缀 |
| `chain_break` | 某条记录的 `prev_hash` ≠ 前一条的 `record_hash`（重写/拼接，即使攻击者重算了被改记录自身的哈希，也无法在不重算整条后缀的情况下修复链接） |
| `checkpoint_mismatch` | 剪枝后首条留存记录的 `prev_hash` 与检查点锚点不一致 |

成功时返回 `ok=true`、记录总数、seq 区间与链头哈希，例如
`verified 3 record(s); seq 1..3; head f5c78ca93bfb...`。

剪枝后全空（只有检查点）属于**合法状态**：结论 `ok=true`，
原因 `chain_fully_pruned_checkpoint_present`。

## 3. 归一化、格式兼容与脱敏规则

- **跨版本兼容**：同一个入口（`POST /audit/records`）同时接受两代记录，
  归一化成同一套 canonical 语义后再入链、脱敏、转发：
  - **v1（当前版）**：`id / timestamp / actor / action / resource /
    detail`，`version` 可省略（缺省按 v1 处理）；
  - **v0（旧版）**：字段名不同但语义相同，按固定映射归一化——
    `event_id→id`、`at→timestamp`、`user→actor`、`op→action`、
    `target→resource`、`meta→detail`，且必须显式携带 `version: 0`。
  - 归一化是一对一映射：旧格式里有的信息**不会**因字段叫法不同而丢失，
    也**不会**悄悄补默认值。落盘记录的 `version` 保留来源代次（0 或 1），
    该字段同样被哈希覆盖；落盘 schema、列表返回与校验结论对两代记录
    完全同口径（校验逻辑不区分版本，只重算哈希与链接）。
  - 未知版本（如 `version: 7`）→ `unsupported_version`，明确拒绝。
- **不静默丢弃、不静默补全**：
  - 出现未声明字段 → `unknown_field`，连同字段名返回（v0 载荷里出现
    v1 字段名，或反之，同样按未知字段拒绝，不允许混代书写）；
  - 缺少必填字段（v1：`id/timestamp/actor/action/resource`；v0：
    对应的五个旧字段名）→ `missing_field`；
  - 空字符串、类型不符、无法解析的 ISO-8601 时间、`detail`/`meta`
    非对象、非 JSON 原生值 → `illegal_value`；
  - 落盘行损坏 / 缺字段 / 含未知字段 → `corrupt_record`。
- **脱敏**：`detail`（含 v0 的 `meta` 归一化后的内容）内的敏感键在
  **哈希之前**被替换为固定标记 `"__redacted__"`（嵌套对象与列表递归
  处理，支持 `user.password` 这类带前缀键名）。因此：
  - 脱敏后的记录仍能正常通过完整性校验（哈希覆盖的是脱敏后的形态）；
  - 原始密钥**不会**出现在落盘文件中，也不会出现在任何对外返回中
    （有测试直接扫描磁盘字节与响应体确认）；
  - 非敏感字段原样保留。

敏感键默认可在 `audit/normalization.py` 的 `DEFAULT_SENSITIVE_KEYS`
中查看，可用环境变量 `AUDIT_SENSITIVE_KEYS="pin,cvn"` 追加。

## 4. 保留（清理）规则

- 超过 `AUDIT_RETENTION_DAYS`（默认 90 天）的记录可被清理，
  `POST /audit/prune` 触发。
- **与转发进度配合**：转发开启时，一条记录要被清理必须同时满足
  "已过期"且"已被下游确认"（`seq <= 转发游标`）。已过期但尚未成功
  转发的记录**一律保留**，等游标追上来后下一轮清理才会释放；游标
  只在发送成功后推进，因此清理读到的游标永远是"已送达"的下界，
  不会误删在途数据。转发未开启、或游标已追平时，清理行为与纯按
  时间的旧策略完全一致。
- 只删除**连续前缀**：遇到第一条仍在保留窗口内、或尚未被下游确认的
  记录即停止，绝不在中间留洞，也绝不删除仍在窗口内/未送出的数据。
- 被删前缀的最后一条记录固化为**检查点**（`seq/id/record_hash`），
  剪枝后留存链以检查点为锚，依旧完整可校验。
- 剪枝与追加使用同一把锁（进程内 `threading.Lock` + 跨进程
  `fcntl.flock`），且保留集合取自锁内快照并以临时文件 +
  `os.replace` + 目录 `fsync` 原子落盘；剪枝进行中的新写入要么在
  重写前、要么在重写后进入，**不会被误删**。剪枝后首条新记录链接到
  检查点而非创世哈希，因此**不会被误判为篡改**。转发器的多次并发
  冲刷由内部互斥锁串行化，并发"清理 + 转发 + 写入"下既不丢记录、
  不重复投递，也不会把正常链判成篡改（有并发用例覆盖）。
- 剪枝完成后会立即自校验；若自校验失败会显式报错，而不是留下无法
  解释的链。

## 5. 下游转发、失败重试与恢复语义

通过 `AUDIT_FORWARD_ENABLED=1` 启用，`POST /audit/forward` 触发。

- **真实下发**：启用后还需用 `AUDIT_FORWARD_URL` 配置下游接收地址
  （HTTP POST，JSON 体为单条 canonical 记录，2xx 视为送达）。从接口
  触发即真正按序推送积压记录；未配置地址时接口返回
  `forwarding_not_configured`，未启用时返回 `forwarding_disabled`，
  两种情形可区分。请求超时由 `AUDIT_FORWARD_TIMEOUT`（秒，默认 5）
  控制；连接失败、超时、非 2xx 都按可重试失败处理。
- **游标（cursor）**：持久化已被下游确认的最大 seq，每次成功发送后
  fsync 落盘。重启后从 `cursor+1` 继续，实现**积压恢复**。
- **有界重试**：单条最多尝试 `AUDIT_FORWARD_MAX_ATTEMPTS`（默认 3）次；
  仍失败则在该条处**有序暂停**——不会跳过它去发后面的记录（避免乱序
  造成的缺口），游标停在最后成功位置。
- **幂等账本**：已确认的记录 id 追加记入 `forward.state.ids`，游标与
  账本共同保证重发不会导致下游重复接收；游标落后但 id 已确认时只推进
  游标而不重发。
- **崩溃窗口**：发送成功与游标落盘之间崩溃只会导致至多一次重投，由
  幂等机制吸收；不存在"已确认但游标未推进导致的数据丢失路径"，也不
  存在重复。
- 返回体给出 `sent / skipped_duplicates / attempts / cursor_after /
  failures`，失败时带 seq、id 与最后一次错误，结论可解释。

## 6. 并发语义

- 所有读改写链状态的操作都在同一把锁内取快照，seq 在锁内分配。
- 并发追加（测试中 16 线程 × 50 条）保证：无重复 seq、无空洞、
  哈希链一致。
- 并发校验永远只观察到自洽状态（空链或某条完整链），读不到"接了
  一半"的链。

## 7. HTTP API

| 方法与路径 | 说明 |
| --- | --- |
| `POST /audit/records` | 追加一条审计记录（校验+脱敏+入链+落盘） |
| `GET  /audit/records` | 列出留存记录（不含任何原始敏感内容） |
| `GET  /audit/verify` | 完整性校验，返回结构化结论 |
| `POST /audit/prune` | 按保留期清理 |
| `POST /audit/forward` | 转发积压记录到下游 |

领域错误返回 JSON：`{"ok": false, "error": "<code>", "message": ...}`，
schema 类错误 HTTP 400，seq 冲突 HTTP 409。

## 8. 配置（环境变量）

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `AUDIT_DATA_DIR` | `data` | 日志 / 检查点 / 转发游标目录 |
| `AUDIT_RETENTION_DAYS` | `90` | 保留天数 |
| `AUDIT_FORWARD_ENABLED` | `false` | 是否启用下游转发 |
| `AUDIT_FORWARD_URL` | （空） | 下游接收地址（HTTP POST）；启用转发后必填，否则接口返回 `forwarding_not_configured` |
| `AUDIT_FORWARD_TIMEOUT` | `5.0` | 单次下游请求超时（秒） |
| `AUDIT_FORWARD_STATE` | `forward.state` | 游标文件名（位于数据目录） |
| `AUDIT_FORWARD_MAX_ATTEMPTS` | `3` | 单条最大尝试次数 |
| `AUDIT_SENSITIVE_KEYS` | （内置集合） | 追加的脱敏键，逗号分隔 |

## 9. 本地验证方法

```bash
# 安装依赖
uv sync

# 运行全部测试（日志会打印每个用例的输入、判定依据与最终结论）
uv run pytest -s

# 启动服务
uv run python main.py serve

# 追加 / 校验
curl -s localhost:8000/audit/verify
curl -s -X POST localhost:8000/audit/records -H 'content-type: application/json' \
  -d '{"id":"e1","timestamp":"2026-09-26T10:00:00","actor":"a",
       "action":"login","resource":"/r","detail":{"password":"x"}}'

# 旧版（v0）记录从同一入口写入，归一化后入链
curl -s -X POST localhost:8000/audit/records -H 'content-type: application/json' \
  -d '{"version":0,"event_id":"old-1","at":"2026-09-20T08:00:00",
       "user":"legacy","op":"export","target":"/reports",
       "meta":{"rows":10}}'

# 脱离 HTTP 直接校验磁盘上的链（退出码 0=完整，2=检出篡改/异常）
uv run python main.py verify

# 人为篡改演示：编辑 data/audit.log 中某条记录的任意字段后再次校验，
# 将得到 hash_mismatch / chain_break / missing_record / ordering_error
# 等可区分结论

# 本地复现"接口触发真实转发"：先起一个本地下游（打印收到的记录）
uv run python -c "from http.server import *; \
  H=type('H',(BaseHTTPRequestHandler,),{'do_POST':lambda s:(print(s.rfile.read(int(s.headers['Content-Length'])).decode()),s.send_response(200),s.end_headers()),'log_message':lambda *a:None}); \
  ThreadingHTTPServer(('127.0.0.1',9000),H).serve_forever()" &

# 打开开关并配置下游地址后启动服务
AUDIT_FORWARD_ENABLED=1 AUDIT_FORWARD_URL=http://127.0.0.1:9000/ingest \
  uv run python main.py serve &

# 写入几条记录后从接口触发转发，下游终端会按序打印收到的记录
curl -s -X POST localhost:8000/audit/forward

# 停掉下游再触发可观察重试与有序暂停；重启下游后再次触发即积压恢复
```

测试覆盖三类必需场景：并发追加（`tests/test_concurrent_append.py`）、
人为篡改（`tests/test_tamper_detection.py`）、转发失败
（`tests/test_forward_failure.py`），并另含脱敏/格式
（`tests/test_redaction.py`）、保留并发（`tests/test_retention.py`）、
API 端到端（`tests/test_api.py`）、跨版本兼容
（`tests/test_versions.py`）、清理与转发进度配合
（`tests/test_retention_forwarding.py`）与接口触发真实下发
（`tests/test_forward_http.py`）。
