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
| `audit/forwarder.py` | 下游转发：重试、游标、幂等账本、积压恢复 |
| `audit/service.py` | 门面：并发安全地串联以上组件 |
| `audit/api.py` / `main.py` | HTTP 入口与本地校验 CLI |

## 1. 记录格式与哈希结构

每条记录（v1）的字段：

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

- **版本**：入站支持两代格式——当前版 **v1** 与老系统版 **v0**。
  无论来自哪一代，记录都会在入链**之前**被归一化成同一个 v1 形态
  （`version` 一律落为 1），因此落盘内容、列表返回、转发载荷与
  校验结论只有**一套判定口径**。
- **v0 → v1 字段映射**（同一件事的两种叫法，信息不丢）：

  | v0（老格式） | v1（归一化后） |
  | --- | --- |
  | `event_id` | `id` |
  | `occurred_at` | `timestamp` |
  | `principal` | `actor` |
  | `operation` | `action` |
  | `object` | `resource` |
  | `attrs` | `detail` |

  归一化后的记录走与 v1 完全相同的校验、脱敏、哈希与转发路径；
  `attrs` 里的敏感键同样会被脱敏。
- **不静默丢弃、不静默补全**（两代同一标准）：
  - 出现未声明字段（v0 或 v1）→ `unknown_field`，连同字段名返回；
  - 缺少必填字段 → `missing_field`（v0 的报错会指出老格式的字段名，
    如 `missing_field: principal (legacy v0 name for actor)`）；
  - 空字符串、类型不符、无法解析的 ISO-8601 时间、`detail`/`attrs`
    非对象、非 JSON 原生值 → `illegal_value`；
  - 完全不认识的版本号 → `unsupported_version`（当前支持 `[0, 1]`）；
  - 落盘行损坏 / 缺字段 / 含未知字段 → `corrupt_record`。
- **脱敏**：`detail` 内的敏感键（见配置）在**哈希之前**被替换为
  固定标记 `"__redacted__"`（嵌套对象与列表递归处理，支持
  `user.password` 这类带前缀键名）。因此：
  - 脱敏后的记录仍能正常通过完整性校验（哈希覆盖的是脱敏后的形态）；
  - 原始密钥**不会**出现在落盘文件中，也不会出现在任何对外返回中
    （有测试直接扫描磁盘字节与响应体确认）；
  - 非敏感字段原样保留。

敏感键默认可在 `audit/normalization.py` 的 `DEFAULT_SENSITIVE_KEYS`
中查看，可用环境变量 `AUDIT_SENSITIVE_KEYS="pin,cvn"` 追加。

## 4. 保留（清理）规则

- 超过 `AUDIT_RETENTION_DAYS`（默认 90 天）的记录可被清理，
  `POST /audit/prune` 触发。
- 只删除**连续前缀**：遇到第一条仍在保留窗口内的记录即停止，绝不
  在中间留洞，也绝不删除仍在窗口内的数据。
- **与转发进度配合**：启用转发时，清理会在同一把锁内读取转发游标
  （下游已确认的最大 seq）。`seq > cursor` 的记录**尚未交付下游，
  即使已过期也保留**，清理在遇到第一条未交付记录时即停止；已被
  下游确认的记录到期照常清理。转发未开启（无游标）或游标已追平时，
  清理行为与纯时间规则完全一致。游标只会单调前进，因此并发转发
  只会让清理决策偏保守（多留），绝不会误删未交付记录。返回体中的
  `forward_cursor` 与 `held_for_forward`（已过期但因未交付被保留的
  条数）使每次清理的判定依据可解释。
- 被删前缀的最后一条记录固化为**检查点**（`seq/id/record_hash`），
  剪枝后留存链以检查点为锚，依旧完整可校验。
- 剪枝与追加使用同一把锁（进程内 `threading.Lock` + 跨进程
  `fcntl.flock`），且保留集合取自锁内快照并以临时文件 +
  `os.replace` + 目录 `fsync` 原子落盘；剪枝进行中的新写入要么在
  重写前、要么在重写后进入，**不会被误删**。剪枝后首条新记录链接到
  检查点而非创世哈希，因此**不会被误判为篡改**。
- 剪枝完成后会立即自校验；若自校验失败会显式报错，而不是留下无法
  解释的链。

## 5. 下游转发、失败重试与恢复语义

通过 `AUDIT_FORWARD_ENABLED=1` 启用，`POST /audit/forward` 触发。

- **真实下发**：配置 `AUDIT_FORWARD_URL` 后，服务内置
  `HttpDownstream`，把每条记录以 JSON POST 到该地址；只有 2xx 响应
  才算交付成功，连接失败 / 超时（`AUDIT_FORWARD_TIMEOUT`，默认 5 秒）
  / 4xx / 5xx 都会进入重试。从接口触发即可真正下发积压记录。
  开关打开但未配置 URL 时，触发返回
  `{"ok": false, "enabled": true, "reason": "forward_url_not_configured"}`，
  明确可解释。测试或嵌入场景也可直接向 `AuditService` 注入自定义
  `Downstream` 实现。
- **游标（cursor）**：持久化已被下游确认的最大 seq，每次成功发送后
  fsync 落盘。重启后从 `cursor+1` 继续，实现**积压恢复**。
- **有界重试**：单条最多尝试 `AUDIT_FORWARD_MAX_ATTEMPTS`（默认 3）次；
  仍失败则在该条处**有序暂停**——不会跳过它去发后面的记录（避免乱序
  造成的缺口），游标停在最后成功位置。
- **幂等账本**：已确认的记录 id 追加记入 `forward.state.ids`，游标与
  账本共同保证重发不会导致下游重复接收；游标落后但 id 已确认时只推进
  游标而不重发。
- **并发发送**：转发器内部以锁串行化并发触发，多个 `POST
  /audit/forward` 同时到达也只会有一个发送序列，游标文件不会竞态。
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
| `AUDIT_FORWARD_URL` | （空） | 下游接收地址；配置后接口触发即真实 POST 下发 |
| `AUDIT_FORWARD_STATE` | `forward.state` | 游标文件名（位于数据目录） |
| `AUDIT_FORWARD_MAX_ATTEMPTS` | `3` | 单条最大尝试次数 |
| `AUDIT_FORWARD_TIMEOUT` | `5.0` | 单次 HTTP 下发超时（秒） |
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

# 老格式（v0）记录从同一入口追加，归一化后与 v1 同口径校验
curl -s -X POST localhost:8000/audit/records -H 'content-type: application/json' \
  -d '{"version":0,"event_id":"old-1","occurred_at":"2026-09-20T08:00:00",
       "principal":"legacy-user","operation":"export","object":"/reports",
       "attrs":{"rows":5,"token":"abc"}}'

# 脱离 HTTP 直接校验磁盘上的链（退出码 0=完整，2=检出篡改/异常）
uv run python main.py verify

# 人为篡改演示：编辑 data/audit.log 中某条记录的任意字段后再次校验，
# 将得到 hash_mismatch / chain_break / missing_record / ordering_error
# 等可区分结论
```

### 本地复现"接口触发真实转发"

```bash
# 1) 起一个本地下游（终端 A）：把收到的记录打印出来并返回 200
uv run python - <<'EOF'
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        print("downstream got:", body.decode()); self.send_response(200); self.end_headers()
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", 9000), H).serve_forever()
EOF

# 2) 打开开关并配置下游地址，启动服务（终端 B）
AUDIT_FORWARD_ENABLED=1 AUDIT_FORWARD_URL=http://127.0.0.1:9000/ingest \
  uv run python main.py serve

# 3) 追加几条记录后从接口触发转发（终端 C），下游终端即可看到按序到达的记录
curl -s -X POST localhost:8000/audit/records -H 'content-type: application/json' \
  -d '{"id":"e1","timestamp":"2026-09-26T10:00:00","actor":"a",
       "action":"login","resource":"/r","detail":{}}'
curl -s -X POST localhost:8000/audit/forward

# 4) 停掉下游再触发：返回 failures 且游标不动；恢复下游后再次触发，
#    积压记录不重、不丢、按序补发
```

### 本地复现"清理与转发进度配合"

```bash
# 保留期设短、记录时间写旧，转发先不开下游：
#   POST /audit/prune 会看到 pruned=0 且 held_for_forward>0（未交付不清）；
# 启动下游并 POST /audit/forward 追平后再次 prune：过期记录照常清理，
# 链依旧校验通过（检查点锚定）。
```

测试覆盖三类必需场景：并发追加（`tests/test_concurrent_append.py`）、
人为篡改（`tests/test_tamper_detection.py`）、转发失败
（`tests/test_forward_failure.py`），并另含脱敏/格式
（`tests/test_redaction.py`）、跨版本兼容
（`tests/test_version_compat.py`）、保留并发
（`tests/test_retention.py`）、保留×转发协调
（`tests/test_retention_forward.py`）、接口触发真实转发
（`tests/test_api_forward.py`）与 API 端到端（`tests/test_api.py`）。
