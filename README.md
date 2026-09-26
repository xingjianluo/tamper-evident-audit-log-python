# Tamper-Evident Audit Log

在现有 FastAPI 服务（`main.py`）中内嵌一条本地可验证的防篡改审计链路。
实现位于 `audit/` 包，测试位于 `tests/`，不另起并行实现。

## 架构

```
main.py            FastAPI 入口：/audit/records、/audit/verify、/audit/retention/run、/audit/forward/run
audit/config.py    AuditConfig：数据目录、保留天数、敏感字段、下游地址、批量与重试参数
audit/normalize.py 记录归一化（v1/v2 -> 统一结构）与敏感字段脱敏
audit/chain.py     追加式哈希链存储（chain.jsonl + anchor.json），并发安全
audit/retention.py 保留策略：过期前缀清除 + 锚点续验
audit/forwarder.py 游标式下游转发：重试、积压恢复、不丢不重
audit/models.py    AuditRecord / VerificationResult / FailureReason
```

数据文件（默认 `data/`，由 `AuditConfig.data_dir` 配置）：

- `chain.jsonl`：每行一条审计记录 `{seq, ts, actor, action, payload, prev_hash, hash}`
- `anchor.json`：保留策略清除过期记录后留下的校验锚点 `{seq, hash}`
- `forward_cursor.json`：下游转发已确认的游标 `{seq}`

## 完整性判定语义

每条记录通过哈希链与全部历史关联：

```
prev_hash(第一条) = "GENESIS"
hash(i) = sha256( prev_hash(i) + "\n" + canonical_json({ts, actor, action, payload}) )
```

`canonical_json` 为固定键序、紧凑分隔符的 JSON。`GET /audit/verify`
（或 `AuditChain.verify()`）从锚点（无锚点则从 GENESIS）重放整条链，
返回 `{ok, checked, reason, detail, seq}`。失败原因**可区分**：

| reason          | 含义                     | 判定依据                                             |
|-----------------|--------------------------|------------------------------------------------------|
| `ok`            | 链完整                   | 全部记录逐一重算通过                                 |
| `schema_error`  | 记录无法解析             | 行不是合法记录（如被写入垃圾数据）                   |
| `hash_mismatch` | 记录内容被修改           | 重算哈希与存储哈希不一致                             |
| `seq_missing`   | 记录被删除               | 期望序号在后续行中不存在                             |
| `seq_reordered` | 记录被重排               | 期望序号缺失但出现在后续行中                         |
| `seq_duplicate` | 记录被复制/重放          | 序号小于期望序号（同一序号再次出现）                 |

并发追加由单把可重入锁串行化：序号取自加锁后的文件尾部，
因此并发写入不会产生重复或跳号，也不会写出断裂的链接。

## 脱敏与记录格式兼容

- 接受两个输入版本并归一化为 `{ts, actor, action, payload}`：
  - v1（隐式）：`{actor, action, payload, ts?}`（`ts` 缺省时由服务端补当前时间）
  - v2：`{version: "v2", timestamp, actor, action, payload}`
- **不静默丢弃、不静默补全**：未知字段、缺失必填字段、非法取值
  （空字符串、负数时间戳、非 JSON 类型等）一律以 `SchemaError` 拒绝，
  HTTP 层返回 `422` 并带机器可读的 `kind`
  （`unknown_field` / `missing_field` / `illegal_value`）。
- 脱敏发生在**哈希计算与落盘之前**：`AuditConfig.sensitive_fields`
  中列出的键（任意嵌套层级按键名匹配）被替换为固定标记
  `***REDACTED***`。因此原始敏感值不会出现在 `chain.jsonl`、
  `GET /audit/records` 或下游转发内容中，且脱敏后的记录照常通过完整性校验。

## 保留策略与下游转发

### 保留（`POST /audit/retention/run`）

- 只清除**连续过期前缀**（`ts < now - retention_days`），清除后写入
  `anchor.json = {seq, hash}`（最后被清除记录的序号与哈希），
  校验从锚点继续——合法清理**不会**被误判为篡改，锚点之后的任何
  修改/删除/重排仍会被检测。
- **不丢失**：`seq > safe_seq` 的记录（`safe_seq` 为下游转发已确认游标）
  即使已过期也保留，直到转发成功。
- **不误删**：清理全程持有链锁，清理进行中的新写入与文件重写串行化，
  新记录不会被清理过程删除。

### 转发（`POST /audit/forward/run`）

- 基于持久化游标的 ack 语义：一批记录只有在下游 `send` 成功返回后，
  游标才原子地（tmp + fsync + rename）前移——**不丢失**。
- 游标先落盘再发下一批，每条记录对每个游标位置至多投递一次——
  **不重复**（`seq` 同时是下游幂等键）。
- 失败重试：每批最多 `forward_max_retries` 次；仍失败则抛出
  `ForwardError`（HTTP 502，带 `delivered`/`pending`），积压保留，
  下游恢复后再次调用即从游标处按序排空——**积压恢复**。
- 未配置 `forward_url` 时返回 503，积压保留。

## 本地验证方法

```bash
uv sync                 # 安装依赖（含 dev 组 pytest/httpx）
uv run pytest           # 运行全部测试（-s 已配置，日志直接打印）
uv run pytest -v        # 逐条查看用例日志
```

每个测试用例日志打印三段：**输入(input) / 判定依据(basis) / 结论(conclusion)**，
覆盖三类核心场景：

- `tests/test_concurrent_append.py`：32 线程 × 25 条并发追加，
  序号 1..800 连续唯一、链完整、敏感值不落盘；
- `tests/test_tamper_detection.py`：修改/删除/重排/复制/垃圾行五类篡改，
  各自映射到可区分的失败原因；
- `tests/test_forward_failure.py`：下游宕机重试、积压保留、恢复后按序
  排空且不重复、断点续传；
- 另有 `test_normalize.py`（版本兼容与严格校验）、`test_retention.py`
  （锚点续验、积压保护、清理后仍可检测篡改）、`test_api.py`（HTTP 入口
  正常/异常路径）。

启动服务并手工验证：

```bash
uv run python main.py   # http://127.0.0.1:8000

curl -X POST localhost:8000/audit/records -H 'Content-Type: application/json' \
     -d '{"actor":"alice","action":"login","payload":{"token":"t0psecret","ip":"10.0.0.1"}}'
curl localhost:8000/audit/records   # token 已脱敏为 ***REDACTED***
curl localhost:8000/audit/verify    # {"ok":true,"reason":"ok",...}
# 手工篡改 data/chain.jsonl 任意一行后再次 verify，可看到对应 reason
```
