# tamper-evident-audit-log (Python bootstrap)

在现有 FastAPI 服务内实现的本地可验证防篡改审计链路：哈希链追加、并发安全
序号、敏感字段脱敏、保留期剪枝（与转发进度配合）、跨版本（v0/v1）归一化入链、
下游转发重试与积压恢复（可配置真实 HTTP 下游，接口触发即下发）。

- 设计、判定语义与本地验证方法：[docs/AUDIT.md](docs/AUDIT.md)
- 运行测试（日志含输入 / 判定依据 / 结论）：`uv run pytest -s`
- 启动服务：`uv run python main.py serve`
- 本地校验审计链：`uv run python main.py verify`（退出码 0 完整，2 异常）
