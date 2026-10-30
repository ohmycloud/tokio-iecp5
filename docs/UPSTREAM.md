# 上游同步记录

## 对齐基准

- 上游：https://github.com/nicedvx/tokio-iecp5
- 对齐提交：`77ed90917891fa1a1f2b61290de49ad19a8bd672`（`feat: parse_104 tool`）
- 本地起点：`6ce1966`（`modify comment`）

本次按文件差异逐项对照，而不是用上游目录覆盖本地。保留了中文协议说明、已经移出的独立测试、
以及原来比上游更安全的 `Result` 错误传播。上游主要增量是编码修复、公开一个解码方法和解析工具，
并不包含现成 UI，也未完成其 README 中的通用命令确认超时 TODO。

| 上游功能差异 | 本项目处理 |
|---|---|
| SCO/DCO 位序 | 按 bit-struct 高位到低位声明：S/E 在 bit 7，状态在低位；同步修改构造器 |
| QOC/QOS 位序 | S/E 在高位，QU/QL 在低位；修正设定点构造器参数顺序 |
| COT 11/12/13 | 修正为 ReturnInfoRemote / ReturnInfoLocal / FileTransfer |
| 初始化结束解析 | 公开 `Asdu::get_end_of_initialization` |
| ASDU payload 切片 | 使用共享 `Bytes::slice`，保留现有错误返回，不引入上游的 `unwrap` |
| `parse_104` 示例 | 补入全部上游解析分支；扩展为多帧解析、严格输入检查及截断报错 |
| 编解码/遥信/遥测测试 | 保留独立 `tests/` 覆盖，不重复嵌回模块 |
| 注释/空行变化 | 不删除本项目的中文说明，不进行无意义的反向同步 |

## 上游之外的可靠性修复

- `Client::start()` 对连接中、重连中、已连接状态均幂等，防止重复连接任务。
- `Client::stop(&self)` 取消连接/重连任务、关闭 TCP、清除状态；`Drop` 也会取消任务。
- `auto_reconnect=false` 在连接断开后不再重连；连接失败保留底层 I/O 错误。
- I 帧序列号以 **32768** 为模；ACK=0 的回绕不再发生减法下溢。
- 收不到 ACK 时关闭连接，不再通过递增本地 ACK 假装收到确认。
- `Server::serve_until()` 提供可取消服务，并管理/清理全部已接受会话；原有 `serve()` 保留。
- 服务端在分发前推进接收序列号：拒绝命令的路径同样消费该 I 帧，避免后续序列失步。
- 编解码器校验 I/S/U 控制字段和长度，拒绝缺失/损坏 ASDU，不再静默吞错。
- 编码失败不先写入半个帧；过大的 ASDU 交给编码器报错，避免构帧算术 panic。
- NSH 控制台业务层增加 3 秒命令确认超时、否定响应检查及 10 秒选择有效期。

## 兼容性注意

1. **线缆编码行为变化是修复**：依赖旧错误位序的设备适配代码需要同步调整。
2. bit-struct 自动生成的 `ObjectSCO::new`、`ObjectDCO::new`、`ObjectQOC::new`、
   `ObjectQOS::new` 的参数顺序与上游一致，均从最高有效位开始。
   高层 `SingleCommandInfo::new(addr, value, select)` / `DoubleCommandInfo::new(...)` 签名不变。
3. **S/E=1 为选择，S/E=0 为执行**；README 原有相反说明已修正。
4. 严格解码会拒绝以前被容忍的非法帧，例如 `68 04 02 00 03 00`：
   它没有 ASDU，而且 N(R) 的保留位为 1。原 APCI 测试已换成合法 I 帧。
5. 通用协议库的发送 API 仍然是异步入队，不自动等待业务确认。
   控制台的确认事务不是所有 `Client<S>` 调用者共享的新行为。
6. HTTP/UI 只在 `console` feature 下编译，不强制库使用者依赖 NSH 或 HTTP 服务。

## 验证入口

- `tests/test_protocol_regressions.rs`：线上字节、ACK 回绕、分片/粘包、非法帧、重复启动、停止重连。
- `src/console/tests.rs`：真实 TCP 主从联调、六类点表、选择不执行、执行反馈、过期/跨连接选择、确认超时。
- `tests/test_console_http.rs`：HTTP 认证、输入校验、解析入口及本地 CORS 边界。
- `ui/Studio.test.tsx`：NSH 无网络启动、鉴权、过滤、连接/激活/召唤、执行锁、窄屏导航。
- `tests/ui/workflow.test.tsx`：独立的原生/Web 实机 UI 联调，不混入默认的 stub 测试。
