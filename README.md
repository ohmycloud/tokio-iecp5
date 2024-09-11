# iecp5

## TODO

- [ ] 实现控制命令超时等待
- [ ] 更好的错误返回

## 术语解释

1. DCO - Double Command Output（双点命令输出）
DCO 用于表示双点遥控命令。它允许控制具有两个稳定状态的设备，例如断路器（开/关）。

2. QOC - Qualifier of Command（命令限定词）
QOC 用于进一步定义命令的性质或执行方式。它可以包含诸如短脉冲/长脉冲、选择/执行等信息。

3. QOS - Qualifier of Set-point Command（设定点命令限定词）
QOS 用于设定点命令，提供关于如何执行设定点操作的附加信息。

4. QOI - Qualifier of Interrogation（总召唤限定词）
QOI用于定义总召唤命令的类型。总召唤是一种请求设备发送其所有当前数据的命令。QOI可以指定不同类型的总召唤,例如:

站总召唤
特定组的召唤
计数器总召唤

5. QCC - Qualifier of Counter Interrogation Command（计数器召唤命令限定词）
QCC用于计数器召唤命令,指定要读取的计数器类型和读取方式。它可以包含以下信息:

请求计数器的类型(如积分计数器、运行时间计数器等)
是否冻结计数器值
是否重置计数器


6. QRP - Qualifier of Reset Process Command（复位进程命令限定词）
QRP用于复位进程命令,指定要执行的复位类型。这可能包括:

特定设备或过程的复位
特定类型事件的复位
全系统复位

7. SIQ - Single-point Information with Quality descriptor（带品质描述词的单点信息）
SIQ 用于传输单个二进制状态信息(如开/关),同时包含了描述该信息质量的附加数据。品质描述词可能包括:

是否被封锁
是否被取代
是否为拓扑信息
是否有效


8. DIQ - Double-point Information with Quality descriptor（带品质描述词的双点信息）
DIQ 类似于SIQ,但用于表示具有两个稳定状态的设备信息。例如,断路器可能有以下状态:

中间态
确定开
确定关
不确定态
DIQ同样包含品质描述词。


9. QDS - Quality Descriptor（品质描述词）
QDS 是一个通用术语,指包含数据点品质信息的描述符。它可能包括:

溢出标志
封锁标志
取代标志
拓扑标志
有效性标志


10. BCR - Binary Counter Reading（二进制计数器读数）
BCR 用于传输计数器的当前值,通常用于电能计量等应用。它包括:

计数器值
序列号
溢出标志
调整标志
无效标志


11. SCD - Status and Change Detection（状态和变位检测）
SCD 用于传输设备的当前状态以及自上次报告以来是否发生了变化。它通常包含:

当前状态信息
变位检测信息
品质描述词

12. SCO（Single Command Output）用于发送单点控制命令，通常用于控制只有两个状态的设备。具体来说：

用途：SCO 主要用于控制开关设备，如断路器、隔离开关等。
状态：它通常表示两种状态，例如：

0 = 关闭 (OFF)
1 = 打开 (ON)


结构：SCO 通常包含以下信息：

命令值（0或1）
选择/执行标志
限定词（Qualifier），提供额外的控制信息

应用：在SCADA（监控与数据采集）系统中，SCO用于远程控制设备的开关状态。
与DCO的区别：SCO用于单点控制，而DCO（Double Command Output）用于双点控制，后者提供更多的状态信息。

这些限定词(Qualifiers)在IEC104协议中扮演着重要角色,它们提供了额外的上下文和精确性,确保控制中心和远程终端单元(RTU)之间的通信明确无误。这对于电力系统、工业控制和其他需要高度可靠性的应用至关重要。