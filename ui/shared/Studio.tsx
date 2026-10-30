import { mount, signal, Scroll, Text, View, windowSize } from "nsh";
import { Button, Input } from "nsh/base";
import { createStore, pointValue, typeLabel, type Kind, type Point, type Role } from "./store";
import { AppMark, Icon, type IconName } from "./Icons";

const c = { page: "#F3F4F2", paper: "#FFFFFF", ink: "#172323", muted: "#718080", line: "#E2E7E4", accent: "#D75732", soft: "#FCF0E9", green: "#23725C", greenSoft: "#EAF5EF", night: "#142828", faint: "#9EB0AB" };
const mono = "monospace";
const row = { flexDirection: "row", alignItems: "center" } as const;
const panel = { backgroundColor: c.paper, borderWidth: 1, borderColor: c.line, borderRadius: 14, padding: 22, gap: 18 } as const;
const caption = { fontSize: 11, fontWeight: "600", color: c.muted, letterSpacing: 1.2 } as const;
type Store = ReturnType<typeof createStore>;

function Action(props: { label: string; onPress: () => void; primary?: boolean; danger?: boolean; disabled?: boolean; id?: string; icon?: IconName }) {
  return <Button testID={props.id} accessibilityLabel={props.label} onPress={props.onPress} disabled={props.disabled}
    activeStyle={{ opacity: 0.7 }} disabledStyle={{ opacity: 0.4 }}
    style={{ ...row, gap: 7, justifyContent: "center", minHeight: 38, paddingHorizontal: 15, borderRadius: 7, borderWidth: 1, borderColor: props.primary ? c.accent : c.line, backgroundColor: props.primary ? c.accent : c.paper }}>
    <If when={!!props.icon}><Icon name={props.icon ?? "connect"} size={15} color={props.primary ? "#FFFFFF" : props.danger ? c.accent : c.ink} /></If>
    <Text style={{ fontSize: 12, fontWeight: "600", color: props.primary ? "#FFFFFF" : props.danger ? c.accent : c.ink }}>{props.label}</Text>
  </Button>;
}
function Field(props: { label: string; value: string; onChange: (s: string) => void; masked?: boolean; id?: string; width?: number }) {
  return <View style={{ gap: 7, flex: props.width ? undefined : 1, width: props.width, minWidth: props.width ?? 100 }}>
    <Text style={caption}>{props.label}</Text>
    <Input testID={props.id} value={props.value} onChange={value => props.onChange(value)} masked={props.masked} autoCapitalize="none" autoCorrect={false}
      style={{ height: 38, paddingHorizontal: 11, borderRadius: 6, borderWidth: 1, borderColor: c.line, backgroundColor: "#F8FAF8", color: c.ink, fontSize: 12, fontFamily: mono }} />
  </View>;
}
function Tag(props: { label: string; active?: boolean }) {
  return <View style={{ ...row, gap: 6, paddingHorizontal: 9, paddingVertical: 5, borderRadius: 5, backgroundColor: props.active ? c.greenSoft : "#EEF1EE" }}>
    <View style={{ width: 5, height: 5, borderRadius: 3, backgroundColor: props.active ? c.green : c.muted }} />
    <Text style={{ fontSize: 10, fontWeight: "600", color: props.active ? c.green : c.muted }}>{props.label}</Text>
  </View>;
}
function SectionTitle(props: { number: string; title: string; detail: string }) {
  return <View style={{ ...row, gap: 12 }}>
    <Text style={{ color: c.accent, fontSize: 11, fontFamily: mono }}>{props.number}</Text>
    <Text style={{ fontSize: 16, fontWeight: "600", color: c.ink, flex: 1 }}>{props.title}</Text>
    <Text style={{ fontSize: 10, color: c.muted, fontFamily: mono }}>{props.detail}</Text>
  </View>;
}
function Metric(props: { label: string; value: string; detail: string; accent?: boolean }) {
  return <View style={{ ...panel, flex: 1, minWidth: 130, padding: 18, gap: 10 }}>
    <Text style={caption}>{props.label}</Text>
    <Text style={{ fontFamily: mono, fontSize: 29, color: props.accent ? c.accent : c.ink, fontWeight: "500" }}>{props.value}</Text>
    <Text style={{ fontSize: 10, color: c.muted }}>{props.detail}</Text>
  </View>;
}

function Connection(props: { store: Store; role: Role }) {
  const s = props.store;
  const address = signal("127.0.0.1:2404");
  const ca = signal("1");
  const role = () => props.role;
  const running = () => role() === "server" ? !!s.data()?.server_running : !!s.data()?.connected;
  function connect() {
    const common_addr = Number(ca());
    if (!Number.isInteger(common_addr) || common_addr < 1 || common_addr > 65534) { s.failed.set(true); s.message.set("公共地址必须为 1..65534 的整数"); return; }
    void s.act(role() === "server" ? "server_start" : "client_connect", { address: address(), common_addr });
  }
  return <View style={panel}>
    <SectionTitle number="01" title={role() === "server" ? "站点监听" : "连接配置"} detail="IEC 60870-5-104 / TCP" />
    <View style={{ ...row, gap: 12, flexWrap: "wrap", alignItems: "flex-end" }}>
      <Field label={role() === "server" ? "LISTEN ADDRESS" : "REMOTE ADDRESS"} value={address()} onChange={v => address.set(v)} id="address" />
      <Field width={110} label="COMMON ADDR" value={ca()} onChange={v => ca.set(v)} id="common-address" />
      <Action label={running() ? (role() === "server" ? "停止监听" : "断开连接") : (role() === "server" ? "启动监听" : "连接站点")}
        icon={running() ? "disconnect" : role() === "server" ? "server" : "connect"}
        primary={!running()} danger={running()} disabled={!s.online() || s.busy()}
        onPress={() => running() ? void s.act(role() === "server" ? "server_stop" : "client_disconnect") : connect()} />
    </View>
    <View style={{ height: 1, backgroundColor: c.line }} />
    <View style={{ ...row, gap: 8, flexWrap: "wrap" }}>
      <Tag label={running() ? (role() === "server" ? "LISTENING" : "TCP CONNECTED") : "OFFLINE"} active={running() && s.online()} />
      <If when={role() === "client"}>
        <Action icon="play" label="STARTDT" onPress={() => void s.act("start_dt")} disabled={!s.online() || !running() || !!s.data()?.active || s.busy()} />
        <Action icon="stop" label="STOPDT" onPress={() => void s.act("stop_dt")} disabled={!s.online() || !s.data()?.active || s.busy()} />
        <View style={{ flex: 1 }} />
        <Action icon="scan" label="总召唤" onPress={() => void s.act("interrogation")} disabled={!s.online() || !s.data()?.active || s.busy()} />
        <Action icon="counter" label="计数量召唤" onPress={() => void s.act("counter_interrogation")} disabled={!s.online() || !s.data()?.active || s.busy()} />
      </If>
      <If when={role() === "server"}><Text style={{ fontSize: 11, color: c.muted }}>模拟站点仅监听本机。启动后，在客户端连接同一地址。</Text></If>
    </View>
  </View>;
}

function PointTable(props: { store: Store; role: Role; onSelect: (p: Point) => void }) {
  const search = signal("");
  const filter = signal("all");
  const points = () => (props.role === "server" ? props.store.data()?.station : props.store.data()?.received) ?? [];
  const visible = () => points().filter(p => (filter() === "all" || (filter() === "digital" ? p.kind === "single" || p.kind === "double" : p.kind !== "single" && p.kind !== "double")) && `${p.ioa} ${p.name} ${typeLabel[p.kind]}`.toLowerCase().includes(search().toLowerCase()));
  const compact = () => windowSize().width < 850;
  return <View style={{ ...panel, padding: 0, overflow: "hidden" }}>
    <View style={{ padding: 22, gap: 18 }}>
      <SectionTitle number="02" title={props.role === "server" ? "模拟点表" : "接收点表"} detail={`${visible().length} POINTS`} />
      <View style={{ ...row, gap: 12, flexWrap: "wrap" }}>
        <View style={{ ...row, gap: 4, flex: 1 }}>
          <Each of={[{ id: "all", label: "全部" }, { id: "digital", label: "遥信" }, { id: "analog", label: "遥测 / 累计" }]}>{item =>
            <Button onPress={() => filter.set(item().id)} style={{ paddingHorizontal: 12, paddingVertical: 7, borderRadius: 5, backgroundColor: filter() === item().id ? c.ink : "transparent" }}>
              <Text style={{ fontSize: 11, color: filter() === item().id ? "#FFFFFF" : c.muted }}>{item().label}</Text>
            </Button>
          }</Each>
        </View>
        <Input testID="point-search" value={search()} onChange={value => search.set(value)} placeholder="搜索点号 / 名称"
          style={{ width: 190, height: 32, fontSize: 11, color: c.ink, borderBottomWidth: 1, borderBottomColor: c.line, paddingHorizontal: 7 }} />
      </View>
    </View>
    <View style={{ ...row, backgroundColor: "#F8FAF8", paddingHorizontal: 22, paddingVertical: 11, gap: 12, borderTopWidth: 1, borderTopColor: c.line }}>
      <Text style={{ ...caption, width: 55 }}>IOA</Text><Text style={{ ...caption, flex: 1 }}>信息点 / TYPE</Text>
      <Text style={{ ...caption, width: compact() ? 105 : 140 }}>VALUE</Text>
      <If when={!compact()}><Text style={{ ...caption, width: 110 }}>UPDATED / UTC</Text></If>
    </View>
    <Each of={visible()} key={p => p.ioa}>{point =>
      <Button onPress={() => props.onSelect(point())} accessibilityLabel={`选择点 ${point().ioa}`} activeStyle={{ backgroundColor: c.soft }}
        style={{ ...row, minHeight: 62, paddingHorizontal: 22, gap: 12, borderTopWidth: 1, borderTopColor: "#EFF2EF" }}>
        <Text style={{ width: 55, fontFamily: mono, fontSize: 12, color: c.muted }}>{String(point().ioa).padStart(4, "0")}</Text>
        <View style={{ flex: 1, gap: 5 }}><Text style={{ fontSize: 12, color: c.ink }}>{point().name}</Text><Text style={{ fontSize: 9, fontFamily: mono, color: c.muted }}>{typeLabel[point().kind]}</Text></View>
        <View style={{ width: compact() ? 105 : 140, gap: 5 }}><Text style={{ fontSize: 12, fontFamily: mono, color: point().quality === 0 ? c.green : c.accent }}>{pointValue(point())}</Text><Text style={{ fontSize: 9, color: c.muted }}>{point().quality === 0 ? "● GOOD" : `QUALITY 0x${point().quality.toString(16)}`}</Text></View>
        <If when={!compact()}><Text style={{ width: 110, fontFamily: mono, fontSize: 10, color: c.muted }}>{point().updated_at}</Text></If>
      </Button>
    }</Each>
    <If when={visible().length === 0}><View style={{ padding: 36, alignItems: "center", gap: 10 }}>
      <Text style={{ color: c.muted, fontSize: 13 }}>{points().length ? "没有匹配的信息点" : "暂无接收数据"}</Text>
      <Text style={{ color: c.muted, fontSize: 11 }}>连接 → STARTDT → 总召唤 / 计数量召唤</Text>
    </View></If>
    <View style={{ padding: 15, borderTopWidth: 1, borderTopColor: c.line }}><Text style={{ fontSize: 10, color: c.muted }}>{props.role === "server" ? "点击信息点，再载入编辑 · 模拟点表仅驻留内存" : "点击信息点，再载入操作面板 · 接收值来自真实 IEC104 会话"}</Text></View>
  </View>;
}

function Command(props: { store: Store; role: Role; point: Point | null }) {
  const s = props.store;
  const ioa = signal("100");
  const kind = signal<Kind>("single");
  const value = signal("0");
  // Use the current selected row as an explicit preset, never send it automatically.
  function preset() { const p = props.point; if (p) { ioa.set(String(p.ioa)); kind.set(p.kind); value.set(String(p.value)); s.selected.set(null); } }
  function changed() { s.selected.set(null); }
  const allowed = () => !s.busy() && s.online() && (props.role === "server" || !!s.data()?.active);
  const params = () => ({ ioa: Number(ioa()), kind: kind(), value: Number(value()) });
  const remains = () => Math.max(0, Math.ceil(((s.selected()?.until ?? 0) - s.clock()) / 1000));
  const canExecute = () => remains() > 0 && s.selected()?.ioa === Number(ioa()) && s.selected()?.kind === kind() && s.selected()?.value === Number(value());
  async function select() {
    const p = params();
    if (!Number.isInteger(p.ioa) || !value().trim() || !Number.isFinite(p.value)) { s.failed.set(true); s.message.set("请输入有效点号与数值"); return; }
    const result = await s.act("select", p);
    if (result) s.selected.set({ ...p, until: Date.now() + 10_000 });
  }
  return <View style={panel}>
    <SectionTitle number="03" title={props.role === "server" ? "编辑模拟点" : "遥控工作台"} detail="MANUAL ONLY" />
    <Text style={{ fontSize: 11, color: c.muted, lineHeight: 18 }}>{props.role === "server" ? "修改模拟站点内存值。客户端重新召唤后可见；不会自动向所有连接广播。" : "先选择，等待对端确认，再执行。仅开放单点与双点遥控，不自动向真实设备发送操作。"}</Text>
    <If when={!!props.point}><Action icon="load" label={`载入点 ${props.point?.ioa ?? ""}`} onPress={preset} /></If>
    <View style={{ ...row, gap: 10 }}><Field label="IOA / 点号" value={ioa()} onChange={v => { ioa.set(v); changed(); }} /><Field label="VALUE / 数值" value={value()} onChange={v => { value.set(v); changed(); }} /></View>
    <If when={props.role === "client"}><View style={{ ...row, gap: 8 }}>
      <Action label="单点 · 0 / 1" primary={kind() === "single"} onPress={() => { kind.set("single"); changed(); }} />
      <Action label="双点 · 1 / 2" primary={kind() === "double"} onPress={() => { kind.set("double"); changed(); }} />
    </View></If>
    <If when={props.role === "client"}>
      <Text style={{ fontFamily: mono, fontSize: 10, color: c.accent }}>{canExecute() ? `SELECT CONFIRMED · ${remains()}s` : "EXECUTE LOCKED · 等待选择确认"}</Text>
      <View style={{ ...row, gap: 8 }}><Action icon="select" label="1. 选择" onPress={() => void select()} disabled={!allowed() || (kind() !== "single" && kind() !== "double")} />
        <Action icon="execute" label="2. 确认执行" primary onPress={() => { const p = params(); s.selected.set(null); void s.act("execute", p); }} disabled={!allowed() || !canExecute()} /></View>
    </If>
    <If when={props.role === "server"}><Action icon="save" label="保存模拟点" primary disabled={!allowed() || !value().trim()} onPress={() => void s.act("update_point", { ioa: Number(ioa()), value: Number(value()) })} /></If>
    <View style={{ padding: 12, backgroundColor: c.soft, borderRadius: 7 }}><Text style={{ fontSize: 10, color: "#9A553C", lineHeight: 17 }}>安全提示：本工具用于开发联调。接入生产设备前，请确认操作权限、点号映射和现场安全条件。</Text></View>
  </View>;
}

function Traffic(props: { store: Store; role: Role; preview?: boolean }) {
  const hex = signal(false);
  const events = () => (props.store.data()?.events ?? []).filter(e => e.side === props.role || e.side === "console").slice(0, props.preview ? 6 : 300);
  return <View style={{ ...panel, backgroundColor: c.night, borderColor: c.night, gap: 17 }}>
    <View style={{ ...row, gap: 12 }}><Text style={{ ...caption, color: c.faint }}>COMMUNICATION JOURNAL</Text><View style={{ flex: 1 }} />
      <Button onPress={() => hex.set(!hex())}><Text style={{ fontFamily: mono, color: "#E7A37D", fontSize: 10 }}>{hex() ? "HEX ON" : "HEX OFF"}</Text></Button>
      <Button disabled={!props.store.online() || props.store.busy()} onPress={() => void props.store.act("clear_logs")}><Text style={{ fontSize: 10, color: c.faint }}>清空</Text></Button>
    </View>
    <Each of={events()} key={e => e.id}>{event => <View style={{ gap: 7, paddingVertical: 8, borderTopWidth: 1, borderTopColor: "#2B3C39" }}>
      <View style={{ ...row, gap: 10, alignItems: "flex-start" }}><Text style={{ width: 82, fontFamily: mono, fontSize: 10, color: c.faint }}>{event().time}</Text><Text style={{ width: 28, fontFamily: mono, fontSize: 10, color: event().direction === "ERR" ? "#FF927F" : "#8FD7B6" }}>{event().direction}</Text><Text style={{ flex: 1, fontFamily: mono, fontSize: 10, color: "#E0EAE4", lineHeight: 16 }}>{event().message}</Text></View>
      <If when={hex() && !!event().hex}><Text style={{ fontFamily: mono, fontSize: 9, color: "#8CA79C", lineHeight: 16 }}>{event().hex}</Text></If>
    </View>}</Each>
    <If when={events().length === 0}><Text style={{ fontFamily: mono, fontSize: 11, color: c.faint }}>等待通信事件 / NO EVENTS YET</Text></If>
    <Text style={{ fontSize: 9, color: c.faint }}>最近 300 条 · HEX 为 ASDU 字节，非 TCP 抓包 · TX 表示发送队列，命令成功以对端确认为准</Text>
  </View>;
}
function Inspector(props: { store: Store }) {
  const input = signal("68 04 07 00 00 00");
  const output = signal("支持 I / S / U 帧与多个粘连帧；不完整报文会明确报错。");
  async function parse() { const result = await props.store.act("parse", { hex: input() }); if (result) output.set(result.description); }
  return <View style={panel}><SectionTitle number="04" title="报文解析器" detail="PARSE_104" />
    <Input testID="hex-input" multiline value={input()} onChange={value => input.set(value)} style={{ height: 110, fontFamily: mono, fontSize: 13, color: c.ink, borderWidth: 1, borderColor: c.line, borderRadius: 7, padding: 14 }} />
    <Action icon="inspect" label="解析报文" primary onPress={() => void parse()} disabled={!props.store.online() || props.store.busy()} />
    <Text style={{ fontFamily: mono, fontSize: 11, color: c.muted, lineHeight: 19 }}>{output()}</Text>
  </View>;
}

function Studio(props: { initialRole: Role }) {
  const s = createStore();
  const role = signal<Role>(props.initialRole);
  const tab = signal("overview");
  const focus = signal<Point | null>(null);
  const settings = signal(true);
  const narrow = () => windowSize().width < 1000;
  const mobile = () => windowSize().width < 700;
  const nav: { id: string; label: string; icon: IconName }[] = [{ id: "overview", label: "工作概览", icon: "overview" }, { id: "points", label: "信息点表", icon: "points" }, { id: "traffic", label: "通信日志", icon: "traffic" }, { id: "inspect", label: "报文解析", icon: "inspect" }];
  const heading = () => nav.find(t => t.id === tab())?.label ?? "工作概览";
  const active = () => s.online() && (role() === "server" ? !!s.data()?.server_running : !!s.data()?.active);
  function changeRole(next: Role) { role.set(next); focus.set(null); s.selected.set(null); }
  return <View style={{ flex: 1, flexDirection: mobile() ? "column" : "row", backgroundColor: c.page }}>
    <View style={{ width: mobile() ? "100%" : 216, backgroundColor: c.night, padding: mobile() ? 14 : 26, gap: mobile() ? 16 : 34 }}>
      <View style={{ ...row, gap: 8 }}><AppMark role={role()} size={44} /><View style={{ gap: 5 }}><Text style={{ fontSize: 15, color: "#F5F7EF", fontWeight: "600" }}>IEC104 Studio</Text><Text testID="workspace-role" style={{ fontSize: 8, letterSpacing: 1.3, color: c.faint }}>{role() === "server" ? "STATION / 服务端" : "MASTER / 客户端"}</Text></View></View>
      <View style={{ gap: 8 }}><If when={!mobile()}><Text style={{ ...caption, fontSize: 9, color: "#7F9890" }}>WORKSPACE</Text></If>
        <View style={{ flexDirection: mobile() ? "row" : "column", gap: 6 }}><Each of={[{ id: "server" as Role, label: "服务端 / Station" }, { id: "client" as Role, label: "客户端 / Master" }]}>{item =>
          <Button onPress={() => changeRole(item().id)} style={{ ...row, gap: 9, padding: 11, borderRadius: 7, backgroundColor: role() === item().id ? "#2B4038" : "transparent", borderWidth: 1, borderColor: role() === item().id ? "#44624D" : "#283B35" }}><Icon name={item().id} size={17} color={role() === item().id ? "#E3EFD9" : c.faint} /><Text style={{ fontSize: 11, color: role() === item().id ? "#E3EFD9" : c.faint }}>{item().label}</Text></Button>
        }</Each></View>
      </View>
      <View style={{ flexDirection: mobile() ? "row" : "column", gap: 7, flexWrap: "wrap" }}><Each of={nav}>{item =>
        <Button onPress={() => tab.set(item().id)} style={{ ...row, gap: 13, borderRadius: 6, paddingVertical: 12, paddingHorizontal: mobile() ? 8 : 11, backgroundColor: tab() === item().id ? "#253B33" : "transparent" }}><Icon name={item().icon} size={17} color={tab() === item().id ? "#E3AA80" : "#799589"} /><Text style={{ fontSize: 12, color: tab() === item().id ? "#F1F5E9" : c.faint }}>{item().label}</Text></Button>
      }</Each></View>
      <If when={!mobile()}><View style={{ flex: 1 }} /><View style={{ gap: 12, paddingTop: 18, borderTopWidth: 1, borderTopColor: "#304139" }}><Text style={{ color: "#C1CFC3", fontFamily: mono, fontSize: 10 }}>IEC 60870-5-104</Text><Text style={{ color: "#789487", fontSize: 10, lineHeight: 17 }}>Rust / Tokio 协议引擎{ "\n" }Native Shell 原生界面</Text><Text style={{ color: "#6F8D80", fontSize: 9 }}>LOCAL LAB · v0.1</Text></View></If>
    </View>
    <Scroll style={{ flex: 1 }}><View style={{ padding: mobile() ? 16 : 32, gap: 22, maxWidth: 1600, width: "100%", alignSelf: "center" }}>
      <View style={{ ...row, gap: 12 }}><View style={{ flex: 1, gap: 10 }}><Text style={{ ...caption, fontSize: 9 }}>WORKSPACE / {role() === "server" ? "STATION" : "MASTER"} / {tab().toUpperCase()}</Text><Text style={{ fontSize: 29, fontWeight: "600", letterSpacing: -1, color: c.ink }}>{heading()}</Text><Text style={{ fontSize: 11, color: c.muted }}>{role() === "server" ? "构建你的测试站点，让每一次协议交互都清晰可见。" : "连接、观测与验证，一处完成 IEC104 协议联调。"}</Text></View><Button accessibilityLabel="控制服务设置" onPress={() => settings.set(!settings())} style={{ ...row, gap: 8 }}><Icon name="settings" size={17} color={c.muted} /><Tag label={s.online() ? "API ONLINE" : "连接控制服务"} active={s.online()} /></Button></View>
      <If when={settings()}><View style={panel}><SectionTitle number="00" title="本地控制服务" detail="TOKEN PROTECTED" /><Text style={{ fontSize: 11, color: c.muted }}>先运行 cargo run --features console --bin iec104-console，再粘贴终端显示的 Token。</Text><View style={{ ...row, gap: 12, flexWrap: "wrap", alignItems: "flex-end" }}><Field id="api-endpoint" label="API ENDPOINT" value={s.endpoint()} onChange={v => { s.endpoint.set(v); s.credentialsChanged(); }} /><Field label="API TOKEN" value={s.token()} onChange={v => { s.token.set(v); s.credentialsChanged(); }} masked id="api-token" /><Action icon="shield" id="authorize" label="连接控制服务" primary disabled={s.busy() || !s.token()} onPress={() => void s.refresh(true)} /></View></View></If>
      <View role="alert" style={{ ...row, padding: 12, gap: 10, backgroundColor: s.failed() ? c.soft : "#E8EEEA", borderRadius: 7 }}><Text style={{ fontFamily: mono, fontSize: 10, color: s.failed() ? c.accent : c.green }}>{s.busy() ? "WAIT" : s.failed() ? "ERR" : "INFO"}</Text><Text style={{ flex: 1, fontSize: 11, color: s.failed() ? "#9A553C" : "#466354", lineHeight: 17 }}>{s.message()}</Text></View>
      <If when={tab() === "overview"}>
        <View style={{ ...row, gap: 12, flexWrap: "wrap" }}><Metric label="SESSION STATUS" value={active() ? "ONLINE" : "STANDBY"} detail={role() === "server" ? `${s.data()?.peers ?? 0} 个 TCP 会话` : s.data()?.connected ? "TCP 已连接 / 等待或正在传输" : "尚未建立 TCP 连接"} accent />
          <Metric label="INFORMATION POINTS" value={String(role() === "server" ? s.data()?.station.length ?? 0 : s.data()?.received.length ?? 0).padStart(2, "0")} detail={role() === "server" ? "六种类型 · 内存模拟点表" : "从对端接收的真实数据"} />
          <Metric label="ASDU · RX / TX" value={`${role() === "server" ? s.data()?.server_rx ?? 0 : s.data()?.client_rx ?? 0} / ${role() === "server" ? s.data()?.server_tx ?? 0 : s.data()?.client_tx ?? 0}`} detail="累计应用数据单元，不含 S / U 帧" /></View>
        <Connection store={s} role={role()} />
      </If>
      <If when={tab() === "overview" || tab() === "points"}><View style={{ flexDirection: narrow() ? "column" : "row", gap: 22, alignItems: "flex-start" }}><View style={{ flex: 1, width: narrow() ? "100%" : undefined }}><PointTable store={s} role={role()} onSelect={p => focus.set(p)} /></View><View style={{ width: narrow() ? "100%" : 310 }}><Command store={s} role={role()} point={focus()} /></View></View></If>
      <If when={tab() === "overview" || tab() === "traffic"}><Traffic store={s} role={role()} preview={tab() === "overview"} /></If>
      <If when={tab() === "inspect"}><Inspector store={s} /></If>
      <View style={{ ...row, justifyContent: "space-between", paddingBottom: 10 }}><Text style={{ fontSize: 9, color: c.muted }}>IEC104 STUDIO / ENGINEERING TOOLS</Text><Text style={{ fontSize: 9, fontFamily: mono, color: c.muted }}>NO AUTOMATIC CONTROL</Text></View>
    </View></Scroll>
  </View>;
}

export function launch(role: Role) { mount(() => <Studio initialRole={role} />); }
