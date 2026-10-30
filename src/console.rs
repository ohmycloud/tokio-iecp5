//! Optional loopback-only control API for the NSH operator applications.
#[cfg(test)]
mod tests;
use std::{
    collections::{BTreeMap, VecDeque},
    future::{ready, Ready},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpListener,
    sync::{broadcast, Mutex as AsyncMutex},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::{
    asdu::{Asdu, Cause, CauseOfTransmission, InfoObjAddr, TypeID},
    cproc::{DoubleCommandInfo, SingleCommandInfo},
    csys::{ObjectQCC, ObjectQOI},
    mproc::*,
    Client, ClientHandler, ClientOption, Error, Server, ServerHandler,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PointKind {
    Single,
    Double,
    Normalized,
    Scaled,
    Float,
    Counter,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Point {
    pub ioa: u16,
    pub name: String,
    pub kind: PointKind,
    pub value: f64,
    pub quality: u8,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub id: u64,
    pub time: String,
    pub side: String,
    pub direction: String,
    pub message: String,
    pub hex: String,
}

struct Data {
    station: BTreeMap<u16, Point>,
    received: BTreeMap<u16, Point>,
    events: VecDeque<Event>,
    next_id: u64,
    peers: usize,
    server_ca: u16,
    client_ca: u16,
    server_rx: u64,
    server_tx: u64,
    client_rx: u64,
    client_tx: u64,
}

fn now() -> String {
    chrono::Utc::now().format("%H:%M:%S%.3f").to_string()
}
fn cot(cause: Cause) -> CauseOfTransmission {
    CauseOfTransmission::new(false, false, cause)
}
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|p| p.into_inner())
}

impl Data {
    fn event(&mut self, side: &str, direction: &str, message: String, hex: String) {
        self.next_id += 1;
        self.events.push_front(Event {
            id: self.next_id,
            time: now(),
            side: side.into(),
            direction: direction.into(),
            message,
            hex,
        });
        self.events.truncate(300);
    }
    fn asdu(&mut self, side: &str, direction: &str, asdu: &Asdu) {
        let mut a = asdu.clone();
        let bytes: Bytes = asdu.clone().try_into().unwrap_or_default();
        let hex = bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ");
        let message = format!(
            "{:?} · {:?} · CA {}",
            a.identifier.type_id,
            a.identifier.cot.cause().get(),
            a.identifier.common_addr
        );
        match (side, direction) {
            ("server", "RX") => self.server_rx += 1,
            ("server", "TX") => self.server_tx += 1,
            ("client", "RX") => self.client_rx += 1,
            ("client", "TX") => self.client_tx += 1,
            _ => {}
        }
        self.event(side, direction, message, hex);
    }
}

fn seed() -> BTreeMap<u16, Point> {
    [
        (100, "主进线断路器", PointKind::Single, 1.0),
        (101, "备用进线断路器", PointKind::Single, 0.0),
        (102, "保护动作信号", PointKind::Single, 0.0),
        (200, "母联开关", PointKind::Double, 1.0),
        (201, "隔离开关", PointKind::Double, 2.0),
        (300, "有功功率 / NVA (i16)", PointKind::Normalized, 16384.0),
        (400, "母线电流 / A", PointKind::Scaled, 286.0),
        (401, "环境温度 / °C", PointKind::Scaled, 26.0),
        (500, "母线电压 / kV", PointKind::Float, 10.52),
        (501, "系统频率 / Hz", PointKind::Float, 50.01),
        (600, "正向有功电能 / kWh", PointKind::Counter, 128640.0),
        (601, "反向有功电能 / kWh", PointKind::Counter, 320.0),
    ]
    .into_iter()
    .map(|(ioa, name, kind, value)| {
        (
            ioa,
            Point {
                ioa,
                name: name.into(),
                kind,
                value,
                quality: 0,
                updated_at: now(),
            },
        )
    })
    .collect()
}

struct RunningServer {
    addr: SocketAddr,
    cancel: CancellationToken,
    task: JoinHandle<()>,
}
struct RunningClient {
    addr: SocketAddr,
    client: Arc<Client<Monitor>>,
}
#[derive(Clone)]
struct Selection {
    ioa: u16,
    value: f64,
    kind: PointKind,
    at: Instant,
}

/// A process can host one station and one master, each controlled independently.
pub struct Console {
    token: String,
    data: Arc<Mutex<Data>>,
    server: AsyncMutex<Option<RunningServer>>,
    client: AsyncMutex<Option<RunningClient>>,
    selection: Mutex<Option<Selection>>,
    actions: AsyncMutex<()>,
    replies: broadcast::Sender<Asdu>,
}

impl Console {
    pub fn new(token: String) -> Arc<Self> {
        assert!(!token.is_empty(), "API token must not be empty");
        let (replies, _) = broadcast::channel(128);
        Arc::new(Self {
            token,
            data: Arc::new(Mutex::new(Data {
                station: seed(),
                received: BTreeMap::new(),
                events: VecDeque::new(),
                next_id: 0,
                peers: 0,
                server_ca: 1,
                client_ca: 1,
                server_rx: 0,
                server_tx: 0,
                client_rx: 0,
                client_tx: 0,
            })),
            server: AsyncMutex::new(None),
            client: AsyncMutex::new(None),
            selection: Mutex::new(None),
            actions: AsyncMutex::new(()),
            replies,
        })
    }
    pub fn router(self: &Arc<Self>) -> Router {
        use axum::http::{header::CONTENT_TYPE, HeaderName, Method, Uri};
        use tower_http::cors::{AllowOrigin, CorsLayer};
        // Browsers may access the token-protected API only from local dev origins.
        let cors = CorsLayer::new()
            .allow_origin(AllowOrigin::predicate(|origin, _| {
                origin
                    .to_str()
                    .ok()
                    .and_then(|s| s.parse::<Uri>().ok())
                    .is_some_and(|u| {
                        u.scheme_str() == Some("http")
                            && matches!(u.host(), Some("localhost" | "127.0.0.1" | "[::1]"))
                    })
            }))
            .allow_methods([Method::GET, Method::POST])
            .allow_headers([CONTENT_TYPE, HeaderName::from_static("x-iec104-token")]);
        Router::new()
            .route("/api/state", get(state))
            .route("/api/action", post(action))
            .layer(cors)
            .with_state(self.clone())
    }
    pub async fn shutdown(&self) {
        let _guard = self.actions.lock().await;
        self.stop_client().await;
        self.stop_server().await;
    }
    async fn stop_client(&self) {
        if let Some(running) = self.client.lock().await.take() {
            running.client.stop().await;
        }
        *lock(&self.selection) = None;
        lock(&self.data).event("client", "SYS", "客户端已断开".into(), String::new());
    }
    async fn stop_server(&self) {
        if let Some(running) = self.server.lock().await.take() {
            running.cancel.cancel();
            let _ = running.task.await;
        }
        lock(&self.data).event(
            "server",
            "SYS",
            "监听及全部会话已停止".into(),
            String::new(),
        );
    }
    async fn client(&self) -> anyhow::Result<Arc<Client<Monitor>>> {
        self.client
            .lock()
            .await
            .as_ref()
            .map(|c| c.client.clone())
            .ok_or_else(|| anyhow::anyhow!("请先连接客户端"))
    }
    async fn snapshot(&self) -> Snapshot {
        let server = self.server.lock().await;
        let client = self.client.lock().await;
        let connected = match client.as_ref() {
            Some(c) => c.client.is_connected().await,
            None => false,
        };
        let active = match client.as_ref() {
            Some(c) => c.client.is_active().await,
            None => false,
        };
        let d = lock(&self.data);
        Snapshot {
            server_running: server.as_ref().is_some_and(|s| !s.task.is_finished()),
            server_addr: server.as_ref().map(|s| s.addr.to_string()),
            client_addr: client.as_ref().map(|c| c.addr.to_string()),
            connected,
            active,
            peers: d.peers,
            server_ca: d.server_ca,
            client_ca: d.client_ca,
            server_rx: d.server_rx,
            server_tx: d.server_tx,
            client_rx: d.client_rx,
            client_tx: d.client_tx,
            station: d.station.values().cloned().collect(),
            received: d.received.values().cloned().collect(),
            events: d.events.iter().cloned().collect(),
        }
    }
    async fn perform(&self, action: Action) -> anyhow::Result<serde_json::Value> {
        let _guard = self.actions.lock().await;
        match action {
            Action::ServerStart {
                address,
                common_addr,
            } => {
                valid_ca(common_addr)?;
                if self.server.lock().await.is_some() {
                    anyhow::bail!("服务端已经启动，请先停止");
                }
                let addr: SocketAddr = address.parse()?;
                // This simulator is deliberately not exposed to the LAN.
                if !addr.ip().is_loopback() {
                    anyhow::bail!("模拟服务端只允许监听回环地址");
                }
                let listener = TcpListener::bind(addr).await?;
                let addr = listener.local_addr()?;
                let cancel = CancellationToken::new();
                let shutdown = cancel.clone();
                let data = self.data.clone();
                lock(&data).server_ca = common_addr;
                let task = tokio::spawn(async move {
                    let error_data = data.clone();
                    let on_connected = move |stream, peer| {
                        let handler = StationHandler::new(data.clone(), peer);
                        async move { Ok(Some((handler, stream))) }
                    };
                    let result = Server::new(listener)
                        .serve_until(
                            &on_connected,
                            move |err| {
                                lock(&error_data).event(
                                    "server",
                                    "ERR",
                                    err.to_string(),
                                    String::new(),
                                );
                            },
                            shutdown.cancelled(),
                        )
                        .await;
                    if let Err(e) = result {
                        log::error!("Station listener: {e}");
                    }
                });
                *self.server.lock().await = Some(RunningServer { addr, cancel, task });
                lock(&self.data).event(
                    "server",
                    "SYS",
                    format!("正在监听 {addr} · CA {common_addr}"),
                    String::new(),
                );
            }
            Action::ServerStop => self.stop_server().await,
            Action::ClientConnect {
                address,
                common_addr,
            } => {
                valid_ca(common_addr)?;
                self.stop_client().await;
                let addr = address.parse()?;
                {
                    let mut d = lock(&self.data);
                    d.client_ca = common_addr;
                    d.received.clear();
                }
                // IEC104 does not transmit point names. Only reuse simulator labels
                // when connecting to this process's own station with the same CA.
                let own_station = self
                    .server
                    .lock()
                    .await
                    .as_ref()
                    .is_some_and(|s| s.addr == addr);
                let labels = {
                    let d = lock(&self.data);
                    if own_station && d.server_ca == common_addr {
                        d.station
                            .iter()
                            .map(|(ioa, p)| (*ioa, p.name.clone()))
                            .collect()
                    } else {
                        BTreeMap::new()
                    }
                };
                let monitor = Monitor {
                    data: self.data.clone(),
                    replies: self.replies.clone(),
                    common_addr,
                    labels,
                };
                let client = Arc::new(Client::new(monitor, ClientOption::new(addr, false)));
                client.start().await?;
                let connected = tokio::time::timeout(Duration::from_secs(5), async {
                    while !client.is_connected().await {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                })
                .await;
                if connected.is_err() {
                    client.stop().await;
                    anyhow::bail!("TCP 连接失败或超时（5 秒），请检查地址及服务端");
                }
                *self.client.lock().await = Some(RunningClient { addr, client });
                lock(&self.data).event(
                    "client",
                    "SYS",
                    format!("TCP 已连接 {addr}，等待 STARTDT"),
                    String::new(),
                );
            }
            Action::ClientDisconnect => self.stop_client().await,
            Action::StartDt | Action::StopDt => {
                let start = matches!(action, Action::StartDt);
                let c = self.client().await?;
                if start {
                    c.send_start_dt().await?;
                } else {
                    c.send_stop_dt().await?;
                }
                tokio::time::timeout(Duration::from_secs(3), async {
                    loop {
                        if !c.is_connected().await {
                            anyhow::bail!("等待确认时连接关闭");
                        }
                        if c.is_active().await == start {
                            break Ok(());
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                })
                .await
                .map_err(|_| anyhow::anyhow!("STARTDT/STOPDT 确认超时"))??;
                if !start {
                    *lock(&self.selection) = None;
                }
                lock(&self.data).event(
                    "client",
                    "SYS",
                    if start {
                        "STARTDT 已确认"
                    } else {
                        "STOPDT 已确认"
                    }
                    .into(),
                    String::new(),
                );
            }
            Action::Interrogation | Action::CounterInterrogation => {
                let counters = matches!(action, Action::CounterInterrogation);
                let ca = lock(&self.data).client_ca;
                let a = if counters {
                    crate::csys::counter_interrogation_cmd(
                        cot(Cause::Activation),
                        ca,
                        ObjectQCC::new(5),
                    )?
                } else {
                    crate::csys::interrogation_cmd(cot(Cause::Activation), ca, ObjectQOI::new(20))?
                };
                self.request(a, Cause::ActivationTerm).await?;
            }
            Action::Select { ioa, kind, value } => {
                *lock(&self.selection) = None;
                let a = self.control(ioa, kind, value, true)?;
                self.request(a, Cause::ActivationCon).await?;
                *lock(&self.selection) = Some(Selection {
                    ioa,
                    kind,
                    value,
                    at: Instant::now(),
                });
            }
            Action::Execute { ioa, kind, value } => {
                let selected = lock(&self.selection).take();
                if !selected.is_some_and(|s| {
                    s.ioa == ioa
                        && s.kind == kind
                        && s.value == value
                        && s.at.elapsed() < Duration::from_secs(10)
                }) {
                    anyhow::bail!("请先成功选择相同点号和值；选择有效期 10 秒");
                }
                let a = self.control(ioa, kind, value, false)?;
                self.request(a, Cause::ActivationTerm).await?;
            }
            Action::UpdatePoint { ioa, value } => {
                let mut d = lock(&self.data);
                let point = d
                    .station
                    .get_mut(&ioa)
                    .ok_or_else(|| anyhow::anyhow!("未知点号"))?;
                valid_value(point.kind, value)?;
                point.value = value;
                point.updated_at = now();
                d.event(
                    "server",
                    "SYS",
                    format!("模拟点 {ioa} 更新为 {value}；客户端需重新召唤"),
                    String::new(),
                );
            }
            Action::Parse { hex } => {
                let frames = crate::inspect::inspect_frames(&hex)?;
                let description = frames
                    .iter()
                    .map(|a| {
                        let mut asdu = a.asdu.clone();
                        let points = asdu.as_mut().and_then(|a| decode_points(a).ok());
                        format!("{a:#?}\nDecoded points: {points:#?}")
                    })
                    .collect::<Vec<_>>()
                    .join("\n\n");
                return Ok(serde_json::json!({ "ok": true, "description": description }));
            }
            Action::ClearLogs => lock(&self.data).events.clear(),
        }
        Ok(serde_json::json!({ "ok": true }))
    }
    fn control(&self, ioa: u16, kind: PointKind, value: f64, select: bool) -> anyhow::Result<Asdu> {
        if ioa == 0 || ioa == u16::MAX {
            anyhow::bail!("点号必须为 1..65534");
        }
        valid_value(kind, value)?;
        let ca = lock(&self.data).client_ca;
        Ok(match kind {
            PointKind::Single => crate::cproc::single_cmd(
                TypeID::C_SC_NA_1,
                cot(Cause::Activation),
                ca,
                SingleCommandInfo::new(ioa, value == 1.0, select),
            )?,
            PointKind::Double => crate::cproc::double_cmd(
                TypeID::C_DC_NA_1,
                cot(Cause::Activation),
                ca,
                DoubleCommandInfo::new(ioa, value as u8, select),
            )?,
            _ => anyhow::bail!("控制台仅开放单点/双点遥控；遥测和累计量请在模拟点表编辑"),
        })
    }
    async fn request(&self, asdu: Asdu, expected: Cause) -> anyhow::Result<()> {
        let c = self.client().await?;
        let mut replies = self.replies.subscribe();
        c.send_asdu(asdu.clone()).await?;
        lock(&self.data).asdu("client", "TX", &asdu);
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let mut reply = replies.recv().await?;
                if reply.identifier.type_id != asdu.identifier.type_id
                    || reply.identifier.common_addr != asdu.identifier.common_addr
                    || reply.raw != asdu.raw
                {
                    continue;
                }
                let cause = reply.identifier.cot.cause().get();
                if reply.identifier.cot.positive().get()
                    || matches!(
                        cause,
                        Cause::UnknownCA
                            | Cause::UnknownIOA
                            | Cause::UnknownCOT
                            | Cause::UnknownTypeID
                    )
                {
                    anyhow::bail!("对端拒绝命令: {cause:?}");
                }
                if cause == expected {
                    return Ok(());
                }
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("等待 ASDU 确认超时（3 秒）；发送入队不等于执行成功"))?
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        if let Some(server) = self.server.get_mut().take() {
            server.cancel.cancel();
            server.task.abort();
        }
        // Dropping the last Client aborts its connection task as well.
        self.client.get_mut().take();
    }
}

fn valid_ca(ca: u16) -> anyhow::Result<()> {
    if ca == 0 || ca == u16::MAX {
        anyhow::bail!("公共地址必须为 1..65534");
    }
    Ok(())
}
fn valid_value(kind: PointKind, value: f64) -> anyhow::Result<()> {
    let valid = value.is_finite()
        && match kind {
            PointKind::Single => value == 0.0 || value == 1.0,
            PointKind::Double => value == 1.0 || value == 2.0,
            PointKind::Normalized | PointKind::Scaled => {
                value.fract() == 0.0 && (i16::MIN as f64..=i16::MAX as f64).contains(&value)
            }
            PointKind::Float => value.abs() <= f32::MAX as f64,
            PointKind::Counter => {
                value.fract() == 0.0 && (i32::MIN as f64..=i32::MAX as f64).contains(&value)
            }
        };
    if !valid {
        anyhow::bail!("数值超出该点类型允许范围");
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    ServerStart {
        address: String,
        common_addr: u16,
    },
    ServerStop,
    ClientConnect {
        address: String,
        common_addr: u16,
    },
    ClientDisconnect,
    StartDt,
    StopDt,
    Interrogation,
    CounterInterrogation,
    Select {
        ioa: u16,
        kind: PointKind,
        value: f64,
    },
    Execute {
        ioa: u16,
        kind: PointKind,
        value: f64,
    },
    UpdatePoint {
        ioa: u16,
        value: f64,
    },
    Parse {
        hex: String,
    },
    ClearLogs,
}
#[derive(Serialize)]
struct Snapshot {
    server_running: bool,
    server_addr: Option<String>,
    client_addr: Option<String>,
    connected: bool,
    active: bool,
    peers: usize,
    server_ca: u16,
    client_ca: u16,
    server_rx: u64,
    server_tx: u64,
    client_rx: u64,
    client_tx: u64,
    station: Vec<Point>,
    received: Vec<Point>,
    events: Vec<Event>,
}
fn authorized(c: &Console, headers: &HeaderMap) -> bool {
    headers.get("x-iec104-token").and_then(|v| v.to_str().ok()) == Some(c.token.as_str())
}
async fn state(State(c): State<Arc<Console>>, headers: HeaderMap) -> Response {
    if !authorized(&c, &headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error":"请输入控制服务启动时显示的 API Token"})),
        )
            .into_response();
    }
    Json(c.snapshot().await).into_response()
}
async fn action(
    State(c): State<Arc<Console>>,
    headers: HeaderMap,
    Json(a): Json<Action>,
) -> Response {
    if !authorized(&c, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match c.perform(a).await {
        Ok(value) => Json(value).into_response(),
        Err(e) => {
            lock(&c.data).event("console", "ERR", e.to_string(), String::new());
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error":e.to_string()})),
            )
                .into_response()
        }
    }
}

#[derive(Clone)]
struct Monitor {
    data: Arc<Mutex<Data>>,
    replies: broadcast::Sender<Asdu>,
    common_addr: u16,
    labels: BTreeMap<u16, String>,
}
impl ClientHandler for Monitor {
    type Future = Ready<Result<Vec<Asdu>, Error>>;
    fn call(&self, mut asdu: Asdu) -> Self::Future {
        lock(&self.data).asdu("client", "RX", &asdu);
        let _ = self.replies.send(asdu.clone());
        if asdu.identifier.common_addr != self.common_addr {
            return ready(Ok(vec![]));
        }
        let points = decode_points(&mut asdu);
        match points {
            Ok(points) => {
                let mut d = lock(&self.data);
                for mut point in points {
                    if let Some(name) = self.labels.get(&point.ioa) {
                        point.name.clone_from(name);
                    }
                    d.received.insert(point.ioa, point);
                }
            }
            Err(err) => lock(&self.data).event("client", "ERR", err.to_string(), String::new()),
        }
        ready(Ok(vec![]))
    }
}
fn decode_points(a: &mut Asdu) -> anyhow::Result<Vec<Point>> {
    let mut result = vec![];
    let mut push = |mut ioa: InfoObjAddr, kind, value: f64, quality| {
        let ioa = ioa.addr().get();
        let name = format!("信息点 {ioa}");
        // JSON has no NaN/Infinity. Preserve invalid quality rather than break the UI.
        let (value, quality) = if value.is_finite() {
            (value, quality)
        } else {
            (0.0, quality | 0x80)
        };
        result.push(Point {
            ioa,
            name,
            kind,
            value,
            quality,
            updated_at: now(),
        });
    };
    match a.identifier.type_id {
        TypeID::M_SP_NA_1 | TypeID::M_SP_TA_1 | TypeID::M_SP_TB_1 => {
            for mut p in a.get_single_point()? {
                let q = p.siq.raw() & 0xf0;
                push(
                    p.ioa,
                    PointKind::Single,
                    if p.siq.spi().get() { 1.0 } else { 0.0 },
                    q,
                );
            }
        }
        TypeID::M_DP_NA_1 | TypeID::M_DP_TA_1 | TypeID::M_DP_TB_1 => {
            for mut p in a.get_double_point()? {
                let q = p.diq.raw() & 0xf0;
                push(
                    p.ioa,
                    PointKind::Double,
                    p.diq.spi().get().value() as f64,
                    q,
                );
            }
        }
        TypeID::M_ME_NA_1 | TypeID::M_ME_TA_1 | TypeID::M_ME_TD_1 | TypeID::M_ME_ND_1 => {
            for p in a.get_measured_value_normal()? {
                push(
                    p.ioa,
                    PointKind::Normalized,
                    p.nva as f64,
                    p.qds.map(|q| q.raw()).unwrap_or(0),
                );
            }
        }
        TypeID::M_ME_NB_1 | TypeID::M_ME_TB_1 | TypeID::M_ME_TE_1 => {
            for p in a.get_measured_value_scaled()? {
                push(p.ioa, PointKind::Scaled, p.sva as f64, p.qds.raw());
            }
        }
        TypeID::M_ME_NC_1 | TypeID::M_ME_TC_1 | TypeID::M_ME_TF_1 => {
            for p in a.get_measured_value_float()? {
                push(p.ioa, PointKind::Float, p.r as f64, p.qds.raw());
            }
        }
        TypeID::M_IT_NA_1 | TypeID::M_IT_TA_1 | TypeID::M_IT_TB_1 => {
            for p in a.get_integrated_totals()? {
                push(
                    p.ioa,
                    PointKind::Counter,
                    p.bcr.value as f64,
                    if p.bcr.invalid { 0x80 } else { 0 },
                );
            }
        }
        _ => {}
    }
    Ok(result)
}

struct StationHandler {
    data: Arc<Mutex<Data>>,
    selected: Mutex<Option<Selection>>,
    peer: SocketAddr,
}
impl StationHandler {
    fn new(data: Arc<Mutex<Data>>, peer: SocketAddr) -> Self {
        {
            let mut d = lock(&data);
            d.peers += 1;
            d.event("server", "SYS", format!("接受连接 {peer}"), String::new());
        }
        Self {
            data,
            selected: Mutex::new(None),
            peer,
        }
    }
    fn responses(
        &self,
        request: &Asdu,
        response: Result<Vec<Asdu>, Error>,
    ) -> Ready<Result<Vec<Asdu>, Error>> {
        let mut d = lock(&self.data);
        d.asdu("server", "RX", request);
        if let Ok(ref replies) = response {
            for a in replies {
                d.asdu("server", "TX", a);
            }
        }
        ready(response)
    }
    fn reject(&self, a: &Asdu, cause: Cause) -> Asdu {
        let mut reply = a.mirror(cause);
        reply.identifier.cot.positive().set(true); // IEC P/N=1 means negative confirmation.
        reply
    }
    fn interrogate(&self, a: &Asdu, counters: bool) -> Result<Vec<Asdu>, Error> {
        let d = lock(&self.data);
        if a.identifier.common_addr != d.server_ca {
            return Ok(vec![self.reject(a, Cause::UnknownCA)]);
        }
        let mut check = a.clone();
        if !counters && check.identifier.cot.cause().get() == Cause::Deactivation {
            return Ok(vec![a.mirror(Cause::DeactivationCon)]);
        }
        let mut replies = vec![a.mirror(Cause::ActivationCon)];
        // One object per ASDU: deterministic, bounded below the IEC104 maximum.
        for p in d
            .station
            .values()
            .filter(|p| (p.kind == PointKind::Counter) == counters)
        {
            replies.push(point_asdu(
                p,
                d.server_ca,
                if counters {
                    Cause::RequestByGeneralCounter
                } else {
                    Cause::InterrogatedByStation
                },
            )?);
        }
        replies.push(a.mirror(Cause::ActivationTerm));
        Ok(replies)
    }
    fn command(&self, a: &Asdu) -> Result<Vec<Asdu>, Error> {
        let mut input = a.clone();
        let ca = lock(&self.data).server_ca;
        if a.identifier.common_addr != ca {
            return Ok(vec![self.reject(a, Cause::UnknownCA)]);
        }
        if input.identifier.cot.cause().get() != Cause::Activation {
            return Ok(vec![self.reject(a, Cause::UnknownCOT)]);
        }
        let (mut ioa, kind, value, select) = match a.identifier.type_id {
            TypeID::C_SC_NA_1 | TypeID::C_SC_TA_1 => {
                let mut c = input.get_single_cmd()?;
                (
                    c.ioa,
                    PointKind::Single,
                    if c.sco.scs().get() { 1.0 } else { 0.0 },
                    c.sco.se().get(),
                )
            }
            TypeID::C_DC_NA_1 | TypeID::C_DC_TA_1 => {
                let mut c = input.get_double_cmd()?;
                (
                    c.ioa,
                    PointKind::Double,
                    c.dco.dcs().get().value() as f64,
                    c.dco.se().get(),
                )
            }
            _ => return Ok(vec![self.reject(a, Cause::UnknownTypeID)]),
        };
        let ioa = ioa.addr().get();
        let mut d = lock(&self.data);
        let Some(p) = d.station.get_mut(&ioa).filter(|p| p.kind == kind) else {
            return Ok(vec![self.reject(a, Cause::UnknownIOA)]);
        };
        if valid_value(kind, value).is_err() {
            return Ok(vec![self.reject(a, Cause::ActivationCon)]);
        }
        if select {
            *lock(&self.selected) = Some(Selection {
                ioa,
                kind,
                value,
                at: Instant::now(),
            });
            return Ok(vec![a.mirror(Cause::ActivationCon)]);
        }
        let selected = lock(&self.selected).take();
        if !selected.is_some_and(|s| {
            s.ioa == ioa
                && s.kind == kind
                && s.value == value
                && s.at.elapsed() < Duration::from_secs(10)
        }) {
            return Ok(vec![self.reject(a, Cause::ActivationCon)]);
        }
        p.value = value;
        p.updated_at = now();
        Ok(vec![
            a.mirror(Cause::ActivationCon),
            point_asdu(p, ca, Cause::Spontaneous)?,
            a.mirror(Cause::ActivationTerm),
        ])
    }
}
impl Drop for StationHandler {
    fn drop(&mut self) {
        let mut d = lock(&self.data);
        d.peers = d.peers.saturating_sub(1);
        d.event(
            "server",
            "SYS",
            format!("会话 {} 已关闭", self.peer),
            String::new(),
        );
    }
}
impl ServerHandler for StationHandler {
    type Future = Ready<Result<Vec<Asdu>, Error>>;
    fn call(&self, a: Asdu) -> Self::Future {
        let result = self.command(&a);
        self.responses(&a, result)
    }
    fn call_interrogation(&self, a: Asdu, mut qoi: ObjectQOI) -> Self::Future {
        let result = if qoi.range().get() != 20 {
            Ok(vec![self.reject(&a, Cause::ActivationCon)])
        } else {
            self.interrogate(&a, false)
        };
        self.responses(&a, result)
    }
    fn call_counter_interrogation(&self, a: Asdu, qcc: ObjectQCC) -> Self::Future {
        let result = if qcc.raw() != 5 {
            Ok(vec![self.reject(&a, Cause::ActivationCon)])
        } else {
            self.interrogate(&a, true)
        };
        self.responses(&a, result)
    }
}
fn point_asdu(p: &Point, ca: u16, cause: Cause) -> Result<Asdu, Error> {
    let ioa = InfoObjAddr::new(0, p.ioa);
    let qds = || ObjectQDS::try_from(p.quality).unwrap();
    match p.kind {
        PointKind::Single => single(
            false,
            cot(cause),
            ca,
            vec![SinglePointInfo::new_single(p.ioa, p.value == 1.0)],
        ),
        PointKind::Double => double(
            false,
            cot(cause),
            ca,
            vec![DoublePointInfo::new_double(p.ioa, p.value as u8)],
        ),
        PointKind::Normalized => measured_value_normal(
            false,
            cot(cause),
            ca,
            vec![MeasuredValueNormalInfo {
                ioa,
                nva: p.value as i16,
                qds: Some(qds()),
                time: None,
            }],
        ),
        PointKind::Scaled => measured_value_scaled(
            cot(cause),
            ca,
            vec![MeasuredValueScaledInfo {
                ioa,
                sva: p.value as i16,
                qds: qds(),
                time: None,
            }],
        ),
        PointKind::Float => measured_value_float(
            false,
            cot(cause),
            ca,
            vec![MeasuredValueFloatInfo {
                ioa,
                r: p.value as f32,
                qds: qds(),
                time: None,
            }],
        ),
        PointKind::Counter => integrated_totals(
            cot(cause),
            ca,
            vec![BinaryCounterReadingInfo {
                ioa,
                bcr: ObjectBCR {
                    invalid: false,
                    ca: false,
                    cy: false,
                    seq: 0,
                    value: p.value as i32,
                },
                time: None,
            }],
        ),
    }
}
