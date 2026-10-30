import { cleanup, signal } from "nsh";

export type Role = "server" | "client";
export type Kind = "single" | "double" | "normalized" | "scaled" | "float" | "counter";
export type Point = { ioa: number; name: string; kind: Kind; value: number; quality: number; updated_at: string };
export type Event = { id: number; time: string; side: string; direction: string; message: string; hex: string };
export type Snapshot = {
  server_running: boolean; server_addr: string | null; client_addr: string | null;
  connected: boolean; active: boolean; peers: number; server_ca: number; client_ca: number;
  server_rx: number; server_tx: number; client_rx: number; client_tx: number;
  station: Point[]; received: Point[]; events: Event[];
};

export function createStore() {
  const data = signal<Snapshot | null>(null);
  const online = signal(false);
  const token = signal("");
  const endpoint = signal("http://127.0.0.1:24040");
  const busy = signal(false);
  const message = signal("输入 API Token，连接本地控制服务。");
  const failed = signal(false);
  const selected = signal<{ ioa: number; kind: Kind; value: number; until: number } | null>(null);
  const clock = signal(Date.now());
  let refreshing = false;
  let disposed = false;
  const controllers = new Set<AbortController>();

  async function request(path: string, body?: unknown) {
    const url = endpoint().replace(/\/$/, "");
    if (!/^http:\/\/(127\.0\.0\.1|localhost|\[::1\]):\d+$/.test(url)) throw new Error("控制 API 只允许本机 HTTP 地址与显式端口");
    const controller = new AbortController();
    controllers.add(controller);
    const timer = setTimeout(() => controller.abort(), 8000);
    try {
      const response = await fetch(url + path, {
        method: body ? "POST" : "GET",
        headers: { "X-IEC104-Token": token(), ...(body ? { "Content-Type": "application/json" } : {}) },
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
      if (!response.ok) {
        const detail = await response.text();
        try { throw new Error(JSON.parse(detail).error || `HTTP ${response.status}`); }
        catch (e) { if (e instanceof SyntaxError) throw new Error(`HTTP ${response.status}`); throw e; }
      }
      return await response.json();
    } finally { clearTimeout(timer); controllers.delete(controller); }
  }
  function error(e: unknown) { failed.set(true); message.set(String(e instanceof Error ? e.message : e)); }
  async function refresh(authorize = false) {
    if (refreshing || disposed || (!online() && !authorize)) return;
    refreshing = true;
    try {
      const next = await request("/api/state") as Snapshot;
      if (!disposed) {
        data.set(next); online.set(true);
        if (!next.active) selected.set(null);
        if (authorize) { failed.set(false); message.set("控制服务已连接。所有协议操作均需手动触发。"); }
      }
    } catch (e) { if (!disposed) { online.set(false); selected.set(null); error(e); } }
    finally { refreshing = false; }
  }
  async function act(action: string, params: Record<string, unknown> = {}) {
    if (busy() || !online()) return null;
    busy.set(true); failed.set(false);
    try {
      const result = await request("/api/action", { action, ...params });
      message.set(action === "select" ? "选择已确认。请在 10 秒内执行，相同点号及数值才有效。" : "操作已完成 / 对端已确认");
      await refresh();
      return result;
    } catch (e) { selected.set(null); error(e); return null; }
    finally { busy.set(false); }
  }
  function credentialsChanged() { online.set(false); selected.set(null); }
  const timer = setInterval(() => { clock.set(Date.now()); void refresh(); }, 1000);
  cleanup(() => { disposed = true; clearInterval(timer); for (const c of controllers) c.abort(); });
  return { data, online, token, endpoint, busy, message, failed, selected, clock, refresh, act, credentialsChanged };
}

export const kindLabel: Record<Kind, string> = { single: "单点遥信", double: "双点遥信", normalized: "归一化值", scaled: "标度化值", float: "短浮点数", counter: "累计量" };
export const typeLabel: Record<Kind, string> = { single: "M_SP_NA_1", double: "M_DP_NA_1", normalized: "M_ME_NA_1", scaled: "M_ME_NB_1", float: "M_ME_NC_1", counter: "M_IT_NA_1" };
export function pointValue(p: Point): string {
  if (p.kind === "single") return p.value === 1 ? "ON · 合" : "OFF · 分";
  if (p.kind === "double") return p.value === 2 ? "CLOSED · 合" : p.value === 1 ? "OPEN · 分" : "不确定";
  return p.kind === "float" ? p.value.toFixed(2) : String(p.value);
}
