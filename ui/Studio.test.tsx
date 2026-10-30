import { expect, open, test } from "nsh/test";

const point = { ioa: 100, name: "主进线断路器", kind: "single", value: 1, quality: 0, updated_at: "12:00:00.000" };
const initial = {
  server_running: false, server_addr: null, client_addr: null, connected: false, active: false,
  peers: 0, server_ca: 1, client_ca: 1, server_rx: 0, server_tx: 0, client_rx: 0, client_tx: 0,
  station: [point], received: [], events: [],
};
const viewport = { width: 1440, height: 1100 };

test("starts safely: no network, no automatic protocol operation", async () => {
  const app = await open("./App.tsx", viewport);
  expect(app.texts()).toContain("IEC104 Studio");
  expect(app.texts()).toContain("暂无接收数据");
  expect(app.enabled("连接站点")).toEqual(false);
  expect(app.enabled("2. 确认执行")).toEqual(false);
  expect(app.requests().length).toEqual(0);
});

test("station entry, authorization and point filtering", async () => {
  const app = await open("./Server.tsx", { ...viewport, network: { "GET http://127.0.0.1:24040/api/state": { body: initial } } });
  await app.type("id:api-token", "test-token-12345678");
  await app.press("id:authorize");
  await app.waitFor("API ONLINE");
  expect(app.texts()).toContain("模拟点表");
  expect(app.texts()).toContain("主进线断路器");
  expect(app.enabled("启动监听")).toEqual(true);
  await app.type("id:point-search", "not-a-point");
  await app.waitFor("没有匹配的信息点");
  expect(app.requests().every(r => r.method === "GET")).toEqual(true);
});

test("master explicitly connects, activates and interrogates", async () => {
  const state = { ...initial };
  const actions: string[] = [];
  const app = await open("./App.tsx", { ...viewport, network: {
    "GET http://127.0.0.1:24040/api/state": () => ({ body: state }),
    "POST http://127.0.0.1:24040/api/action": req => {
      const command = JSON.parse(req.body!); actions.push(command.action);
      if (command.action === "client_connect") state.connected = true;
      if (command.action === "start_dt") state.active = true;
      if (command.action === "interrogation") (state.received as typeof point[]) = [point];
      return { body: { ok: true } };
    },
  } });
  await app.type("id:api-token", "test-token-12345678"); await app.press("id:authorize"); await app.waitFor("API ONLINE");
  await app.press("连接站点"); await app.waitFor("TCP CONNECTED");
  expect(app.enabled("总召唤")).toEqual(false);
  await app.press("STARTDT"); await app.waitUntil(() => app.enabled("总召唤"));
  await app.press("总召唤"); await app.waitFor("主进线断路器");
  expect(actions).toEqual(["client_connect", "start_dt", "interrogation"]);
});

test("execution stays locked until select confirmation; value change invalidates it", async () => {
  const app = await open("./App.tsx", { ...viewport, network: {
    "GET http://127.0.0.1:24040/api/state": { body: { ...initial, connected: true, active: true, received: [point] } },
    "POST http://127.0.0.1:24040/api/action": { body: { ok: true } },
  } });
  await app.type("id:api-token", "test-token-12345678"); await app.press("id:authorize"); await app.waitFor("API ONLINE");
  expect(app.enabled("2. 确认执行")).toEqual(false);
  await app.press("1. 选择"); await app.waitUntil(() => app.enabled("2. 确认执行"));
  await app.press("双点 · 1 / 2");
  expect(app.enabled("2. 确认执行")).toEqual(false);
  const posts = app.requests().filter(r => r.method === "POST");
  expect(posts.length).toEqual(1); expect(JSON.parse(posts[0].body!).action).toEqual("select");
});

test("authorization error does not enable operations", async () => {
  const app = await open("./App.tsx", { ...viewport, network: { "GET http://127.0.0.1:24040/api/state": { status: 401, body: { error: "Token 不正确" } } } });
  await app.type("id:api-token", "bad-token"); await app.press("id:authorize"); await app.waitFor("Token 不正确");
  expect(app.enabled("连接站点")).toEqual(false);
});

test("inspector displays a parsed result and mobile navigation works", async () => {
  const app = await open("./App.tsx", { width: 390, height: 844, network: {
    "GET http://127.0.0.1:24040/api/state": { body: initial },
    "POST http://127.0.0.1:24040/api/action": { body: { ok: true, description: "U_STARTDT_ACTIVE / valid" } },
  } });
  await app.type("id:api-token", "test-token-12345678"); await app.press("id:authorize"); await app.waitFor("API ONLINE");
  await app.press("报文解析"); await app.press("解析报文"); await app.waitFor("U_STARTDT_ACTIVE / valid");
});
