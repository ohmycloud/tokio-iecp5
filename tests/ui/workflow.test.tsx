// Opt-in live test: IEC104_API_ADDR=127.0.0.1:24940 IEC104_TOKEN=iec104-local-smoke-token.
// Dedicated test ports avoid touching a user\'s development service on 24040/2404.
// Run separately from the stubbed suite: nsh test tests/ui/workflow.test.tsx --target web
import { expect, open, test } from "nsh/test";

test("live native-shell workflow and screenshots", async () => {
  const app = await open("../../ui/server/App.tsx", { width: 1440, height: 1100, network: "live", platform: "macos" });
  await app.clear("id:api-endpoint");
  await app.type("id:api-endpoint", "http://127.0.0.1:24940");
  await app.clear("id:address");
  await app.type("id:address", "127.0.0.1:24904");
  await app.type("id:api-token", "iec104-local-smoke-token");
  await app.press("id:authorize"); await app.waitFor("API ONLINE");
  await app.press("启动监听"); await app.waitFor("LISTENING");
  await app.press("客户端 / Master"); await app.press("连接站点"); await app.waitFor("TCP CONNECTED");
  await app.press("STARTDT"); await app.waitUntil(() => app.enabled("总召唤"));
  await app.press("总召唤"); await app.waitFor("主进线断路器");
  await app.press("计数量召唤"); await app.waitFor("正向有功电能 / kWh");
  await app.press("1. 选择"); await app.waitUntil(() => app.enabled("2. 确认执行"));
  await app.press("2. 确认执行"); await app.waitFor("OFF · 分");
  await app.press("label:控制服务设置");
  await app.screenshot("docs/screenshots/client.png");
  await app.press("服务端 / Station"); await app.waitFor("模拟点表");
  await app.screenshot("docs/screenshots/server.png");
  await app.press("停止监听");
  expect(app.texts()).toContain("OFFLINE");
});
