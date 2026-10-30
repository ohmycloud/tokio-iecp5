import { expect, open, test } from "nsh/test";

for (const role of ["client", "server"] as const) {
  test(`${role} app has its own mark and switches role without network access`, async () => {
    const app = await open(`./${role}/App.tsx`, { width: 1440, height: 1000 });
    const label = role === "client" ? "IEC104 客户端图标" : "IEC104 服务端图标";
    const otherLabel = role === "client" ? "IEC104 服务端图标" : "IEC104 客户端图标";
    expect(app.count(`label:${label}`)).toEqual(1);
    expect(app.count("id:workspace-app-icon")).toEqual(1);
    expect(app.texts()).toContain(role === "client" ? "MASTER / 客户端" : "STATION / 服务端");
    await app.press(role === "client" ? "服务端 / Station" : "客户端 / Master");
    expect(app.count(`label:${otherLabel}`)).toEqual(1);
    expect(app.count(`label:${label}`)).toEqual(0);
    expect(app.requests().length).toEqual(0);
  });
}
