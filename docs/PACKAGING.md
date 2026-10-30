# 独立 UI 应用：安装、打包与排错

> 所有命令从项目根目录执行。UI 使用 NSH 0.3.0，Rust 本地控制服务独立运行。
> 两个应用仅是控制界面，**不内嵌/不自动启动 Rust 控制服务，也不自动连接设备**。

## 1. 环境与目录

- Rust/Cargo：构建 `iec104-console`；纯 NSH UI 打包不需要重新构建协议库。
- NSH CLI **0.3.0 (`76fa8a7`)**：`nsh --version` 确认版本。
- macOS 原生运行要求 macOS 14+；打包图标使用系统的 `sips`、`iconutil` 和 `codesign`。
- Web 本地预览需要现代浏览器；运行 `nsh test … --target web` 需要 Chrome / Chromium / Edge。
- Windows / Linux 在各自系统打包；Linux 需要 NSH 对应的 GTK 4.14+ 等平台依赖。
  具体安装要求见 [NSH 官方文档](https://nsh.dev/docs/installation)。

macOS 安装 NSH：

```sh
brew install longbridge/tap/nsh
nsh --version
```

若安装的是更新版本，先执行本文的类型检查与测试；NSH main 文档和 0.3.0 的 Input / Image API
存在差异，不能仅按主分支示例替换项目代码。

```text
ui/
├── client/
│   ├── App.tsx        launch("client")
│   ├── nsh.json       独立 name / id / icon
│   └── tsconfig.json
├── server/
│   ├── App.tsx        launch("server")
│   ├── nsh.json       独立 name / id / icon
│   └── tsconfig.json
├── shared/            两端共用的工作台、状态和图标组件
├── assets/            随项目提供的 SVG / PNG，不依赖下载
├── App.tsx            兼容旧的客户端开发入口
├── Server.tsx         兼容旧的服务端开发入口
└── nsh.json           旧工作区元数据，默认客户端图标
```

| 应用 | 名称 | 应用 ID | 打包图标 |
|---|---|---|---|
| 客户端 | IEC104 Client | `com.ohmycloud.iec104studio.client` | `ui/assets/app-client.png` |
| 服务端 | IEC104 Server | `com.ohmycloud.iec104studio.server` | `ui/assets/app-server.png` |

**独立发布必须使用 `ui/client`、`ui/server`。** 直接打包旧的 `ui/Server.tsx` 会读取同目录
`ui/nsh.json`，无法自动切换成服务端应用 ID 和服务端系统图标。

## 2. 开发模式

三个终端分别启动：

```sh
# 终端 A：控制服务，启动时显示 API Token
cargo run --features console --bin iec104-console

# 终端 B：服务端 UI
nsh run ui/server --target macos --window-size 1440x1000

# 终端 C：客户端 UI
nsh run ui/client --target macos --window-size 1440x1000
```

原生窗口使用共享 NSH 开发宿主，所以 Dock 可能仍显示开发宿主图标；这不是应用图标失效。
界面内会分别显示对应的角色图标；系统级图标需要下一节的打包模式。

连接步骤：

1. 两个窗口填入终端 A 显示的 Token，连接默认 API `http://127.0.0.1:24040`。
2. 服务端使用 `127.0.0.1:2404` / 公共地址 `1`，点击“启动监听”。
3. 客户端连接同一地址，点击 STARTDT，再总召唤、计数量召唤。
4. 单/双点遥控须先选择并等待确认，再在 10 秒内执行；操作细节见 [工作台文档](STUDIO.md)。
5. 退出前断开客户端、停止监听，最后对控制服务 Ctrl-C。

默认是本机内存模拟站点，不需要外部设备。不要为了“启动成功”而填入真实生产设备地址。

## 3. macOS：带独立图标的应用包

```sh
nsh package ui/client --target macos --out "$PWD/dist/macos/client"
nsh package ui/server --target macos --out "$PWD/dist/macos/server"

open "dist/macos/client/IEC104 Client.app"
open "dist/macos/server/IEC104 Server.app"
```

产物：

```text
dist/macos/
├── client/IEC104 Client.app
└── server/IEC104 Server.app
```

两者有不同 Bundle ID 和 `AppIcon.icns`，可以同时运行或分别复制到 `/Applications`。
首次验证建议先从 `dist/` 打开，确认图标、窗口名称及 Token 流程，再安装；复制/更新应用前先退出旧版本。

本机开发包是 **ad hoc 签名**，不是 Developer ID 签名或公证发布包。对外分发需按 Apple 的要求签名、
开启合适的 hardened runtime 配置并公证；不要把本地包描述成已通过 Gatekeeper 分发验收。
参考 [NSH macOS 打包说明](https://nsh.dev/docs/macos)。

核对已打包的图标与身份：

```sh
/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' \
  'dist/macos/client/IEC104 Client.app/Contents/Info.plist'
/usr/libexec/PlistBuddy -c 'Print :CFBundleIconFile' \
  'dist/macos/client/IEC104 Client.app/Contents/Info.plist'
ls -lh 'dist/macos/client/IEC104 Client.app/Contents/Resources/AppIcon.icns'

# 服务端应是不同的 Bundle ID，并具有自己的 AppIcon.icns
/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' \
  'dist/macos/server/IEC104 Server.app/Contents/Info.plist'
```

要无需 Cargo 启动控制服务，可先 `cargo build --release --features console --bin iec104-console`，
再运行 `./target/release/iec104-console`。如果配置了 `CARGO_TARGET_DIR`，二进制位于对应的 target 目录。
分发时必须同时考虑该 Rust 程序和两个 UI 应用；不需要在用户机器上安装 NSH CLI 来打开已打包的 UI。

## 4. Web

开发预览：

```sh
nsh run ui/client --target web
nsh run ui/server --target web
```

独立静态包：

```sh
nsh package ui/client --target web --out "$PWD/dist/web/client"
nsh package ui/server --target web --out "$PWD/dist/web/server"
```

目录分别为 `dist/web/client/IEC104 Client/`、`dist/web/server/IEC104 Server/`。
NSH 会生成 `index.html`、带内容哈希的运行时/资源、`manifest.webmanifest` 和多尺寸图标。
客户端/服务端的 favicon、manifest 名称和应用图标各不相同。

用本机 HTTP 服务打开，不要直接双击 `file://` 页面：

```sh
python3 -m http.server 8080 --bind 127.0.0.1 --directory 'dist/web/client/IEC104 Client'
# 浏览器打开 http://127.0.0.1:8080
```

本机控制服务仍需运行。默认 CORS 只允许 **HTTP 的回环来源**；HTTPS 公网部署不能直接沿用这里的
HTTP 本机控制方案。浏览器可能要求本地网络访问权限；CORS、CSP、混合内容和浏览器私网访问策略都是
独立限制，不能用关闭浏览器安全机制来替代合理部署。Web 图标资源已生成并检查；不声称所有浏览器
都能把此工具作为完整离线 PWA 安装。

## 5. Windows / Linux

以下为 NSH 支持的打包命令，**本项目尚未在这两个系统进行实机验收**。
在对应系统、项目根目录运行：

```sh
# Windows：生成目录、带嵌入图标的 .exe 和 .zip
nsh package ui/client --target windows --out dist/windows/client
nsh package ui/server --target windows --out dist/windows/server

# Linux：生成目录、.desktop、PNG 和 .tar.gz
nsh package ui/client --target linux --out dist/linux/client
nsh package ui/server --target linux --out dist/linux/server
```

不要只复制 `.exe` 或 Linux 可执行文件；UI 依赖旁边的 `nsh/` 资源目录。Linux 桌面启动器需按系统的
`.desktop` 安装方式处理路径及图标；Windows 图标嵌入在 Windows 上完成。Rust 控制服务也需在相同机器
构建/运行，不能把 macOS 控制服务二进制直接复制到其他系统使用。

## 6. 验证与发布清单

```sh
cargo test --all-features --all-targets
cargo clippy --all-features --all-targets -- -D warnings
nsh check ui
nsh check ui/client
nsh check ui/server
nsh test ui
python3 -m unittest discover -s tests -p 'test_ui_assets.py' -v
```

- 检查应用名称、版本、`build`、独立 ID 和图标路径；正式使用自己的反向域名 ID。
- 版本与网络能力配置目前在 `ui/nsh.json`、`ui/client/nsh.json`、`ui/server/nsh.json` 中分别声明，
  **不隐式继承**；修改时同步三处，离线测试会检测能力配置漂移。
- 打开真实包检查 Dock/Finder 图标，而不是只检查开发宿主。
- 运行默认无网络测试，再运行显式 opt-in 的真实协议联调；不要把 Token 写入配置/应用包。
- 修改图标后重新生成全部 PNG、重新打包，必要时递增 `build`；不要只替换已签名包内部文件。
- 更新 `docs/screenshots/`；输出 `dist/`、`.nsh/` 和 Python 缓存不提交 Git。

实机流程及截图使用专用 API 端口 **24940** 和模拟站点端口 **24904**，不会操作默认的
24040/2404 开发服务。确保这两个测试端口空闲；固定测试 Token 不能用于正式环境：

```sh
# 终端 A
IEC104_API_ADDR=127.0.0.1:24940 IEC104_TOKEN=iec104-local-smoke-token \
  cargo run --features console --bin iec104-console
# 终端 B：macOS 原生；完成后也可再测 Web
nsh test tests/ui/workflow.test.tsx --target macos
nsh test tests/ui/workflow.test.tsx --target web
```

## 7. 常见问题

| 现象 | 检查方法 |
|---|---|
| Dock 仍是 NSH 图标 | 是否正在用 `nsh run`？改为打开 `nsh package ui/client` / `ui/server` 的 `.app` |
| 两端应用名称/图标相同 | 是否打包了旧 `ui/Server.tsx`？使用独立目录，检查 `CFBundleIdentifier` 和 `icon` |
| 更新图标后 Finder 未变化 | 退出旧应用、重新完整打包并替换应用；重新启动 Finder/登录会话可刷新系统图标缓存，不必修改系统安全设置 |
| `rsvg-convert` 找不到 | 仅图标再生成需要 `librsvg`；普通运行/打包直接使用随项目提供的 PNG |
| `nsh check` 提示缺少类型 | 在对应应用目录执行 `nsh check ui/client` / `ui/server` 以生成 `.nsh/`；检查 NSH 版本 |
| API 连接失败 | 检查 Rust 服务是否运行、API 地址及 Token，API 必须为本机 HTTP 地址 |
| 401 | 使用本次服务启动打印的 Token；自动 Token 在重启后会改变 |
| 端口占用 | 不重复启动控制服务；改 `IEC104_API_ADDR` 后同步修改两个窗口 API 地址；模拟站点使用其他空闲端口 |
| STARTDT/命令超时 | 检查 TCP 是否连接、对端协议支持、公共地址及设备确认；不要把排队成功当成执行成功 |
| 空点表 | 先连接 → STARTDT → 总召唤；累计量需单独计数量召唤 |
| 打包后 UI 正常但操作不可用 | UI 不自带 Rust 后端；必须先启动控制服务并输入 Token |

更多业务限制见 [工作台安全边界](STUDIO.md#限制与安全)，图标源文件维护见 [图标文档](ICONS.md)。
