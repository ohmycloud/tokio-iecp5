# 应用图标与界面图标

## 设计

两端使用同一视觉语言，靠轮廓而不只是颜色区分。图标均为本项目原创几何绘制，不使用 emoji、
截图、外部商标、图标字体或 CDN，不需要额外第三方图标授权；随项目采用根目录的 MIT 许可证。

| 客户端：IEC104 Client | 服务端：IEC104 Server |
|:---:|:---:|
| ![客户端](../ui/assets/app-client-128.png) | ![服务端](../ui/assets/app-server-128.png) |
| 显示终端、薄荷绿信号脉冲、暖橙发送箭头 | 双层机架、暖橙状态灯、三分支连接节点 |
| 强调观测与发送 | 强调站点与多连接 |

共同特征：深松绿圆角底板、细内边框、象牙白主体、充足留白。主图形在 32px 左右仍可识别，
不加入缩小后无法阅读的 `IEC104` 文字。1024px 资源保留透明安全边距，适用于 macOS 桌面图标；
本项目未把当前图标作为 iOS App Store 的无透明通道资源验证。

## 资源目录

```text
ui/assets/
├── app-client.svg          原创客户端矢量源文件，1024×1024 viewBox
├── app-client.png          客户端打包图标，1024×1024 RGBA PNG
├── app-client-128.png      客户端界面/文档预览，128×128 RGBA PNG
├── app-server.svg          原创服务端矢量源文件
├── app-server.png          服务端打包图标，1024×1024 RGBA PNG
├── app-server-128.png      服务端界面/文档预览，128×128 RGBA PNG
└── glyphs/                 18 个 24×24 SVG 线性图标
```

18 个界面图标：`overview`、`points`、`traffic`、`inspect`、`server`、`client`、
`connect`、`disconnect`、`play`、`stop`、`scan`、`counter`、`select`、`execute`、
`save`、`load`、`settings`、`shield`。

统一采用 24×24 网格、1.7 单位线宽、圆端点和圆连接。在浅色工作区使用深色线条，在深绿侧栏使用
灰绿/暖橙线条，主操作按钮使用白色线条。**状态不能只靠图标或颜色表达**：所有按钮仍保留文字、
禁用态和无障碍名称，装饰图标设置 `accessible={false}`，避免屏幕阅读器重复朗读。

## 在界面中使用

组件位于 `ui/shared/Icons.tsx`，使用 NSH 原生 `Image`，没有 HTML `<svg>` 或 DOM 依赖。

```tsx
import { AppMark, Icon } from "./Icons";

<AppMark role="client" size={44} />
<AppMark role="server" size={44} />
<Icon name="scan" size={17} color="#23725C" />
```

`AppMark` 使用本地 128px PNG，供高密度屏幕上的小尺寸显示；图标带“IEC104 客户端图标”/
“IEC104 服务端图标”的无障碍名称。角色切换时，界面标记和角色文字同步更新，不发起网络连接。

线性图标以 SVG 源数据用 `tintColor` 着色。生成器把 128px 标记和 SVG 的本地字节写入
`ui/shared/icon-data.ts`（base64 data URI），随 TS 模块内嵌；1024px 系统图标仍由打包器读取 PNG。

这样做是为了规避 NSH 0.3.0 的跨应用根目录资源路径问题：两个独立入口引用上一级共用图片时，
直接图片 import 会生成带构建机器绝对路径的资源 URI，开发宿主请求会 404，打包资源也可能落到错误位置。
内嵌的小图标不依赖源代码目录、网络或资源文件查找；不是运行时下载/拼接文件路径。该方案已经在
macOS 原生和 Web 运行中验证，没有图标加载失败警告。不要把 1024px 大图一起内嵌进脚本。

**版本提醒**：已验证的 NSH 0.3.0 使用 `<Image resizeMode="contain">`，而不是主分支文档中的
`style.objectFit`。升级 NSH 时以 `nsh check ui` 生成的类型为准。

## 绑定到系统应用

两个应用各自的 `nsh.json` 已配置图标，路径相对该配置文件：

```json
// ui/client/nsh.json 的相关字段（注释不是实际 JSON 的一部分）
{
  "name": "IEC104 Client",
  "id": "com.ohmycloud.iec104studio.client",
  "icon": "../assets/app-client.png"
}
```

服务端对应 `IEC104 Server`、`com.ohmycloud.iec104studio.server` 和 `../assets/app-server.png`。
NSH 打包器负责转换：

- macOS：生成多尺寸 `AppIcon.icns`，并设置 `CFBundleIconFile`。
- Windows：在 Windows 上把图标嵌入应用 `.exe`。
- Linux：复制 PNG，并写入应用 `.desktop` 条目。
- Web：生成 32/180/192/512px 图标、favicon、apple-touch-icon 和 manifest 引用。

这些是打包器的工作，不需要手动提交 `.icns` / `.ico`。macOS 与 Web 产物已实际生成并检查；
Windows / Linux 未在本项目中实机验收。

`nsh run` 运行的是共享开发宿主，**不会因为配置了 `icon` 就改变开发宿主的 Dock 图标**。
要看到独立系统图标，请打开 `nsh package` 生成的 `.app`。完整命令见 [打包与安装](PACKAGING.md)。

## 修改与重新生成

**正常运行和打包不需要图形工具**：SVG 和 PNG 均已随项目提供。只有更新设计时才需要重新生成。

生成器是 `scripts/generate-icons.py`。它是图标的唯一设计源，使用 Python 3 标准库构建 SVG，
再调用 `rsvg-convert` 渲染 PNG，最后更新 `ui/shared/icon-data.ts`；没有字体依赖，也不会联网下载素材。

```sh
# macOS：只在修改设计时安装
brew install librsvg

# Debian / Ubuntu 对应依赖：librsvg2-bin
# 从项目根目录运行
python3 scripts/generate-icons.py

# 仅更新 SVG（不更新 PNG / icon-data.ts，不能代替完整发布流程）
python3 scripts/generate-icons.py --svg-only
```

修改 `app_svg()` 中的应用几何形状，或者 `GLYPHS` 中的线性路径，然后运行完整生成器。
**不要只手改生成的 SVG 或 PNG**，否则之后重新生成会覆盖修改，源文件一致性测试也会失败。
渲染器版本可能影响 PNG 压缩/抗锯齿细节，因此测试验证尺寸、PNG CRC/解压完整性及矢量源的一致性，
不跨版本硬编码 PNG 的文件哈希。测试也会核对内嵌模块和当前图片字节是否一致，防止更新资源后界面仍使用旧图标。

更新图标后：

```sh
python3 scripts/generate-icons.py
python3 -m unittest discover -s tests -p 'test_ui_assets.py' -v
nsh check ui
nsh test ui
nsh package ui/client --target macos --out "$PWD/dist/macos/client"
nsh package ui/server --target macos --out "$PWD/dist/macos/server"
```

检查两端在浅/深背景、32px 与 128px 下的辨识度，重新生成工作台截图；不要把 `.nsh/`、`dist/`
或 Python 缓存提交进仓库。
