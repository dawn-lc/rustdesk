# RustDesk SOS 精简受控端

基于 `hbb_common` 库构建的 RustDesk 精简远程协助客户端。
仅支持 Windows，单一可执行文件，系统托盘交互，支持 UAC 捕获。

## 功能

- ✅ 屏幕捕获与编码（DXGI/DGI + H264/VP8）
- ✅ 鼠标键盘输入注入（含 UAC 安全桌面操作）
- ✅ 音频捕获（cpal/WASAPI + Opus）
- ✅ 剪贴板同步（文本 + 文件列表）
- ✅ 文件传输（分块 + Zstd 压缩）
- ✅ TCP 隧道（端口白名单 + 最多 10 条）
- ✅ UAC 捕获（SYSTEM 权限便携服务）

## 构建

```powershell
cargo build --bin rustdesk-sos --release
```

产物：`target/release/rustdesk-sos.exe`

## 运行

```powershell
# 使用默认信令服务器
rustdesk-sos.exe

# 指定信令服务器
rustdesk-sos.exe --rendezvous rs-cn.rustdesk.com

# 指定设备 ID
rustdesk-sos.exe --id 123456789

# 设置临时密码
rustdesk-sos.exe --password mypassword
```

## 服务器端

SOS 客户端依赖独立的 RustDesk 服务器组件：

- 信令服务器 (hbbs, 端口 21116)
- 中继服务器 (hbbr, 端口 21117)

服务器端使用 [rustdesk/rustdesk-server](https://github.com/rustdesk/rustdesk-server) 部署。

## 要求

- Windows 7+ (x86_64)
- 必须以管理员权限运行
- 需要 DirectX 11 兼容 GPU（DXGI 捕获）
