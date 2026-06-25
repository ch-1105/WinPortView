# WinPortView — Windows 端口查看器

![Python](https://img.shields.io/badge/python-3.8+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

WinPortView 是一个轻量级的 Windows 端口查看工具，实时展示运行中的 TCP/UDP 端口、对应的进程和 Windows 服务。

## 功能

- **端口列表** — 展示所有 TCP/UDP 连接：协议、本地地址、远程地址、状态、PID、进程名、服务名
- **实时刷新** — 默认 2 秒自动刷新，支持 1/2/5/10 秒间隔或暂停
- **搜索过滤** — 按端口号、进程名、服务名、PID 快速定位
- **终止进程** — 右键菜单一键终止占用端口的进程
- **服务识别** — 自动识别 svchost 等进程承载的多个 Windows 服务
- **状态着色** — 不同连接状态对应不同颜色，一目了然
- **管理员模式** — 可通过"管理员模式"按钮提权，终止系统进程

## 快速开始

### 从源码运行

```bash
pip install -r requirements.txt
py main.py
```

### 打包为单文件

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name WinPortView main.py
```

可执行文件在 `dist/WinPortView.exe`。

## 依赖

| 包 | 用途 |
|---|---|
| psutil | 端口扫描与进程管理 |
| ttkbootstrap | 现代化 tkinter 主题 |
| wmi | Windows 服务信息查询 |

## 技术架构

```
main.py → MainWindow (ttkbootstrap GUI)
            ├── PortScanner  — psutil.net_connections()
            ├── ProcessResolver — PID → 进程名（缓存）
            └── ServiceResolver — WMI → PID → 服务名（后台定时刷新）
```

## 许可

MIT
