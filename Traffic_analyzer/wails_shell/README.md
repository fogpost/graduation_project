# wails_shell

Wails 桌面端（标准前端工程，非 iframe 方案）。

## 架构

- Wails 前端：`frontend/`（Vue + Vite）
- Wails 后端：`app.go`（托管后端进程、托管抓包进程、提供状态方法）
- Python 后端 API：`http://127.0.0.1:8000`

## 前置

- Go 1.22+
- Node.js 20+
- Wails CLI：`go install github.com/wailsapp/wails/v2/cmd/wails@latest`

## 开发

```powershell
cd Traffic_analyzer\wails_shell\frontend
npm install
cd ..
go mod tidy
wails dev
```

## 打包

```powershell
cd Traffic_analyzer\wails_shell\frontend
npm install
npm run build
cd ..
wails build
```

## 功能

- 内置启动/停止 Python 后端
- 内置启动/停止 Go 抓包
- 在同一窗口直接展示分析界面（不再 iframe）
- 展示规则库统计、可解释检测结果与告警列表
- 标题区域隐藏终端入口，可打开后台控制终端与日志
- 终端中心支持多终端（本地 + SSH）并可执行命令

## 跨平台路径说明

- 可通过 `TA_PROJECT_ROOT` 指定工程根路径
- 可通过 `TRAFFIC_ANALYZER_DATA_DIR` 指定数据目录（导包/抓包/解析统一使用）
- 可通过 `TA_PYTHON` 指定 Python 可执行程序路径
- 打包后会自动从可执行文件路径向上回溯定位项目目录，避免 `build/bin` 导致的路径错位
