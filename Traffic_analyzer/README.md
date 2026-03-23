# Traffic_analyzer

当前主线实现目录（后端 API + 前端页面 + Go 实时抓包 + Wails 壳）。

## 目录

- `main.py`：FastAPI 入口
- `core/`：pcap 加载、文件目录索引、包详情解析
- `wails_shell/frontend/`：Wails 标准前端工程（Vue + Vite）
- `traffic-ui/`：历史前端目录（已迁移，保留参考）
- `go_capture/`：Go 实时抓包模块（输出到 `data/live`）
- `wails_shell/`：Wails 桌面端（内置后端，不再 iframe）
- `data/`：样本数据与抓包输出

## 后端接口

- `GET /health`
- `GET|POST /load?file_path=...`
- `GET /pcap-files`
- `POST /load-data-file?relative_path=...`
- `POST /load-next-data-file`
- `POST /upload-pcap`
- `GET /packets?offset=0&limit=200`
- `GET /packet/{packet_id}`
- `GET /packet/{packet_id}/detail`
- `GET /analysis/rules`
- `GET /analysis/report`

## 前端功能

- 刷新包列表
- 导包（上传并解析）
- 文件解析列表（加载 `data` 下任意文件）
- 顺序解析下一个文件
- 自动刷新文件列表
- 自动轮询解析 `data/live` 新抓包文件
- 包详情固定为：左侧解析数据、右侧 Hex 联动高亮

## Go 抓包模块

```powershell
cd Traffic_analyzer\go_capture
go run .
```

常用参数：

```powershell
go run . -list-ifaces
go run . -iface-index 3 -count 1000 -timeout 120
go run . -out "..\data\live\manual_capture.pcap"
```

## Wails 轻量壳

```powershell
.\scripts\start_wails_shell.ps1
```

详细说明见：`Traffic_analyzer/wails_shell/README.md`
