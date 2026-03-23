# graduation_project

基于网络流量抓取与离线解析的异常通信检测系统（毕业设计项目）。

## 项目目标

项目主线：抓包层 -> 解析层 -> API 层 -> 前端展示层。

当前第一阶段已完成内容：
- 明确主线目录与草稿目录边界
- 后端接口增加基础稳定性（错误处理、健康检查、分页）
- 文档统一 UTF-8 并补齐启动说明
- 提供一键启动脚本（Windows PowerShell）

## 目录说明

- `Traffic_analyzer/`：当前可运行主线
- `draft/`：历史实验与草稿代码（不作为当前交付主链路）
- `requirements.txt`：Python 依赖
- `scripts/`：启动脚本

## 快速开始

### 1) 安装依赖

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2) 启动后端 API

```powershell
.\scripts\start_backend.ps1
```

后端默认地址：`http://127.0.0.1:8000`

### 3) 启动前端（可选）

```powershell
.\scripts\start_frontend.ps1
```

前端默认地址：`http://127.0.0.1:34115`（Wails 标准前端工程开发服务）

### 4) 一键同时启动（后端+前端）

```powershell
.\scripts\start_all.ps1
```

### 5) 启动 Go 实时抓包（可选）

```powershell
.\scripts\start_go_capture.ps1
```

或与前后端一起启动：

```powershell
.\scripts\start_all.ps1 -WithCapture
```

### 6) 启动 Wails 桌面端（推荐）

```powershell
.\scripts\start_wails_shell.ps1
```

如需手动指定路径（打包后推荐）：
- `TA_PROJECT_ROOT`：仓库根目录
- `TRAFFIC_ANALYZER_DATA_DIR`：数据目录
- `TA_PYTHON`：Python 可执行路径

## API 概览

- `GET /health`：健康检查
- `GET|POST /load?file_path=...`：加载 pcap 文件
- `GET /pcap-files`：获取 `Traffic_analyzer/data` 下可解析文件列表（含 size/modified_at）
- `POST /load-data-file?relative_path=...`：按相对路径加载 `data` 下文件
- `POST /load-next-data-file`：按列表顺序加载下一个文件
- `POST /upload-pcap`：上传并解析 pcap 文件
- `GET /packets?offset=0&limit=200`：分页获取包列表
- `GET /packet/{packet_id}`：查看单包分层字段
- `GET /packet/{packet_id}/detail`：查看单包详情（层级字段 + raw hex + 偏移）
- `GET /analysis/rules`：规则库列表
- `GET /analysis/report`：特征统计 + 可解释检测告警列表

## 说明

- 默认启动时会尝试加载：
  `Traffic_analyzer/data/test/all-xena-pcap/ARP_Spoofing.pcap`
- 可通过环境变量 `PCAP_ON_STARTUP` 覆盖默认路径
