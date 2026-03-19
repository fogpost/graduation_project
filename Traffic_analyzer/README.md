# Traffic_analyzer

本目录是项目当前主线实现（可直接运行）。

## 技术栈

- 后端：FastAPI + Scapy
- 前端：Vue 3 + Vite

## 后端结构

- `main.py`：API 入口
- `core/pcap_loader.py`：pcap 加载
- `core/packet_list.py`：包列表与分页
- `core/list_packet_parser.py`：单包分层解析

## 运行后端

在仓库根目录执行：

```powershell
.\.venv\Scripts\Activate.ps1
python -m uvicorn Traffic_analyzer.main:app --reload --host 127.0.0.1 --port 8000
```

## 前端开发

```powershell
cd Traffic_analyzer\traffic-ui
npm install
npm run dev
```

## 已完成的稳定性改造（第一阶段）

- 启动加载 pcap 路径可配置
- `packet_id` 越界返回 404
- `/packets` 支持 `offset + limit` 分页
- 新增 `/health` 接口
- CORS 由全开放调整为本地开发源
