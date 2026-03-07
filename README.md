# graduation_project
my_homework_for_graduation

抓包层 → 解析层 → API层 → 前端展示

Go（抓包 + 初步解析）
用 Go + gopacket
作用：
实时抓包
提取基本信息
写入 pcap 或 json

用 Python + Scapy

用 FastAPI
作用：
提供 API：
GET /packets
GET /packet/{id}
GET /flows