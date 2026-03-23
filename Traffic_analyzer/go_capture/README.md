# go_capture

实时抓包模块，输出 `.pcap` 文件到 `Traffic_analyzer/data/live/`。

## 运行

```powershell
cd Traffic_analyzer\go_capture
go run .
```

默认行为：
- 自动选择一个网卡
- 最多抓取 500 个包
- 最长抓取 60 秒
- 输出文件到 `${TRAFFIC_ANALYZER_DATA_DIR}/live`（未设置时使用 `..\data\live`）

## 常用参数

```powershell
go run . -list-ifaces
go run . -iface-index 3 -count 1000 -timeout 120
go run . -iface "Intel(R) Ethernet" -count 1000 -timeout 120
go run . -out "..\data\live\manual_capture.pcap"
```

参数说明：
- `-list-ifaces`: 列出可用网卡（含描述和 IP）
- `-iface-index`: 按网卡索引选择
- `-iface`: 按网卡名称或描述关键字匹配
- `-count`: 最大抓包数量
- `-timeout`: 超时秒数
- `-out`: 输出文件路径
- `-snaplen`: 抓包快照长度
- `-promisc`: 是否混杂模式
