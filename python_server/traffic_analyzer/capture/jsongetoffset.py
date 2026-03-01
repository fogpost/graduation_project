import json
from scapy.all import PcapReader, IP, TCP, UDP, ARP, Ether
from pathlib import Path

# 1. 路径设置
base_path = Path(__file__).resolve()
pcap_file = base_path.parent.parent / 'data' / 'all-xena-pcap' / 'ARP_Spoofing.pcap'

def get_packet_layers_with_offsets(pkt):
    #解析数据包，并获取偏移量和长度
    layers_info=[]
    raw_bytes=bytes(pkt)
    current_offset=0

    #遍历数据包所有层
    layer= pkt
    while layer:
        layer_name=layer.name
        layer_payload_offset = len(layer)-len(layer.payload)

        layer_detail={
            "layer":layer_name,
            "start":current_offset,
            "end":current_offset+layer_payload_offset,
            "fields":{}
        }

        #提取当前层的所有字段
        for field in layer.fields_desc:
            field_name=field.name
            if field_name in layer.fields:
                #获取字段位置和长度
                #采用简化映射
                fvalue=layer.getfieldval(field_name)
                #通过字节表示
                try:
                    # i2m 将 Python 对象转为机器字节流，len() 即可获得准确字节长度
                    flen = len(field.i2m(layer, fvalue))
                except Exception:
                    # 备选方案：尝试获取 sz 属性
                    flen = getattr(field, 'sz', 0)

                # 获取字段在当前层内的相对偏移
                # 某些字段（如 BitField）可能没有 start()，这里做异常处理
                try:
                    f_start = field.start(layer)
                except Exception:
                    f_start = 0

                #计算字段在原始数据中的位置
                layer_detail["fields"][field_name]={
                    "value":str(field.i2repr(layer, fvalue)),
                    "offset":current_offset + f_start,
                    "length":flen
                }
        
        layers_info.append(layer_detail)

        #移动下一层
        current_offset+=layer_payload_offset
        layer = layer.payload
        if not layer or isinstance(layer,(bytes,str)):
            break

    return layers_info

#2.主逻辑
packet_list=[]

if pcap_file.exists():
    with PcapReader(str(pcap_file)) as reader:
        count = 0
        for pkt in reader:
            count+=1
            
            #原始数据转化为hex
            raw_hex=bytes(pkt).hex()

            pkt_entry={
                "id":count,
                "time":float(pkt.time),
                "raw_hex":raw_hex,
                "structure":get_packet_layers_with_offsets(pkt)
            }

            packet_list.append(pkt_entry)
            
            if count>=50:
                break

# 3.导出json
    output_filename=f"{pcap_file.stem}_offsets.json"
    output_dir = base_path.parent.parent / "output"
    output_dir.mkdir(exist_ok=True)
    output_path = base_path.parent / "output" / output_filename
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(packet_list, f, indent=4, ensure_ascii=False)

    print(f"解析完成！JSON 已生成：{output_path}")
else:
    print("文件不存在")


