package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type PacketInfo struct {
	SrcIP string `json:"src_ip"`
	DstIP string `json:"dst_ip"`
	Protocol string `json:"protocol"`
}

func pcapget() {
	//获取网卡（windows）
	devices, err := pcap.FindAllDevs()
	if err!=nil{
		log.Fatal(err)
	}

	if len(devices)==0{
		log.Fatal("没有找到网卡")
	}

	//选择第一个网卡设备
	device := devices[0].Name
	fmt.Println("当前使用网卡：", device)
	
	handle, err:= pcap.OpenLive(device, 65535, true, pcap.BlockForever)
	if err !=nil{
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets(){
		networkLayer :=packet.NetworkLayer()
		if networkLayer != nil{
			info :=PacketInfo{
				SrcIP: networkLayer.NetworkFlow().Src().String(),
				DstIP: networkLayer.NetworkFlow().Dst().String(),
				Protocol: networkLayer.LayerType().String(),
			}

			jsonData, _:=json.Marshal(info)
			fmt.Println(string(jsonData))
		}
	}
}

func saveget() {
	// Windows 推荐先获取设备列表
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	if len(devices) == 0 {
		log.Fatal("没有找到网卡设备")
	}

	// 选第一个网卡（测试用）
	device := devices[0].Name
	fmt.Println("使用网卡:", device)

	handle, err := pcap.OpenLive(device, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		fmt.Println(packet)
	}
}

func standpcap() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	if len(devices) == 0 {
		log.Fatal("没有找到网卡")
	}

	for i, device := range devices {
		fmt.Printf("[%d] %s\n", i, device.Name)
		fmt.Printf("    Description: %s\n", device.Description)

		for _, address := range device.Addresses {
			fmt.Printf("    IP: %s\n", address.IP)
		}
		fmt.Println("--------------------------------")
	}

	var index int
	fmt.Print("选择网卡编号: ")
	fmt.Scanln(&index)

	handle, err := pcap.OpenLive(devices[index].Name, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		fmt.Println(packet)
	}
}
