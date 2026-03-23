package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type DeviceInfo struct {
	Index       int
	Name        string
	Description string
	IPs         []string
}

func resolveDataRoot() string {
	envData := strings.TrimSpace(os.Getenv("TRAFFIC_ANALYZER_DATA_DIR"))
	if envData != "" {
		return envData
	}
	return filepath.Join("..", "data")
}

func defaultOutputPath() string {
	now := time.Now().Format("20060102_150405")
	return filepath.Join(resolveDataRoot(), "live", "live_"+now+".pcap")
}

func collectDevices() ([]DeviceInfo, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, fmt.Errorf("no network interfaces found")
	}

	out := make([]DeviceInfo, 0, len(devices))
	for i, d := range devices {
		item := DeviceInfo{
			Index:       i,
			Name:        d.Name,
			Description: d.Description,
		}
		for _, addr := range d.Addresses {
			item.IPs = append(item.IPs, addr.IP.String())
		}
		out = append(out, item)
	}

	return out, nil
}

func listDevices(devices []DeviceInfo) {
	fmt.Println("Available interfaces:")
	for _, d := range devices {
		desc := d.Description
		if strings.TrimSpace(desc) == "" {
			desc = "(no description)"
		}
		ips := "-"
		if len(d.IPs) > 0 {
			ips = strings.Join(d.IPs, ",")
		}
		fmt.Printf("[%d] %s\n", d.Index, d.Name)
		fmt.Printf("    Description: %s\n", desc)
		fmt.Printf("    IPs: %s\n", ips)
	}
}

func pickInterface(devices []DeviceInfo, nameOrDesc string, index int) (DeviceInfo, error) {
	if index >= 0 {
		if index >= len(devices) {
			return DeviceInfo{}, fmt.Errorf("iface-index out of range: %d", index)
		}
		return devices[index], nil
	}

	if strings.TrimSpace(nameOrDesc) != "" {
		target := strings.ToLower(strings.TrimSpace(nameOrDesc))
		for _, d := range devices {
			if strings.ToLower(d.Name) == target {
				return d, nil
			}
		}
		for _, d := range devices {
			if strings.Contains(strings.ToLower(d.Name), target) || strings.Contains(strings.ToLower(d.Description), target) {
				return d, nil
			}
		}
		return DeviceInfo{}, fmt.Errorf("no interface matched: %s", nameOrDesc)
	}

	for _, d := range devices {
		nameLower := strings.ToLower(d.Name)
		if strings.Contains(nameLower, "loopback") || strings.Contains(nameLower, "npcap loopback") {
			continue
		}
		if len(d.IPs) > 0 {
			return d, nil
		}
	}

	return devices[0], nil
}

func ensureParentDir(path string) error {
	parent := filepath.Dir(path)
	return os.MkdirAll(parent, 0o755)
}

func main() {
	iface := flag.String("iface", "", "Interface name or description keyword")
	ifaceIndex := flag.Int("iface-index", -1, "Interface index from -list-ifaces")
	listIfaces := flag.Bool("list-ifaces", false, "List available interfaces and exit")
	jsonOutput := flag.Bool("json", false, "When used with -list-ifaces, print JSON output")
	output := flag.String("out", defaultOutputPath(), "Output pcap path")
	packetCount := flag.Int("count", 500, "Max packets to capture")
	timeoutSec := flag.Int("timeout", 60, "Max capture time in seconds")
	snaplen := flag.Int("snaplen", 65535, "Snap length")
	promisc := flag.Bool("promisc", true, "Promiscuous mode")
	flag.Parse()

	if *packetCount <= 0 {
		log.Fatal("count must be > 0")
	}
	if *timeoutSec <= 0 {
		log.Fatal("timeout must be > 0")
	}

	devices, err := collectDevices()
	if err != nil {
		log.Fatalf("failed to query interfaces: %v", err)
	}

	if *listIfaces {
		if *jsonOutput {
			data, err := json.Marshal(devices)
			if err != nil {
				log.Fatalf("failed to encode interfaces json: %v", err)
			}
			fmt.Println(string(data))
			return
		}
		listDevices(devices)
		return
	}

	picked, err := pickInterface(devices, *iface, *ifaceIndex)
	if err != nil {
		log.Fatalf("failed to pick interface: %v", err)
	}

	if err := ensureParentDir(*output); err != nil {
		log.Fatalf("failed to create output directory: %v", err)
	}

	handle, err := pcap.OpenLive(picked.Name, int32(*snaplen), *promisc, pcap.BlockForever)
	if err != nil {
		log.Fatalf("failed to open interface %s: %v", picked.Name, err)
	}
	defer handle.Close()

	outFile, err := os.Create(*output)
	if err != nil {
		log.Fatalf("failed to create output file: %v", err)
	}
	defer outFile.Close()

	writer := pcapgo.NewWriter(outFile)
	if err := writer.WriteFileHeader(uint32(*snaplen), handle.LinkType()); err != nil {
		log.Fatalf("failed to write pcap header: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	timeout := time.After(time.Duration(*timeoutSec) * time.Second)

	desc := strings.TrimSpace(picked.Description)
	if desc == "" {
		desc = "(no description)"
	}
	fmt.Printf("Start capture on [%d] %s (%s) output=%s count=%d timeout=%ds\n", picked.Index, picked.Name, desc, *output, *packetCount, *timeoutSec)

	captured := 0
	for captured < *packetCount {
		select {
		case pkt, ok := <-packetSource.Packets():
			if !ok {
				fmt.Println("Packet source closed")
				fmt.Printf("Capture finished. packets=%d output=%s\n", captured, *output)
				return
			}

			ci := pkt.Metadata().CaptureInfo
			if err := writer.WritePacket(ci, pkt.Data()); err != nil {
				log.Fatalf("failed to write packet: %v", err)
			}

			captured++
		case <-timeout:
			fmt.Println("Capture timeout reached")
			fmt.Printf("Capture finished. packets=%d output=%s\n", captured, *output)
			return
		}
	}

	fmt.Printf("Capture finished. packets=%d output=%s\n", captured, *output)
	fmt.Println("Tip: use -list-ifaces to get index and description, then set -iface-index", strconv.Itoa(picked.Index))
}
