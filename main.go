package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/tarm/serial"
)

func main() {
	// シリアルポートの設定
	config := &serial.Config{
		Name: "COM13", // シリアルポートのデバイス名（適宜変更してください）
		Baud: 9600,   // ボーレート（通信速度）を設定します
	}

	// シリアルポートを開く
	port, err := serial.OpenPort(config)
	if err != nil {
		log.Fatal(err)
	}
	defer port.Close()

	// ネットワークデバイスの取得
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Devices found:")
	// デバイスの一覧を表示
	for i, device := range devices {
		fmt.Printf("%d. %s\n", i, device.Name)
		for _, address := range device.Addresses {
			fmt.Printf("    IP address: %s\n", address.IP)
		}
	}

	// 数字を入力してもらいデバイスを選択
	var deviceNumber int
	var deviceName string
	fmt.Print("Select device number: ")
	fmt.Scan(&deviceNumber)
	selectedDevice := devices[deviceNumber]
	deviceName = selectedDevice.Name
	fmt.Println("Selected device: ", deviceName)

	// 最初のネットワークデバイスを使用してパケットキャプチャを開始
	handle, err := pcap.OpenLive(deviceName, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// パケットのキュー
	packetQueue := make(chan gopacket.Packet, 100)

	// パケットをキャプチャしてキューに入れるゴルーチン
	go func() {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			packetQueue <- packet
		}
	}()

	// キューからパケットを順に取り出して処理するゴルーチン
	for packet := range packetQueue {
		// パケットの種類を判別して数字を返す
		packetType := getPacketType(selectedDevice, packet)
		fmt.Println(packetType)
		_, err = port.Write(packetType)
		if err != nil {
			log.Fatal(err)
		}
		// 0.1秒待つ
		time.Sleep(150 * time.Millisecond)
	}
}

func isAnomaly(packet gopacket.Packet) bool {
	anml := false
	if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
			tcpl, _ := tcp.(*layers.TCP)
			// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
			if tcpl.FIN && tcpl.URG && tcpl.PSH {
					anml = true
			}
	}
	return anml
}

// 返り値は[(受信なら0, 送信なら1), categorizePacketを参照しパケットの種類]
func getPacketType(device pcap.Interface, packet gopacket.Packet) []byte {
	packetType := []byte{0, 0}
	if isAnomaly(packet) {
		packetType[1] = 1
		fmt.Print("Anomaly ")
	}else if lldp := packet.Layer(layers.LayerTypeLinkLayerDiscovery); lldp != nil {
		packetType[1] = 2
		fmt.Print("LLDP ")
	}else if dns := packet.Layer(layers.LayerTypeDNS); dns != nil {
		packetType[1] = 3
		fmt.Print("DNS ")
	}else if icmpv4 := packet.Layer(layers.LayerTypeICMPv4); icmpv4 != nil {
		packetType[1] = 4
		fmt.Print("ICMPv4 ")
	}else if icmpv6 := packet.Layer(layers.LayerTypeICMPv6); icmpv6 != nil {
		packetType[1] = 4
		fmt.Print("ICMPv6 ")
	}else if dhcpv4 := packet.Layer(layers.LayerTypeDHCPv4); dhcpv4 != nil {
		packetType[1] = 5
		fmt.Print("DHCPv4 ")
	}else if arp := packet.Layer(layers.LayerTypeARP); arp != nil {
		packetType[1] = 6
		fmt.Print("ARP ")
	}else if igmp := packet.Layer(layers.LayerTypeIGMP); igmp != nil {
		packetType[1] = 7
		fmt.Print("IGMP ")
	}else if udp := packet.Layer(layers.LayerTypeUDP); udp != nil {
		packetType[1] = 8
		fmt.Print("UDP ")
	}else if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
		packetType[1] = 9
		fmt.Print("TCP ")
	}
	// 送信ならpacketType[0]を1にする、受信なら0のまま
	for _, address := range device.Addresses {
		// panic: runtime error: invalid memory address or nil pointer dereference
		if nil == packet.NetworkLayer() {
			continue
		}

		if address.IP.String() == packet.NetworkLayer().NetworkFlow().Dst().String() {
			packetType[0] = 1
		}
	}

	return packetType
}