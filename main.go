package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/tarm/serial"
	getserial "go.bug.st/serial.v1"
)

func main() {
	// シリアルポートを開く
	config := setSerialPort()
	port, err := serial.OpenPort(config)
	if err != nil {
		log.Fatal(err)
	}
	defer port.Close()

	// ネットワークデバイスを選択
	selectedDevice := setNetworkDevice()
	deviceName := selectedDevice.Name

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
			if len(packetQueue) >= 50 {
				continue
			}
			packetQueue <- packet
		}
	}()

	// キューからパケットを順に取り出して処理するゴルーチン
	for packet := range packetQueue {
		// パケットの種類を判別して数字を返す
		packetType := getPacketType(selectedDevice, packet)
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

// # 0 White others
// # 1 Red Anomaly
// # 2 Green LLDP
// # 3 Lime DNS
// # 4 Pink ICMP
// # 5 Cyan DHCP
// # 6 Purple ARP
// # 7 Orange IGMP
// # 8 Yellow UDP
// # 9 Blue TCP

// 返り値は[(受信なら0, 送信なら1), categorizePacketを参照しパケットの種類]
func getPacketType(device pcap.Interface, packet gopacket.Packet) []byte {
	packetType := []byte{1, 0}
	if isAnomaly(packet) {
		packetType[1] = 1
		fmt.Print("\x1b[31mRed\tAnomaly")
	} else if lldp := packet.Layer(layers.LayerTypeLinkLayerDiscovery); lldp != nil {
		packetType[1] = 2
		fmt.Print("\x1b[32mGreen\tLLDP")
	} else if dns := packet.Layer(layers.LayerTypeDNS); dns != nil {
		packetType[1] = 3
		fmt.Print("\x1b[32mLime\tDNS")
	} else if icmpv4 := packet.Layer(layers.LayerTypeICMPv4); icmpv4 != nil {
		packetType[1] = 4
		fmt.Print("\x1b[35mPink\tICMPv4")
	} else if icmpv6 := packet.Layer(layers.LayerTypeICMPv6); icmpv6 != nil {
		packetType[1] = 4
		fmt.Print("\x1b[35mPink\tICMPv6")
	} else if dhcpv4 := packet.Layer(layers.LayerTypeDHCPv4); dhcpv4 != nil {
		packetType[1] = 5
		fmt.Print("\x1b[36mCyan\tDHCPv4")
	} else if arp := packet.Layer(layers.LayerTypeARP); arp != nil {
		packetType[1] = 6
		fmt.Print("\x1b[35mPurple\tARP")
	} else if igmp := packet.Layer(layers.LayerTypeIGMP); igmp != nil {
		packetType[1] = 7
		fmt.Print("\x1b[33mOrange\tIGMP")
	} else if udp := packet.Layer(layers.LayerTypeUDP); udp != nil {
		packetType[1] = 8
		fmt.Print("\x1b[33mYellow\tUDP")
	} else if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
		packetType[1] = 9
		fmt.Print("\x1b[34mBlue\tTCP")
	} else {
		fmt.Print("\x1b[37mWhite\tothers")
	}
	// 送信ならpacketType[0]を1にする、受信なら0のまま
	for _, address := range device.Addresses {
		// panic: runtime error: invalid memory address or nil pointer dereference
		if nil == packet.NetworkLayer() {
			continue
		}

		if address.IP.String() == packet.NetworkLayer().NetworkFlow().Dst().String() {
			packetType[0] = 0
		}
	}

	// 送信か受信かを表示
	if packetType[0] == 0 {
		fmt.Print("\t\x1b[32mReceive")
	} else {
		fmt.Print("\t\x1b[33mSend")
	}

	// パケットのあて先と送信元を表示
	var source, destination gopacket.Endpoint
	if nil != packet.NetworkLayer() {
		source = packet.NetworkLayer().NetworkFlow().Src()
		destination = packet.NetworkLayer().NetworkFlow().Dst()
		if packetType[0] == 0 {
			fmt.Printf("\t\x1b[34m%s\t\x1b[0m%s", source, destination)
		} else {
			fmt.Printf("\t\x1b[0m%s\t\x1b[34m%s", source, destination)
		}
	}

	fmt.Println("\x1b[0m")

	return packetType
}

// シリアルポートの設定
func setSerialPort() *serial.Config {
	// シリアルポートのリストからデバイスを選択
	portList, err := getserial.GetPortsList()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Serial ports available:")

	// デバイスの一覧を表示
	for i, port := range portList {
		fmt.Printf("%d. %s\n", i, port)
	}

	// 数字を入力してもらいデバイスを選択
	var portNumber int
	var portName string
	fmt.Print("Select port number: ")
	fmt.Scan(&portNumber)
	portName = portList[portNumber]
	fmt.Println("Selected port: ", portName)

	// シリアルポートの設定
	config := &serial.Config{
		Name: portName, // デバイス名
		Baud: 9600,     // ボーレート（通信速度）を設定します
	}

	return config
}

func setNetworkDevice() pcap.Interface {
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

	return selectedDevice
}
