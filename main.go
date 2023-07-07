package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
    "github.com/tarm/serial"
)

func main() {
    // シリアルポートの設定
    config := &serial.Config{
        Name: "COM11", // シリアルポートのデバイス名（適宜変更してください）
        Baud: 9600,           // ボーレート（通信速度）を設定します
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
	deviceName = devices[deviceNumber].Name
	fmt.Println("Selected device: ", deviceName)

	// 最初のネットワークデバイスを使用してパケットキャプチャを開始
	handle, err := pcap.OpenLive(deviceName, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// パケットをキャプチャして処理
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// パケットの種類を判別して数字を返す
		packetType := getPacketType(packet)
        fmt.Println([]byte{byte(packetType)})
        _, err = port.Write([]byte{byte(packetType)})
        if err != nil {
            log.Fatal(err)
        }
	}
}

func getPacketType(packet gopacket.Packet) int {
	// パケットのレイヤーを取得
	networkLayer := packet.NetworkLayer()
	transportLayer := packet.TransportLayer()

	// パケットの種類を判別
	if networkLayer != nil && transportLayer != nil {
		switch networkLayer.LayerType() {
		case layers.LayerTypeEthernet:
			switch transportLayer.LayerType() {
			case layers.LayerTypeTCP:
				return 3 // Blue TCP
			case layers.LayerTypeUDP:
				return 6 // Yellow UDP
			}
		case layers.LayerTypeIPv4:
			switch transportLayer.LayerType() {
			case layers.LayerTypeTCP:
				return 3 // Blue TCP
			case layers.LayerTypeUDP:
				return 6 // Yellow UDP
			}
		case layers.LayerTypeIPv6:
			switch transportLayer.LayerType() {
			case layers.LayerTypeTCP:
				return 3 // Blue TCP
			case layers.LayerTypeUDP:
				return 6 // Yellow UDP
			}
		}
	} else if networkLayer != nil {
		switch networkLayer.LayerType() {
		case layers.LayerTypeEthernet:
			return 0 // White others
		case layers.LayerTypeIPv4:
			return 0 // White others
		case layers.LayerTypeIPv6:
			return 0 // White others
		}
	}

	return 0 // サポートされていないパケットタイプ
}
