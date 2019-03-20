package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"flag"
	"time"
	"./mysql"
	"./redis"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// 将SQL语句写入log文件
func writeLog(s []byte) {
	if "" == string(s) {
		return
	}
	fd, _ := os.OpenFile("sql.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	var buffer bytes.Buffer
	buffer.Write([]byte(time.Now().Format("2006-01-02 15:04:05") + " |"))
	buffer.Write(s)
	buffer.Write([]byte("\n"))
	fd.Write(buffer.Bytes())
	fd.Close()
	fmt.Println(buffer.String())
}

var (
	snapshot_len int32 = 1024
	promiscuous  bool  = false
	err          error
	timeout      time.Duration = 30 * time.Second
	dev          *bool         = flag.Bool("dev", false, "device list")
	p            *int          = flag.Int("p", 0, "listening port")
)
type Runner interface {
	GetIP(tcp *layers.TCP, ip *layers.IPv4) (string,bool)
	GetContent(tcp *layers.TCP) string
}

func main() {

	flag.Parse()
	if *dev {
		interfaces, err := net.Interfaces()
		if err != nil {
			log.Fatal(err)
		}
		for _, i := range interfaces {
			fmt.Println(i.Name)
		}
		return
	}
	if len(os.Args) < 3 {
		log.Fatal("sniffer [device] [type] ")
	}
	
	device := os.Args[1]
	dbtype := os.Args[2]

	RunnerMap:=map[string]Runner{"redis":redis.RedisRunner{},"mysql":mysql.MySQLRunner{}}
	if _, ok :=RunnerMap[dbtype]; !ok{
		log.Fatal("only support redis and mysql")
	}

	// 打开网口设备
	handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}

	// 设置过滤器
	filter := fmt.Sprintf("tcp and port %d", *p)
	if 0 == *p {
		filter = "tcp"
	}

	if err := handle.SetBPFFilter(filter); err != nil {
		fmt.Printf("set bpf filter failed: %v", err)
		return
	}else{
		fmt.Println(filter)
	}
	defer handle.Close()


	ipAddr := ""
	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		ip, _ := ipLayer.(*layers.IPv4)

		// tcp 层
		tcp := packet.TransportLayer().(*layers.TCP)

		if ipAddr == "" {
			if addr, ok := RunnerMap[dbtype].GetIP(tcp, ip); ok{
				ipAddr = addr
			} else {
				continue
			}
		}

		if ip.DstIP.String() == ipAddr {
			content := RunnerMap[dbtype].GetContent(tcp)
			writeLog([]byte(content))
		}
	}

}
