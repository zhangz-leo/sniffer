package mysql

import (
	"github.com/google/gopacket/layers"
)

type MySQLRunner struct {

}

func (m MySQLRunner) GetIP(tcp *layers.TCP, ip *layers.IPv4) (string,bool){
		// 前三个字节是消息长度，第四个字节是序号，第五个字节是消息类型
		// 消息类型为3，表示这是一个SQL查询请求
		if len(tcp.Payload) >= 4 && 3 == tcp.Payload[4] {
			return ip.DstIP.String(), true
		}else{
			return "", false
		}
}


func (m MySQLRunner) GetContent(tcp *layers.TCP) string{
	if len(tcp.Payload) >= 4 && 3 == tcp.Payload[4] {
		return string(tcp.Payload[5:])
	}
	return ""
}