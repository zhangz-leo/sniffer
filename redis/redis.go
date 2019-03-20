package redis

import (
	"github.com/google/gopacket/layers"
	"strings"
)

type RedisRunner struct {

}

func (r RedisRunner) GetIP(tcp *layers.TCP, ip *layers.IPv4) (string,bool){
	//请求的第一个字节是*
	//回复的第一个字节是*、+、-、:、$
	//所以首字符是以下四种的，一定是服务器的回复
	sign := map[string]string{"+": "", "-": "", ":": "", "$": ""}
	if _, ok := sign[string(tcp.Payload[0])]; ok {
		return ip.SrcIP.String(), true
	} else {
		return "", false
	}
}

func (r RedisRunner) GetContent(tcp *layers.TCP) string{
		sql := []string{}
		command := strings.Split(string(tcp.Payload), "\r\n")
		for i := 2; i < len(command)-1; i += 2 {
			sql = append(sql, command[i])
		}
		return strings.Join(sql, " ")


}