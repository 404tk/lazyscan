package plugins

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/404tk/lazyscan/common"
	"github.com/404tk/lazyscan/pkg/webscan"
)

func WebVulnScan(info *common.HostInfo) {
	switch info.Port {
	case "80":
		info.Url = fmt.Sprintf("http://%s", info.Host)
	case "443":
		info.Url = fmt.Sprintf("https://%s", info.Host)
	default:
		host := fmt.Sprintf("%s:%s", info.Host, info.Port)
		protocol := GetProtocol(host, info.Timeout)
		info.Url = fmt.Sprintf("%s://%s:%s", protocol, info.Host, info.Port)
	}
	webscan.WebScan(info)
}

func GetProtocol(host string, Timeout int64) string {
	socksconn, err := WrapperTcpWithTimeout("tcp", host, time.Duration(Timeout)*time.Second)
	if err != nil {
		return "http"
	}
	conn := tls.Client(socksconn, &tls.Config{InsecureSkipVerify: true})
	defer func() {
		if conn != nil {
			defer func() {
				if err := recover(); err != nil {
					log.Println(err)
				}
			}()
			conn.Close()
		}
	}()
	conn.SetDeadline(time.Now().Add(time.Duration(Timeout) * time.Second))
	err = conn.Handshake()
	if err == nil || strings.Contains(err.Error(), "handshake failure") {
		return "https"
	}

	return "http"
}

func WrapperTcpWithTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
