package common

import "github.com/404tk/lazyscan/common/queue"

type HostInfo struct {
	Host             string
	Port             string
	IfTlS            bool
	Timeout          int64
	Usernames        []string
	Passwords        []string
	Token            string
	Command          Command
	RedisRogueServer string
	Queue            *queue.Queue
}

type Command struct {
	UnixCommand string
	TCPCommand  string
	WinCommand  string
}

var Userdict = map[string][]string{
	"mysql":      {"root"},
	"ssh":        {"root"},
	"mssql":      {"sa"},
	"postgresql": {"postgres"},
}

var Passwords = []string{"123456", "{user}", "{user}@123"}

var DefaultPorts = "22,1433,2375,2379,3306,5432,6379,6443"

var PortList = map[string]string{
	"ssh":           "22",
	"mssql":         "1433",
	"docker-remote": "2375",
	"etcd":          "2379",
	"mysql":         "3306",
	"postgresql":    "5432",
	"redis":         "6379",
	"kube-api":      "6443",
	"all":           "0",
}
