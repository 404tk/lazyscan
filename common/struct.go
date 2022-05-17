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

type Downloader struct {
	WinHTTP  Loader
	UnixHTTP Loader
	UnixTCP  Loader
}

type Loader struct {
	Addr        string
	FileName    string
	ExecCommand string
}

type Vuln struct {
	Host   string
	Port   string
	Unauth bool
	User   string
	Pass   string
	Token  string
}
