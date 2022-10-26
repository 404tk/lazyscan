package common

import "github.com/404tk/lazyscan/common/queue"

type HostInfo struct {
	Host             string
	Port             string
	Url              string
	DisableExp       bool
	Timeout          int64
	Usernames        []string
	Passwords        []string
	Token            string
	Hash             string
	Command          string
	Commands         Commands
	RedisRogueServer string
	Queue            *queue.Queue
}

type Commands struct {
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
	Host    string
	Port    string
	Unauth  bool
	User    string
	Pass    string
	Token   string
	Hash    string
	PocName string
}
