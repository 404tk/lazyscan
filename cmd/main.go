package main

import (
	"flag"

	"github.com/404tk/lazyscan/common"
	"github.com/404tk/lazyscan/runner"
)

func parseOptions() *runner.Options {
	// 优先配置Downloader，否则无法利用
	options := &runner.Options{
		Downloader: common.DefaultDownloader,
	}
	flag.StringVar(&options.Host, "h", "", "IP address or cidr")
	flag.StringVar(&options.HostFile, "hf", "", "host file, -hf ip.txt")
	flag.StringVar(&options.Ports, "p", "", "Select a port")
	flag.BoolVar(&options.NoPing, "np", false, "not to ping")
	flag.StringVar(&options.Scantype, "m", "", "Select scan type ,as: -m etcd")
	flag.Int64Var(&options.Timeout, "time", 3, "Set timeout")
	flag.IntVar(&options.Threads, "t", 600, "Thread nums")
	flag.IntVar(&options.LiveTop, "top", 10, "show live len top")
	flag.StringVar(&options.Password, "pwd", "", "custom password")
	flag.StringVar(&options.RedisRogueServer, "rs", "", "redis rogue server, -rs 192.168.1.2:6380")
	flag.Parse()

	return options
}

func main() {
	options := parseOptions()
	runner := runner.New(options)
	runner.Enumerate(nil)
}
