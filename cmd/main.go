package main

import (
	"context"
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
	flag.StringVar(&options.Token, "token", "", "K8s api-server token")
	flag.BoolVar(&options.NoPing, "np", false, "not to ping")
	flag.StringVar(&options.Scantype, "m", "", "Select scan type ,as: -m etcd")
	flag.Int64Var(&options.Timeout, "time", 3, "Set timeout")
	flag.IntVar(&options.Threads, "t", 600, "Thread nums")
	flag.IntVar(&options.LiveTop, "top", 10, "show live len top")
	flag.StringVar(&options.Password, "pwd", "", "custom password")
	flag.BoolVar(&options.RedisListen, "rl", false, "Default not start redis rogue server")
	flag.StringVar(&options.RedisRogueServer, "rs", "", "redis rogue server, -rs 192.168.1.2:6380")
	flag.Parse()

	return options
}

func main() {
	options := parseOptions()
	runner, err := runner.New(options)
	if err != nil {
		return
	}
	runner.Run(context.TODO(), nil)
}
