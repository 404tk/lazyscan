package runner

import (
	"log"
	"strings"

	"github.com/404tk/lazyscan/common"
	"github.com/404tk/lazyscan/common/utils"
)

func ParseScantype(opt *Options) {
	if len(opt.PortList) == 0 {
		opt.PortList = common.PortList
	}
	port, ok := opt.PortList[opt.Scantype]
	if !ok {
		log.Fatalf("The specified scan type does not exist: %s\n", opt.Scantype)
	}
	if opt.Scantype != "all" {
		opt.Ports = port
		log.Printf("Start scan the port: %s\n", opt.Ports)
	}
}

func ParseInput(opt *Options) {
	if opt.Host == "" && opt.HostFile == "" {
		log.Fatalf("Host is none.\n")
	}
}

func ParsePass(opt *Options) {
	if opt.Password != "" {
		pwds := strings.Split(opt.Password, ",")
		for _, pass := range pwds {
			if pass != "" && !utils.IsContain(opt.Passwords, pass) {
				opt.Passwords = append(opt.Passwords, pass)
			}
		}
	}
	if len(opt.Userdict) == 0 {
		opt.Userdict = common.Userdict
	}
	if len(opt.Passwords) == 0 {
		opt.Passwords = common.Passwords
	}
}

func ParseAccount(opt *Options) {
	if len(opt.Accounts) > 0 {
		for _, account := range opt.Accounts {
			acc := strings.Split(account, "/")
			if len(acc) == 2 {
				if !utils.IsContain(opt.Passwords, acc[1]) {
					opt.Passwords = append(opt.Passwords, acc[1])
				}
				for k, v := range opt.Userdict {
					if !utils.IsContain(v, acc[0]) {
						opt.Userdict[k] = append(v, acc[0])
					}
				}
			}
		}
	}
}
