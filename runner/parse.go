package runner

import (
	"log"
	"strings"

	"github.com/404tk/lazyscan/common"
	"github.com/404tk/lazyscan/common/utils"
)

func ParseScantype(opt *Options) bool {
	if len(opt.PortList) == 0 {
		opt.PortList = common.PortList
	}
	if opt.Ports != "" {
		return true
	}
	if opt.Scantype != "" {
		port, ok := opt.PortList[opt.Scantype]
		if !ok {
			log.Printf("The specified scan type does not exist: %s\n", opt.Scantype)
			return false
		}
		opt.Ports = port
		log.Printf("Start scan the port: %s\n", opt.Ports)
	} else {
		var ports []string
		for _, p := range opt.PortList {
			ports = append(ports, p)
		}
		opt.Ports = strings.Join(ports, ",")
	}
	return true
}

func ParseInput(opt *Options) bool {
	if opt.Host == "" && opt.HostFile == "" {
		log.Println("Host is none.")
		return false
	}
	return true
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

func ParsePocs(opt *Options) {
	for _, customPoc := range opt.CustomPocs {
		if customPoc != "" && !utils.IsContain(opt.CustomPocs, customPoc) {
			opt.CustomPocs = append(opt.CustomPocs, customPoc)
		}
	}
	for _, defaultPocName := range opt.DefaultPocsName {
		if defaultPocName != "" && !utils.IsContain(opt.DefaultPocsName, defaultPocName) {
			opt.DefaultPocsName = append(opt.DefaultPocsName, defaultPocName)
		}
	}
	if opt.Poc != "" && !utils.IsContain(opt.DefaultPocsName, opt.Poc) {
		opt.DefaultPocsName = append(opt.DefaultPocsName, opt.Poc)
	}
}
