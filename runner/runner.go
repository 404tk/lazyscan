package runner

import (
	"errors"
	"log"
	"reflect"
	"strings"
	"sync"

	"github.com/404tk/lazyscan/common"
	"github.com/404tk/lazyscan/common/utils"
	"github.com/404tk/lazyscan/pkg"
	"github.com/404tk/lazyscan/pkg/schema"
)

type Options struct {
	Host             string
	HostFile         string
	Ports            string
	NoPing           bool
	Scantype         string
	Timeout          int64
	Threads          int
	LiveTop          int
	Password         string
	HTTPDownloadAddr string
	TCPDownloadAddr  string
	FileName         string
	ExecCommand      string
	RedisRogueServer string
	Userdict         map[string][]string
	Passwords        []string
	PortList         map[string]string
}

func New(opt *Options) *Options {
	ParseScantype(opt)
	ParseInput(opt)
	ParsePass(opt)
	return opt
}

func (opt *Options) Enumerate() {
	log.Println("Start infoscan...")
	Hosts, err := utils.ParseIP(opt.Host, opt.HostFile)
	if err != nil {
		log.Fatalf("Parse IP ERROR: %s\n", err)
	}
	var ch = make(chan struct{}, opt.Threads)
	var wg = sync.WaitGroup{}
	if opt.NoPing == false {
		Hosts = schema.CheckLive(Hosts, opt.LiveTop)
		log.Printf("icmp alive hosts num is: %d\n", len(Hosts))
	}
	if len(Hosts) > 0 {
		AlivePorts := schema.PortScan(Hosts, opt.Ports, opt.Timeout, opt.Threads)
		log.Printf("open ports num is: %d\n", len(AlivePorts))
		if len(AlivePorts) > 0 {
			log.Println("start vulscan...")
			cmds := common.Command{
				UnixCommand: utils.GenerateCMD("unix", opt.HTTPDownloadAddr, opt.FileName, opt.ExecCommand),
				TCPCommand:  utils.GenerateCMD("tcp", opt.TCPDownloadAddr, opt.FileName, opt.ExecCommand),
				WinCommand:  utils.GenerateCMD("win", opt.HTTPDownloadAddr, opt.FileName, opt.ExecCommand),
			}
			for _, targetIP := range AlivePorts {
				var info = common.HostInfo{
					Host:             strings.Split(targetIP, ":")[0],
					Port:             strings.Split(targetIP, ":")[1],
					Passwords:        opt.Passwords,
					Timeout:          opt.Timeout,
					Command:          cmds,
					RedisRogueServer: opt.RedisRogueServer,
				}
				if opt.Scantype == "all" {
					m := opt.getService(info.Port)
					if m != "" {
						info.Usernames = opt.Userdict[m]
						addScan(m, info, ch, &wg) //plugins scan
					}
				} else {
					info.Usernames = opt.Userdict[opt.Scantype]
					addScan(opt.Scantype, info, ch, &wg)
				}
			}
		}
	}
	wg.Wait()
	log.Println("scan end.")
}

func addScan(scantype string, info common.HostInfo, ch chan struct{}, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		scanFunc(pkg.PluginList, scantype, &info)
		wg.Done()
		<-ch
	}()
	ch <- struct{}{}
}

func scanFunc(m map[string]interface{}, name string, infos ...interface{}) (result []reflect.Value, err error) {
	f := reflect.ValueOf(m[name])
	if len(infos) != f.Type().NumIn() {
		err = errors.New("The number of infos is not adapted ")
		log.Println(err.Error())
		return result, err
	}
	in := make([]reflect.Value, len(infos))
	for k, info := range infos {
		in[k] = reflect.ValueOf(info)
	}
	result = f.Call(in)
	return result, nil
}

func (opt *Options) getService(port string) string {
	for k, v := range opt.PortList {
		if utils.IsContain(strings.Split(v, ","), port) {
			return k
		}
	}
	return ""
}
