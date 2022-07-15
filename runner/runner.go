package runner

import (
	"context"
	"errors"
	"log"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/404tk/lazyscan/common"
	"github.com/404tk/lazyscan/common/queue"
	"github.com/404tk/lazyscan/common/utils"
	"github.com/404tk/lazyscan/pkg"
	"github.com/404tk/lazyscan/pkg/schema"
)

type Options struct {
	Host             string
	HostFile         string
	Ports            string
	Token            string
	NoPing           bool
	Scantype         string
	Timeout          int64
	Threads          int
	LiveTop          int
	Password         string
	Downloader       common.Downloader
	RedisListen      bool
	RedisRogueServer string
	Userdict         map[string][]string
	Passwords        []string
	PortList         map[string]string
	Accounts         []string
	Pocs             []string
}

type Output struct {
	AliveHosts []string
	AlivePorts []string
}

func New(opt *Options) (*Options, error) {
	if !ParseInput(opt) {
		return opt, errors.New("Host is none.")
	}
	if !ParseScantype(opt) {
		return opt, errors.New("ScanType error!")
	}
	ParsePass(opt)
	ParseAccount(opt)
	ParsePocs(opt)
	return opt, nil
}

func (opt *Options) Run(ctx context.Context, resultQueue *queue.Queue) (result Output) {
	scanctx, cancel := context.WithCancel(context.Background())
	go opt.Enumerate(scanctx, cancel, resultQueue, &result)
	for {
		select {
		case <-scanctx.Done():
			return
		case <-ctx.Done():
			log.Println("scan task is forcibly stop.")
			return
		default:
			time.Sleep(1000 * time.Microsecond)
		}
	}
}

func (opt *Options) Enumerate(ctx context.Context, cancel context.CancelFunc, resultQueue *queue.Queue, result *Output) {
	log.Println("Start infoscan...")
	Hosts, err := utils.ParseIP(opt.Host, opt.HostFile)
	if err != nil {
		log.Printf("Parse IP ERROR: %s\n", err)
		cancel()
		return
	}
	var ch = make(chan struct{}, opt.Threads)
	var wg = sync.WaitGroup{}
	if opt.NoPing == false {
		Hosts = schema.CheckLive(Hosts, opt.LiveTop)
		log.Printf("icmp alive hosts num is: %d\n", len(Hosts))
	}
	var AlivePorts []string
	if len(Hosts) > 0 {
		AlivePorts = schema.PortScan(Hosts, opt.Ports, opt.Timeout, opt.Threads)
		log.Printf("open ports num is: %d\n", len(AlivePorts))
		if len(AlivePorts) > 0 {
			cmds := common.Command{
				UnixCommand: utils.GenerateCMD("unix", opt.Downloader),
				TCPCommand:  utils.GenerateCMD("tcp", opt.Downloader),
				WinCommand:  utils.GenerateCMD("win", opt.Downloader),
			}
			if opt.RedisListen {
				go opt.RunRedisRogueServer()
				time.Sleep(1 * time.Second)
			}
			log.Println("start vulscan...")
			for _, targetIP := range AlivePorts {
				var info = common.HostInfo{
					Host:             strings.Split(targetIP, ":")[0],
					Port:             strings.Split(targetIP, ":")[1],
					Token:            opt.Token,
					Passwords:        opt.Passwords,
					Pocs:             opt.Pocs,
					Timeout:          opt.Timeout,
					Command:          cmds,
					RedisRogueServer: opt.RedisRogueServer,
					Queue:            resultQueue,
				}
				if opt.Scantype == "" {
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
	result.AliveHosts = Hosts
	result.AlivePorts = AlivePorts
	wg.Wait()
	log.Println("scan end.")
	cancel()
}

func addScan(scantype string, info common.HostInfo, ch chan struct{}, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		scanFunc(pkg.PluginList, scantype, &info)
		<-ch
		wg.Done()
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
