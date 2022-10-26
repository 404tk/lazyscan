package plugins

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	"github.com/404tk/lazyscan/common"
	"github.com/404tk/lazyscan/pkg/schema/wmiexec"
)

func WMIScan(info *common.HostInfo) error {
	starttime := time.Now().Unix()
	target := fmt.Sprintf("%s:%s", info.Host, info.Port)
	hostname := RandHostName()
	for _, user := range info.Usernames {
		if info.Hash != "" {
			cfg, err := wmiexec.NewExecConfig(user, "", info.Hash, "", target, hostname)
			if err != nil {
				return err
			}
			flag, err := WMIAuth(info, cfg)
			if flag {
				result := fmt.Sprintf("[%s:%s] WMI credential %s/%s", info.Host, info.Port, user, info.Hash)
				log.Println(result)
				if info.Queue != nil {
					vuln := common.Vuln{
						Host: info.Host,
						Port: info.Port,
						User: user,
						Hash: info.Hash,
					}
					info.Queue.Push(vuln)
				}
			}
			return err
		}

		for _, pass := range info.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			cfg, err := wmiexec.NewExecConfig(user, pass, "", "", target, hostname)
			if err != nil {
				return err
			}
			flag, err := WMIAuth(info, cfg)
			if flag {
				result := fmt.Sprintf("[%s:%s] WMI credential %s/%s", info.Host, info.Port, user, pass)
				log.Println(result)
				if info.Queue != nil {
					vuln := common.Vuln{
						Host: info.Host,
						Port: info.Port,
						User: user,
						Pass: pass,
					}
					info.Queue.Push(vuln)
				}
				return err
			} else {
				if time.Now().Unix()-starttime > (int64(len(info.Usernames)*len(info.Passwords)) * info.Timeout) {
					return err
				}
			}
		}
	}
	return nil
}

func WMIAuth(info *common.HostInfo, cfg wmiexec.WmiExecConfig) (bool, error) {
	execer := wmiexec.NewExecer(&cfg)
	err := execer.SetTargetBinding("", info.Timeout)
	if err != nil {
		return false, err
	}

	err = execer.Auth(info.Timeout)
	if err != nil {
		return false, err
	}

	if info.DisableExp && info.Command == "" {
		return true, err
	}

	var cmd string
	if !info.DisableExp {
		cmd = fmt.Sprintf("C:\\Windows\\system32\\cmd.exe /c \"%s\"", info.Commands.WinCommand)
	} else {
		cmd = fmt.Sprintf("C:\\Windows\\system32\\cmd.exe /c \"%s\"", info.Command)
	}
	if execer.TargetRPCPort == 0 {
		return true, errors.New("RPC Port is 0, cannot connect")
	}
	err = execer.RPCConnect(info.Timeout)
	if err != nil {
		return true, err
	}
	err = execer.Exec(cmd)

	return true, err
}

func RandHostName() string {
	rand.Seed(time.Now().UnixNano())
	digits := "0123456789"
	specials := "-"
	all := "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		digits + specials
	length := 16
	buf := make([]byte, length)
	buf[0] = digits[rand.Intn(len(digits))]
	buf[1] = specials[rand.Intn(len(specials))]
	for i := 2; i < length; i++ {
		buf[i] = all[rand.Intn(len(all))]
	}
	rand.Shuffle(len(buf), func(i, j int) {
		buf[i], buf[j] = buf[j], buf[i]
	})
	return string(buf) // E.g. "3i[g0|)z"
}
