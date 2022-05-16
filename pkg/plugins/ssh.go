package plugins

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/404tk/lazyscan/common"
	"golang.org/x/crypto/ssh"
)

func SshScan(info *common.HostInfo) (tmperr error) {
	starttime := time.Now().Unix()
	for _, user := range info.Usernames {
		for _, pass := range info.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := SshConn(info, user, pass)
			if flag == true && err == nil {
				return err
			} else {
				if time.Now().Unix()-starttime > (int64(len(info.Usernames)*len(info.Passwords)) * info.Timeout) {
					return err
				}
			}
		}
	}
	return tmperr
}

func SshConn(info *common.HostInfo, user, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Port, user, pass
	Auth := []ssh.AuthMethod{ssh.Password(Password)}

	config := &ssh.ClientConfig{
		User:    Username,
		Auth:    Auth,
		Timeout: time.Duration(info.Timeout) * time.Second,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(info.Timeout))
	defer cancel()
	// client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", Host, Port), config)
	client, err := dial(ctx, "tcp", fmt.Sprintf("%v:%v", Host, Port), config)
	if err == nil {
		defer client.Close()
		session, err := client.NewSession()
		if err == nil {
			defer session.Close()
			flag = true
			result := fmt.Sprintf("[%s:%s] SSH credential %s/%s", Host, Port, Username, Password)
			log.Println(result)
			if info.Queue != nil {
				info.Queue.Push(result)
			}
			cmd := info.Command.UnixCommand
			session.Run(cmd)
		}
	}
	return flag, err

}

func dial(ctx context.Context, network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	d := net.Dialer{Timeout: config.Timeout}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}
