package webscan

import (
	"embed"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/404tk/lazyscan/common"
	"github.com/404tk/lazyscan/pkg/webscan/lib"
)

type PocInfo struct {
	Num     int
	Timeout int64
	Target  string
}

//go:embed pocs
var Pocs embed.FS
var once sync.Once
var AllPocs []*lib.Poc

func WebScan(info *common.HostInfo) {
	var num = 20 // 默认限制并发20
	lib.Inithttp(num, info.Timeout)
	once.Do(initpoc)
	Execute(info, num)
}

func Execute(info *common.HostInfo, num int) {
	req, err := http.NewRequest("GET", info.Url, nil)
	if err != nil {
		errlog := fmt.Sprintf("[-] webpocinit %v %v", info.Url, err)
		log.Println(errlog)
		return
	}
	req.Header.Set("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
	lib.CheckMultiPoc(req, AllPocs, num, info)
}

func initpoc() {
	entries, err := Pocs.ReadDir("pocs")
	if err != nil {
		log.Printf("[-] init poc error: %v\n", err)
		return
	}
	for _, one := range entries {
		path := one.Name()
		if strings.HasSuffix(path, ".yaml") {
			if poc, _ := lib.LoadPoc(path, Pocs); poc != nil {
				AllPocs = append(AllPocs, poc)
			}
		}
	}
}
