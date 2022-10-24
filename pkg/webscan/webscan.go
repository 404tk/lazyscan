package webscan

import (
	"embed"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/404tk/lazyscan/common"
	"github.com/404tk/lazyscan/common/utils"
	"github.com/404tk/lazyscan/pkg/webscan/lib"
)

type PocInfo struct {
	Num     int
	Timeout int64
	Target  string
}

//go:embed pocs
var Pocs embed.FS
var DefaultPocs []*lib.Poc
var AllPocs []*lib.Poc

func WebScan(info *common.HostInfo) {
	var num = 20 // 默认限制并发20
	lib.Inithttp(num, info.Timeout)
	Execute(info, AllPocs, num)
}

func Execute(info *common.HostInfo, allPocs []*lib.Poc, num int) {
	req, err := http.NewRequest("GET", info.Url, nil)
	if err != nil {
		errlog := fmt.Sprintf("[-] webpocinit %v %v", info.Url, err)
		log.Println(errlog)
		return
	}
	req.Header.Set("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
	lib.CheckMultiPoc(req, allPocs, num, info)
}

func InitDefaultPoc() []*lib.Poc {
	var defaultPocs []*lib.Poc
	var defaultPocLen int
	entries, err := Pocs.ReadDir("pocs")
	if err != nil {
		log.Printf("[-] init defaultPoc error: %v\n", err)
		return defaultPocs
	}
	for _, one := range entries {
		path := one.Name()
		if strings.HasSuffix(path, ".yaml") {
			if poc, _ := lib.LoadPoc(path, Pocs); poc != nil {
				defaultPocs = append(defaultPocs, poc)
				defaultPocLen++
			}
		}
	}
	log.Printf("init defaultPoc Success : %d", defaultPocLen)
	return defaultPocs
}

func LoadAllpocs(defaultPocsName, customPocs []string) []*lib.Poc {
	var defaultPocLen, customPocLen int
	var allPocs []*lib.Poc
	if len(defaultPocsName) == 1 && defaultPocsName[0] == "all" {
		allPocs = append(allPocs, DefaultPocs...)
		defaultPocLen = len(allPocs)
	} else {
		for _, defaultPoc := range DefaultPocs {
			if utils.IsContain(defaultPocsName, defaultPoc.Name) {
				allPocs = append(allPocs, defaultPoc)
				defaultPocLen++
			}
		}
	}

	if len(customPocs) > 0 {
		for _, customPocStr := range customPocs {
			customPoc, err := lib.LoadPocStr(customPocStr)
			if err != nil {
				continue
			}
			allPocs = append(allPocs, customPoc)
			customPocLen++
		}
	}
	log.Printf("Load Poc Success defaultPoc: %d, customPoc: %d", defaultPocLen, customPocLen)
	return allPocs
}
