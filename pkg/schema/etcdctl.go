package schema

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/tidwall/gjson"
)

type EtcdRequestOption struct {
	Endpoint  string
	Api       string
	Method    string
	PostData  string
	TlsConfig *tls.Config
	Silent    bool
}

func EtcdRequest(opt EtcdRequestOption) (string, error) {
	// http client
	if opt.TlsConfig == nil || len(opt.TlsConfig.Certificates) == 0 || opt.TlsConfig.RootCAs == nil {
		opt.TlsConfig = &tls.Config{InsecureSkipVerify: true}
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: opt.TlsConfig,
		},
		Timeout: time.Duration(5) * time.Second,
	}

	request, err := http.NewRequest(opt.Method, opt.Endpoint+opt.Api, bytes.NewBuffer([]byte(opt.PostData)))
	if err != nil {
		return "", errors.New("err found while generate post request in net.http: " + err.Error())
	}
	if opt.Method == "POST" {
		request.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(request)
	if resp != nil {
		defer resp.Body.Close()
	} else if err != nil {
		return "", errors.New("err found in post request: " + err.Error())
	}

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.New("err found in post request: " + err.Error())
	}

	return string(content), nil
}

func GetKeys(content string, silent bool) (map[string]string, error) {
	kvs := gjson.Get(content, "kvs").Array()
	ret := make(map[string]string, len(kvs))
	for _, k := range kvs {
		name, err := base64.StdEncoding.DecodeString(k.Get("key").String())
		if err != nil {
			log.Println("base64 decode failed:", err.Error())
			continue
		}

		ret[string(name)] = ""
		if !silent {
			log.Println(string(name))
		}

		if k.Get("value").Exists() {
			v, _ := base64.StdEncoding.DecodeString(k.Get("value").String())
			if !silent {
				fmt.Println(string(v))
			}
			ret[string(name)] = string(v)
		}
	}
	return ret, nil
}

func GenerateQuery(key string) (query string) {
	b64key := base64.StdEncoding.EncodeToString([]byte(strings.TrimSuffix(key, "\n")))
	if key == "/" {
		bzero := base64.StdEncoding.EncodeToString([]byte{0})
		query = fmt.Sprintf("{\"range_end\": \"%s\", \"key\": \"%s\", \"keys_only\":true}", bzero, b64key)
	} else {
		query = fmt.Sprintf("{\"key\": \"%s\"}", b64key)
	}
	return
}

func GetVersion(endpoint string) (string, error) {
	opt := EtcdRequestOption{
		Endpoint: endpoint,
		Api:      "/version",
		Method:   "GET",
	}
	resp, err := EtcdRequest(opt)
	if err != nil {
		return "", err
	}
	v := gjson.Get(resp, "etcdserver").String()
	return v, nil
}
