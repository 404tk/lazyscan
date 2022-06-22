package schema

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
)

type K8sRequestOption struct {
	Endpoint  string
	Token     string
	Api       string
	Method    string
	PostData  string
	Anonymous bool
}

func ServerAccountRequest(opts K8sRequestOption) (string, error) {
	// parse token
	if opts.Anonymous {
		opts.Token = ""
	}

	// http client
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	var request *http.Request
	opts.Method = strings.ToUpper(opts.Method)

	request, err := http.NewRequest(opts.Method, opts.Endpoint+opts.Api, bytes.NewBuffer([]byte(opts.PostData)))
	if err != nil {
		return "", errors.New("err found while generate post request in net.http: " + err.Error())
	}

	// set request header
	if opts.Method == "POST" {
		request.Header.Set("Content-Type", "application/json")
	}
	// auth token
	if len(opts.Token) > 0 {
		token := strings.TrimSpace(opts.Token)
		request.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(request)
	if err != nil {
		return "", errors.New("err found in post request: " + err.Error())
	}
	//defer resp.Body.Close()

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.New("err found in post request: " + err.Error())
	}

	return string(content), nil
}
