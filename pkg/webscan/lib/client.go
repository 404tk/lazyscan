package lib

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"time"
)

var (
	Client           *http.Client
	ClientNoRedirect *http.Client
	dialTimout       = 5 * time.Second
	keepAlive        = 5 * time.Second
)

func Inithttp(num int, timeout int64) {
	err := InitHttpClient(num, time.Duration(timeout)*time.Second)
	if err != nil {
		log.Fatal(err)
	}
}

func InitHttpClient(ThreadsNum int, Timeout time.Duration) error {
	type DialContext = func(ctx context.Context, network, addr string) (net.Conn, error)
	dialer := &net.Dialer{
		Timeout:   dialTimout,
		KeepAlive: keepAlive,
	}

	tr := &http.Transport{
		DialContext:         dialer.DialContext,
		MaxConnsPerHost:     5,
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: ThreadsNum * 2,
		IdleConnTimeout:     keepAlive,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout: 5 * time.Second,
		DisableKeepAlives:   false,
	}

	Client = &http.Client{
		Transport: tr,
		Timeout:   Timeout,
	}
	ClientNoRedirect = &http.Client{
		Transport:     tr,
		Timeout:       Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	return nil
}
