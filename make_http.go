package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"

	dns "main/dns"

	"golang.org/x/net/http2"
)

const MimeType = "application/dns-message"

var queryPaths = []string{"dns-query", "resolve", "", "doh"}

type HTTPResult struct {
	question_name string
	query_host    string
	answers       []dns.RR
}

func makeHTTP11Request(sslConn *tls.Conn, ip string, host string, path string, question_name string, carry_path bool) (*dns.Msg, error, string) {

	// 创建支持HTTP/1.1的http.Transport，并使用tlsConn
	transport1 := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return sslConn, nil
		},
		TLSClientConfig:        &tls.Config{},
		TLSHandshakeTimeout:    0,
		DisableKeepAlives:      false,
		DisableCompression:     false,
		MaxIdleConns:           0,
		MaxIdleConnsPerHost:    0,
		MaxConnsPerHost:        0,
		IdleConnTimeout:        0,
		ResponseHeaderTimeout:  0,
		ExpectContinueTimeout:  0,
		TLSNextProto:           map[string]func(authority string, c *tls.Conn) http.RoundTripper{},
		ProxyConnectHeader:     map[string][]string{},
		MaxResponseHeaderBytes: 0,
		WriteBufferSize:        0,
		ReadBufferSize:         0,
		ForceAttemptHTTP2:      false,
	}

	client1 := &http.Client{
		Transport: transport1,
	}

	return requestSend(ip, host, path, question_name, carry_path, client1, "1")
}

func NewRequest(method string, m *dns.Msg, ip string, path string) (*http.Request, error) {
	buf, err := m.Pack()
	if err != nil {
		return nil, err
	}

	ip = fmt.Sprintf("https://%s", ip)

	Path := path

	switch method {
	case http.MethodGet:
		b64 := base64.RawURLEncoding.EncodeToString(buf)

		req, err := http.NewRequest(
			http.MethodGet,
			fmt.Sprintf("%s/%s?dns=%s", ip, Path, b64),
			nil,
		)
		if err != nil {
			return req, err
		}

		req.Header.Set("content-type", MimeType)
		req.Header.Set("accept", MimeType)
		return req, nil

	case http.MethodPost:
		req, err := http.NewRequest(
			http.MethodPost,
			fmt.Sprintf("%s/%s", ip, Path),
			bytes.NewReader(buf),
		)
		if err != nil {
			return req, err
		}

		req.Header.Set("content-type", MimeType)
		req.Header.Set("accept", MimeType)
		return req, nil

	default:
		return nil, fmt.Errorf("method not allowed: %s", method)
	}
}

func requestSend(ip string, host string, path string,
	question_name string, carry_path bool,
	client *http.Client, indicator string) (*dns.Msg, error, string) {

	var log_info string
	msg := new(dns.Msg)
	msg.SetQuestion(question_name, dns.TypeA)

	if carry_path {
		newrequest, _ := NewRequest(http.MethodPost, msg, host, path)
		resp, err := client.Do(newrequest)
		if err != nil {
			log_info = fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%s\t%s", ip, host, "error", 0, "", "h"+indicator, err)
			defer client.CloseIdleConnections()
			return nil, err, log_info
		}

		defer client.CloseIdleConnections()
		r, err := ResponseToMsg(resp)
		defer resp.Body.Close()
		if err != nil {
			log_info = fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%s\t%s", ip, host, "parse error", 0, "", "h"+indicator, err)
			return nil, err, log_info
		} else {
			if r.Answer != nil {
				log_info = fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%s\t%s", ip, host, "success", 0, "", "h"+indicator, "")
			} else {
				log_info = fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%s\t%s", ip, host, "empty", 0, "", "h"+indicator, "")
			}
			return r, err, log_info
		}
	} else {
		// enumerate all provided paths
		for index, query := range queryPaths {
			newrequest, _ := NewRequest(http.MethodPost, msg, host, query)
			resp, err := client.Do(newrequest)
			if err != nil {
				log_info = fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%s\t%s", ip, host, "error", index, "", "h"+indicator, err)
				defer client.CloseIdleConnections()
				return nil, err, log_info
			}

			defer client.CloseIdleConnections()
			r, err := ResponseToMsg(resp)
			defer resp.Body.Close()
			if err != nil {
				// log_info = fmt.Sprintf("%s\t%d\t%s\t%s\t%s", host, index, query, "h"+indicator+" parse error", err)
				// return nil, err, log_info
				continue
			} else {
				if r.Answer != nil {
					log_info = fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%s\t%s", ip, host, "success", index, "", "h"+indicator, "")
				} else {
					log_info = fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%s\t%s", ip, host, "empty", index, "", "h"+indicator, "")
				}
				return r, err, log_info
			}
		}
	}

	log_info = fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%s\t%s", ip, host, "path not found", len(queryPaths), "", "h"+indicator, "")
	return nil, &dns.Error{}, log_info
}

func makeHTTP2Request(sslConn *tls.Conn, ip string, host string, path string, question_name string, carry_path bool) (*dns.Msg, error, string) {

	transport2 := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return sslConn, nil
		},
		TLSClientConfig:            &tls.Config{},
		ConnPool:                   nil,
		DisableCompression:         false,
		AllowHTTP:                  false,
		MaxHeaderListSize:          0,
		StrictMaxConcurrentStreams: false,
		ReadIdleTimeout:            0,
		PingTimeout:                0,
		WriteByteTimeout:           0,
		CountError: func(errType string) {
		},
	}

	client2 := &http.Client{
		Transport: transport2,
	}

	return requestSend(ip, host, path, question_name, carry_path, client2, "2")
}

// ResponseToMsg converts a http.Response to a dns message.
func ResponseToMsg(resp *http.Response) (*dns.Msg, error) {
	defer resp.Body.Close()
	return toMsg(resp.Body)
}

// RequestToMsg converts a http.Request to a dns message.
func RequestToMsg(req *http.Request) (*dns.Msg, error) {
	switch req.Method {
	case http.MethodGet:
		return requestToMsgGet(req)

	case http.MethodPost:
		return requestToMsgPost(req)

	default:
		return nil, fmt.Errorf("method not allowed: %s", req.Method)
	}
}

// requestToMsgPost extracts the dns message from the request body.
func requestToMsgPost(req *http.Request) (*dns.Msg, error) {
	defer req.Body.Close()
	return toMsg(req.Body)
}

// requestToMsgGet extract the dns message from the GET request.
func requestToMsgGet(req *http.Request) (*dns.Msg, error) {
	values := req.URL.Query()
	b64, ok := values["dns"]
	if !ok {
		return nil, fmt.Errorf("no 'dns' query parameter found")
	}
	if len(b64) != 1 {
		return nil, fmt.Errorf("multiple 'dns' query values found")
	}
	return base64ToMsg(b64[0])
}

func toMsg(r io.ReadCloser) (*dns.Msg, error) {
	buf, err := io.ReadAll(http.MaxBytesReader(nil, r, 65536))
	if err != nil {
		return nil, err
	}
	m := new(dns.Msg)
	err = m.Unpack(buf)
	return m, err
}

func base64ToMsg(b64 string) (*dns.Msg, error) {
	buf, err := b64Enc.DecodeString(b64)
	if err != nil {
		return nil, err
	}

	m := new(dns.Msg)
	err = m.Unpack(buf)

	return m, err
}

var b64Enc = base64.RawURLEncoding
