package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	dns "main/dns"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

type InputType struct {
	ip    string
	host  string
	path  string
	query string
}

type ResultType struct {
	doh_string_1 []string
	doh_string_2 []string
	ssl_string   string
	log_info     string
	success      bool
}

func makeConnection(sslConn *tls.Conn, ip string, host string,
	port int, timeout time.Duration) (*x509.Certificate, *tls.Conn, string) {
	var derCert *x509.Certificate
	var err error

	// Set up TCP connection
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := net.Dialer{
		Timeout:       timeout,
		Deadline:      time.Now().Add(timeout),
		LocalAddr:     nil,
		DualStack:     false,
		FallbackDelay: 0,
		KeepAlive:     0,
		Resolver:      &net.Resolver{},
		Cancel:        make(<-chan struct{}),
	}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		// tcp_log_info := fmt.Sprintf("%s:%d, %s \n", host, port, err)
		tcp_log_info := fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%s\t%s", ip, host, "tcp error", -1, "", "", "")
		// log.Fatalf()
		return nil, nil, tcp_log_info
	}

	f, err := os.OpenFile("./ssl_keys", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)

	// Set up TLS configuration
	tlsConfig := &tls.Config{
		NextProtos:         []string{"http/1.1", "h2", "http/2"},
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
		KeyLogWriter:       f,
		InsecureSkipVerify: true,
	}

	// Establish TLS connection
	// conn.vers = tls.VersionTLS12
	sslConn = tls.Client(conn, tlsConfig)
	err = sslConn.Handshake()
	if err != nil {
		// log.Fatalf()
		// tcp_log_info := fmt.Sprintf("%s:%d, %s \n", host, port, err)
		tcp_log_info := fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%s\t%s", ip, host, "ssl handshake error", -1, "", "", "")
		return nil, nil, tcp_log_info
	}

	// Get peer certificate
	state := sslConn.ConnectionState()
	derCert = state.PeerCertificates[0]

	return derCert, sslConn, ""
}

func extract_header_info(header dns.MsgHdr) string {
	result := fmt.Sprintf("%d\t%d\t%d\t", header.Id, header.Rcode, header.Opcode)
	if header.Authoritative {
		result += "1\t"
	} else {
		result += "0\t"
	}

	if header.AuthenticatedData {
		result += "1\t"
	} else {
		result += "0\t"
	}

	if header.RecursionAvailable {
		result += "1\t"
	} else {
		result += "0\t"
	}

	if header.RecursionDesired {
		result += "1\t"
	} else {
		result += "0\t"
	}

	if header.Response {
		result += "1\t"
	} else {
		result += "0\t"
	}

	if header.Truncated {
		result += "1\t"
	} else {
		result += "0\t"
	}

	if header.CheckingDisabled {
		result += "1"
	} else {
		result += "0"
	}

	return result

}

// this is executed by the go routine directly.
// The main procedure including tcp connection, ssl connection, http connection
func connection_exec(ip string, host string, path string, query string,
	disable_ssl_filtered bool, disable_cert_save bool, carry_path bool) (ResultType, bool) {

	port := 443
	timeout := 10 * time.Second
	var log_info string

	var doh_contents_1 []string
	var doh_contents_2 []string
	var sslConn *tls.Conn

	startTime := time.Now()
	derCert, sslConn, err := makeConnection(sslConn, ip, host, port, timeout)
	if derCert == nil || sslConn == nil {
		endTime := time.Now()
		duration := endTime.Sub(startTime)
		return ResultType{
			log_info: err + fmt.Sprint("\t", duration.Milliseconds()) + "\n",
			success:  false,
		}, false
	}
	check_passed, alpn_check, alpn := check_ssl(derCert, sslConn)
	if disable_ssl_filtered {
		check_passed = true
	}
	ssl_content := extract_information(ip, derCert, sslConn, check_passed)
	if check_passed {
		// first make http1.1 request
		if alpn == "http/1.1" || alpn == "" {
			result1, err, tmp_info := makeHTTP11Request(sslConn, ip, host, path, query, carry_path)
			log_info = tmp_info
			if err == nil {
				if result1 != nil {
					header_info := extract_header_info(result1.MsgHdr)
					for _, rr := range result1.Answer {
						rr_string := rr.String()
						doh_content_1 := ip + "\t" + rr_string + "\t" + header_info
						doh_contents_1 = append(doh_contents_1, doh_content_1)
					}
				}
			}
		}
		if alpn == "h2" || alpn == "http/2" || alpn == "" {
			// if return none, then make http2 request
			result2, err, tmp_info := makeHTTP2Request(sslConn, ip, host, path, query, carry_path)
			log_info = tmp_info
			if err == nil {
				if result2 != nil {
					header_info := extract_header_info(result2.MsgHdr)
					for _, rr := range result2.Answer {
						rr_string := rr.String()
						doh_content_2 := ip + "\t" + rr_string + "\t" + header_info
						doh_contents_2 = append(doh_contents_2, doh_content_2)
					}
				}
			}
		}

	} else {
		if alpn_check {
			log_info = fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%s\t%s", ip, host, "tls filtered by certs", -1, "", "", alpn)
		} else {
			log_info = fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%s\t%s", ip, host, "tls filtered by alpn", -1, "", "", alpn)
		}

	}

	endTime := time.Now()

	duration := endTime.Sub(startTime)

	// Clean up connection
	sslConn.Close()
	log_info += fmt.Sprint("\t", duration.Milliseconds()) + "\n"
	// make results for chan
	routine_result := ResultType{
		doh_string_1: doh_contents_1,
		doh_string_2: doh_contents_2,
		ssl_string:   ssl_content,
		log_info:     log_info,
		success:      true,
	}
	if !disable_cert_save {
		saveCertificateAsCRT("./certs/", host, derCert)
	}
	return routine_result, true
}

func check_ssl(derCert *x509.Certificate, sslConn *tls.Conn) (bool, bool, string) {

	// ssl information judgement, (mini tlsv1.2) and (http1.1 or http2)
	state := sslConn.ConnectionState()
	alpn := state.NegotiatedProtocol
	if (alpn != "http/1.1") && (alpn != "http/2") && (alpn != "") && (alpn != "h2") {
		return false, true, alpn
	}

	// x509 information judgement
	sj_name := derCert.Subject.CommonName
	alt_name := strings.Join(append(derCert.DNSNames, sj_name), ",")
	ipRegex := regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
	dohRegex := regexp.MustCompile(`doh|dns|\*|dot|resolve`)
	selfRegex := regexp.MustCompile(`\.`)

	containIP := ipRegex.MatchString(alt_name)
	containDoh := dohRegex.MatchString(alt_name)
	IsEmpty := (len(alt_name) == 0)
	selfSigned := selfRegex.MatchString(alt_name)
	selfSigned2 := (derCert.Issuer.CommonName == derCert.Subject.CommonName)

	matched := IsEmpty || (!selfSigned) || selfSigned2 || containIP || containDoh

	return matched, false, alpn

}

func sslVersionToString(version uint16) string {
	switch version {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}
