package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	_ "main/dns"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

//optimize:cert save logic. start a new thread

func rountine_exec_wrapper(host_input_chan <-chan InputType,
	result_output_chan chan<- ResultType, lookupWG *sync.WaitGroup, index int,
	disable_ssl_filtered bool, enable_cert_save bool, carry_path bool) error {

	// Use routine to control timeout in case of long tcp failuer
	done := make(chan bool)
	var result ResultType
	for input_item := range host_input_chan {
		ip, host, path, query := input_item.ip, input_item.host, input_item.path, input_item.query
		go func() {
			result, _ = connection_exec(ip, host, path, query, disable_ssl_filtered, enable_cert_save, carry_path)
			done <- true
		}()

		timeout := 10 * time.Second

		select {
		case <-done:
			result_output_chan <- result
		case <-time.After(timeout):
			result = ResultType{log_info: host + "\tconnection timeout\t10000\n"}
			result_output_chan <- result
		}
	}
	lookupWG.Done()
	return nil
}

func parse_input(input_line string, carry_path bool) (string, string) {
	var host, path string

	if input_line[:5] == "https" {
		total_host := input_line[8:]
		if strings.Contains(total_host, "/") {
			host = strings.Split(total_host, "/")[0]
			path = strings.Split(total_host, "/")[1]
		} else {
			host = total_host
			path = ""
		}
	} else {
		host = input_line
		path = ""
	}

	return host, path
}

func read_exec(output_path string, host_file_name string, base_domain string,
	debug bool,
	host_input_chan chan<- InputType, carry_path bool, wg *sync.WaitGroup) error {

	defer close(host_input_chan)
	defer (*wg).Done()

	// log input csv
	ilog_filepath := path.Join(output_path, "input.csv")
	ilogf, _ := os.OpenFile(ilog_filepath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	defer ilogf.Close()
	ilogf.WriteString("ip\thost\tpath\tsubdomain\n")

	// open file and iterate each line into channel
	file, err := os.Open(host_file_name)
	if err != nil {
		fmt.Printf("Failed to open hosts file: %v\n", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	index := 0
	if !debug {
		for scanner.Scan() {
			var result InputType
			input_line := scanner.Text()
			host, path := parse_input(input_line, carry_path)

			ip_test := net.ParseIP(host)
			if ip_test == nil {
				ips, _ := net.LookupHost(host)
				for _, ip := range ips {
					if strings.Contains(ip, ":") {
						continue
					}
					// fmt.Println(host, ip)
					result = InputType{ip: ip, host: host, path: path, query: base_domain}
					host_input_chan <- result
					output_string := fmt.Sprintf("%s\t%s\t%s\t%s\n", ip, host, path, base_domain)
					ilogf.WriteString(output_string)
				}
			} else {
				result = InputType{ip: host, host: host, path: path, query: base_domain}
				host_input_chan <- result
				output_string := fmt.Sprintf("%s\t%s\t%s\t%s\n", host, host, path, base_domain)
				ilogf.WriteString(output_string)
			}

		}
	} else {
		for scanner.Scan() {
			var result InputType
			input_line := scanner.Text()
			host, path := parse_input(input_line, carry_path)

			ip_test := net.ParseIP(host)
			if ip_test == nil {
				ips, _ := net.LookupHost(host)
				for _, ip := range ips {
					if strings.Contains(ip, ":") {
						continue
					}
					sub_domain := fmt.Sprintf("%s.%s", host, base_domain)
					// fmt.Println(host, ip)
					result = InputType{ip: ip, host: host, path: path, query: sub_domain}
					host_input_chan <- result
					output_string := fmt.Sprintf("%s\t%s\t%s\t%s", ip, host, path, sub_domain)
					ilogf.WriteString(output_string)
				}
			} else {
				sub_domain := fmt.Sprintf("%s.%s", host, base_domain)
				result = InputType{ip: host, host: host, path: path, query: sub_domain}
				host_input_chan <- result
				output_string := fmt.Sprintf("%s\t%s\t%s\t%s", host, host, path, sub_domain)
				ilogf.WriteString(output_string)
			}

			if index%100000 == 0 {
				fmt.Println(index)
			}
			index += 1
		}
	}
	fmt.Println("all input to the chan")
	return nil
}

func write_exec(output_path string, result_output_chan <-chan ResultType, wg *sync.WaitGroup) {
	// get and save results from chain
	defer (*wg).Done()

	doh_filepath := path.Join(output_path, "doh.csv")
	ssl_filepath := path.Join(output_path, "ssl.csv")
	log_filepath := path.Join(output_path, "log.csv")

	dohf, doh_err := os.OpenFile(doh_filepath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	sslf, ssl_err := os.OpenFile(ssl_filepath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	logf, log_err := os.OpenFile(log_filepath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if doh_err != nil || ssl_err != nil || log_err != nil {
		log.Fatalf("unable to open output file: %v\n%v\n%v", doh_err, ssl_err, log_err)
	}
	defer dohf.Close()
	defer sslf.Close()
	defer logf.Close()

	ssl_header := strings.TrimSuffix(strings.Join([]string{"domain_name", "version",
		"cipher", "alpn", "sni", "subject_commonName", "subject_country",
		"subject_organization",
		"issuerCommonName", "extension_AltNames", "extension_emailAddress", "check_passed"},
		"_@_"), "_@_")
	doh_header := strings.TrimSuffix(strings.Join([]string{"domain_name", "query",
		"ttl", "class", "type", "value", "ID", "RCode", "OPCode", "Authoritative", "AuthenticatedData",
		"RecursionAvailable", "RecursionDesired", "Response", "Truncated", "CheckingDisabled"},
		"\t"), "\t")
	log_header := strings.TrimSuffix(strings.Join([]string{"ip", "host", "status", "level", "path", "protocol",
		"error", "duration"},
		"\t"), "\t")

	logf.WriteString(log_header + "\n")
	sslf.WriteString(ssl_header + "\n")
	dohf.WriteString(doh_header + "\n")

	for result := range result_output_chan {
		doh_string_1 := result.doh_string_1
		doh_string_2 := result.doh_string_2
		ssl_string := result.ssl_string
		log_string := result.log_info
		success := result.success

		if success {
			if len(doh_string_1) != 0 {
				dohf.WriteString(strings.Join(doh_string_1, "\n") + "\n")
			}
			if len(doh_string_2) != 0 {
				dohf.WriteString(strings.Join(doh_string_2, "\n") + "\n")
			}
			sslf.WriteString(ssl_string + "\n")
			logf.WriteString(log_string)
		} else {
			logf.WriteString(log_string)
		}

	}
	fmt.Println("files saved successfully.")
}

func check(maxr int, input string, output string, base_domain string) {
	if maxr < 1 {
		log.Fatal("maxr should be greate than 1")
	}
	if input == "" {
		log.Fatal("input should be required")
	}
	if output == "" {
		log.Fatal("output should be required")
	}
	if base_domain == "" {
		log.Fatal("output should be required")
	}
}

func check_fqdn(b string) string {
	if b[len(b)-1] == '.' {
		return b
	} else {
		return b + "."
	}
}

func main() {

	// Parse args
	var max_routine int
	var input_file string
	var output_path string
	var base_domain string
	var debug bool
	var disable_ssl_filtered bool
	var disable_cert_save bool
	var carry_path bool


	flag.IntVar(&max_routine, "m", 1, "Max Rountine Number")
	flag.BoolVar(&carry_path, "p", false, "Path indicator") // Set this flag means use the path from input
	flag.StringVar(&input_file, "i", "", "Input File. Must Required")
	flag.StringVar(&output_path, "o", "", "Output Path. Must Required")
	flag.StringVar(&base_domain, "b", "", "Base Domain. Must Required")
	flag.BoolVar(&debug, "d", false, "Debug flag.")                                      // Set this flag means disable flag, use the generated domain
	flag.BoolVar(&disable_ssl_filtered, "s", false, "Disable SSL Layer filterred flag.") // Set this flag means check=True
	flag.BoolVar(&disable_cert_save, "c", false, "Disable Cert Save flag.")              //Set this flag means disable cert save

	flag.Parse()

	check(max_routine, input_file, output_path, base_domain)
	base_domain = check_fqdn(base_domain)

	host_input_chan := make(chan InputType)
	result_output_chan := make(chan ResultType)
	//send the value to corresponding chain

	var ioWG sync.WaitGroup
	ioWG.Add(2)
	go read_exec(output_path, input_file, base_domain, debug, host_input_chan, carry_path, &ioWG)
	go write_exec(output_path, result_output_chan, &ioWG)

	// start go routine
	var lookupWG sync.WaitGroup
	lookupWG.Add(max_routine)
	for i := 0; i < max_routine; i++ {
		go rountine_exec_wrapper(host_input_chan,
			result_output_chan, &lookupWG, i, disable_ssl_filtered, disable_cert_save, carry_path)
	}
	lookupWG.Wait()
	close(result_output_chan)
	ioWG.Wait()
	return
}
