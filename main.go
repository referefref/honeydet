package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/TwiN/go-color"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	host            = flag.String("host", "", "Single host or range of hosts to scan (i.e. 1.1.1.1, 10.1.1.1/24, 172.16.10.20-172.16.10.30)")
	hostFile        = flag.String("hostfile", "", "File containing a list of hosts to scan")
	port            = flag.String("port", "22", "Target port(s) to scan, single (22), range (22-80), or list (22,80,443)")
	bypassPortCheck = flag.Bool("bypassPortCheck", false, "Bypass port match checking and run all signatures against all ports")
	proto           = flag.String("proto", "tcp", "Protocol (tcp or udp)")
	username        = flag.String("username", "", "Username for authentication")
	password        = flag.String("password", "", "Password for authentication")
	signatureFile   = flag.String("signatures", "signatures.csv", "File with signatures")
	verbose         = flag.Bool("verbose", false, "Enable verbose output")
	delay           = flag.Int("delay", 0, "Delay in milliseconds between requests to a single host")
	threads         = flag.Int("threads", 1, "Number of concurrent threads")
	reportType      = flag.String("report", "none", "Type of report to generate (none, json, csv)")
	timeout         = flag.Int("timeout", 5, "Connection timeout in seconds")
	checkPing       = flag.Bool("checkPing", false, "Check if the host responds to ping before scanning")
	output          = flag.String("output", "", "Output file for the report (default is stdout)")
	webserver       = flag.Bool("webserver", false, "Run as a web server on port 8080")
)

type HoneypotSignature struct {
	Name            string
	Port            string
	Proto           string
	InputType       string
	Input           string
	OutputMatchType string
	Output          string
}

type DetectionResult struct {
	Host         string
	Port         int
	IsHoneypot   bool
	HoneypotType string
}

func parsePortInput(portInput string) ([]int, error) {
	var ports []int
	validatePort := func(p int) (bool, error) {
		if p < 1 || p > 65535 {
			return false, fmt.Errorf("port %d is out of range (1-65535)", p)
		}
		return true, nil
	}

	portParts := strings.Split(portInput, ",")
	for _, part := range portParts {
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range format in '%s'", part)
			}
			start, err := strconv.Atoi(rangeParts[0])
			if err != nil {
				return nil, err
			}
			end, err := strconv.Atoi(rangeParts[1])
			if err != nil {
				return nil, err
			}
			if start > end {
				return nil, fmt.Errorf("invalid port range: start port is greater than end port in '%s'", part)
			}

			for p := start; p <= end; p++ {
				if _, err := validatePort(p); err != nil {
					return nil, err
				}
				ports = append(ports, p)
			}
		} else {
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port format in '%s'", part)
			}
			if _, err := validatePort(port); err != nil {
				return nil, err
			}
			ports = append(ports, port)
		}
	}

	return ports, nil
}

func parseHostInput(input string) ([]string, error) {
	var ips []string
	if strings.Contains(input, "/") {
		_, ipNet, err := net.ParseCIDR(input)
		if err != nil {
			return nil, err
		}
		for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
			ips = append(ips, ip.String())
		}
	} else if strings.Contains(input, "-") {
		parts := strings.Split(input, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid range format")
		}
		startIP := net.ParseIP(parts[0])
		endIP := net.ParseIP(parts[1])
		if startIP == nil || endIP == nil {
			return nil, fmt.Errorf("invalid IP in range")
		}
		for ip := startIP; !ip.Equal(endIP); incIP(ip) {
			ips = append(ips, ip.String())
		}
		ips = append(ips, endIP.String())
	} else {
		ips = append(ips, input)
	}
	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func readHostsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hosts []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		host := scanner.Text()
		if host != "" {
			hosts = append(hosts, host)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return hosts, nil
}

func readSignatures(filePath string) ([]HoneypotSignature, error) {
	file, err := os.Open(filePath)
	if err != nil {
		if *verbose {
			fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Error opening signature file: %s", err)))
		}
		return nil, err
	}
	defer file.Close()

	var signatures []HoneypotSignature
	reader := csv.NewReader(bufio.NewReader(file))

	if *verbose {
		fmt.Println(color.Ize(color.Blue, fmt.Sprintf("[Verbose] Reading signatures from file: %s", filePath)))
	}

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			if *verbose {
				fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Error reading a line from signature file: %s", err)))
			}
			return nil, err
		}

		if len(record) != 7 {
			if *verbose {
				fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Skipping malformed line (expected 7 fields, got %d): %v", len(record), record)))
			}
			continue
		}

		signatures = append(signatures, HoneypotSignature{
			Name:            record[0],
			Port:            record[1],
			Proto:           record[2],
			InputType:       record[3],
			Input:           record[4],
			OutputMatchType: record[5],
			Output:          record[6],
		})

		if *verbose {
			fmt.Println(color.Ize(color.Green, fmt.Sprintf("[Verbose] Loaded signature: %v", record)))
		}
	}

	if *verbose {
		fmt.Println(color.Ize(color.Green, fmt.Sprintf("[Verbose] Total loaded signatures: %d", len(signatures))))
	}

	return signatures, nil
}

func connectToNetworkService(host string, port int, proto string, timeout int) (net.Conn, error) {
	address := fmt.Sprintf("%s:%d", host, port)
	var conn net.Conn
	var err error

	if *verbose {
		fmt.Printf("[Verbose] Attempting to connect to %s:%d over %s with timeout %d seconds\n", host, port, proto, timeout)
	}

	switch proto {
	case "tcp", "udp":
		conn, err = net.DialTimeout(proto, address, time.Duration(timeout)*time.Second)
		if err != nil {
			if *verbose {
				fmt.Printf("[Verbose] Failed to connect: %s\n", err)
			}
			return nil, err
		}
		deadline := time.Now().Add(time.Duration(timeout) * time.Second)
		if err := conn.SetDeadline(deadline); err != nil {
			if *verbose {
				fmt.Printf("[Verbose] Failed to set deadline: %s\n", err)
			}
			conn.Close()
			return nil, err
		}
	default:
		err = fmt.Errorf("unsupported protocol: %s", proto)
		if *verbose {
			fmt.Printf("[Verbose] Unsupported protocol: %s\n", proto)
		}
		return nil, err
	}

	return conn, nil
}

func hostRespondsToPing(host string) bool {
	if *verbose {
		fmt.Printf("[Verbose] Checking if host %s responds to ping\n", host)
	}

	cmd := exec.Command("ping", "-c", "1", "-W", "1", host)
	err := cmd.Run()
	return err == nil
}

func probeWithSignature(conn net.Conn, signature HoneypotSignature, timeout int) bool {
	var request string
	switch signature.InputType {
	case "string":
		request = signature.Input
	case "hex":
		decodedRequest, err := hex.DecodeString(signature.Input)
		if err != nil {
			if *verbose {
				fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Error decoding hex input for signature '%s': %s", signature.Name, err)))
			}
			return false
		}
		request = string(decodedRequest)
	default:
		if *verbose {
			fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Unsupported input type '%s' for signature '%s'", signature.InputType, signature.Name)))
		}
		return false
	}

	if *verbose {
		fmt.Println(color.Ize(color.Blue, fmt.Sprintf("[Verbose] Sending probe to %s: %s", conn.RemoteAddr(), request)))
	}

	_, err := conn.Write([]byte(request + "\n"))
	if err != nil {
		if *verbose {
			fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Error sending probe: %s", err)))
		}
		return false
	}

	buffer := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	n, err := conn.Read(buffer)
	if err != nil {
		if *verbose {
			fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Error reading response: %s", err)))
		}
		return false
	}

	response := string(buffer[:n])
	if *verbose {
		fmt.Println(color.Ize(color.Green, fmt.Sprintf("[Verbose] Received response: %s", response)))
	}

	var isMatch bool
	switch signature.OutputMatchType {
	case "string":
		isMatch = strings.Contains(response, signature.Output)
	case "hex":
		hexResponse := hex.EncodeToString([]byte(response))
		isMatch = strings.Contains(hexResponse, signature.Output)
	case "regex":
		matched, err := regexp.MatchString(signature.Output, response)
		if err != nil {
			if *verbose {
				fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Error compiling regex: %s", err)))
			}
			return false
		}
		isMatch = matched
	default:
		if *verbose {
			fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Unsupported output match type '%s' for signature '%s'", signature.OutputMatchType, signature.Name)))
		}
		return false
	}

	if *verbose {
		matchStatus := "not matched"
		if isMatch {
			matchStatus = "matched"
		}
		fmt.Println(color.Ize(color.Green, fmt.Sprintf("[Verbose] Response %s honeypot signature '%s'", matchStatus, signature.Name)))
	}

	return isMatch
}

func probeSSHServer(host string, port int, timeout int) bool {
	if *verbose {
		fmt.Printf("[Verbose] Checking if the service is an SSH server on host %s:%d\n", host, port)
	}

	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, time.Duration(timeout)*time.Second)
	if err != nil {
		if *verbose {
			fmt.Printf("[Verbose] Failed to connect to host %s:%d: %s\n", host, port, err)
		}
		return false
	}
	defer conn.Close()

	buffer := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	_, err = conn.Read(buffer)
	if err != nil {
		if *verbose {
			fmt.Printf("[Verbose] Failed to read from host %s:%d: %s\n", host, port, err)
		}
		return false
	}

	isSSH := strings.Contains(string(buffer), "SSH")
	if *verbose {
		fmt.Printf("[Verbose] SSH service detected on host %s:%d: %t\n", host, port, isSSH)
	}
	return isSSH
}

func authenticateSSH(host string, port int, username, password string, timeout int) (*ssh.Client, error) {
	if *verbose {
		fmt.Printf("[Verbose] Preparing to authenticate via SSH on %s:%d with username '%s'\n", host, port, username)
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(timeout) * time.Second,
	}

	if *verbose {
		fmt.Printf("[Verbose] SSH client configuration set. Dialing TCP connection to %s:%d\n", host, port)
	}

	address := fmt.Sprintf("%s:%d", host, port)
	client, err := ssh.Dial("tcp", address, config)
	if err != nil {
		if *verbose {
			fmt.Printf("[Verbose] Failed to establish SSH connection to %s:%d: %s\n", host, port, err)
		}
		return client, err
	}

	if *verbose {
		fmt.Printf("[Verbose] SSH connection established and authenticated to %s:%d\n", host, port)
	}

	return client, err
}

func executeSSHCommand(client *ssh.Client, command string) (string, error) {
	if *verbose {
		fmt.Printf("[Verbose] Creating new SSH session to execute command\n")
	}

	session, err := client.NewSession()
	if err != nil {
		if *verbose {
			fmt.Printf("[Verbose] Failed to create SSH session: %s\n", err)
		}
		return "", err
	}
	defer session.Close()

	if *verbose {
		fmt.Printf("[Verbose] SSH session created. Executing command: %s\n", command)
	}

	output, err := session.CombinedOutput(command)
	if err != nil {
		netErr, ok := err.(net.Error)
		if ok && netErr.Timeout() {
			if *verbose {
				fmt.Printf("[Verbose] SSH command timed out: %s\n", err)
			}
			return "SSH command timed out", err
		}

		if *verbose {
			fmt.Printf("[Verbose] Error executing command via SSH: %s\n", err)
		}
		return "", err
	}

	if *verbose {
		fmt.Printf("[Verbose] Command executed. Output: %s\n", string(output))
	}

	return string(output), nil
}

func detectHoneypot(host string, ports []int, proto string, signatures []HoneypotSignature, timeout int) []DetectionResult {
	var results []DetectionResult

	for _, port := range ports {
		var conn net.Conn
		var err error
		var sshClient *ssh.Client
		var isSSH bool = false
		var honeypotDetected bool = false
		var honeypotType string = ""

		if *username != "" && *password != "" && proto == "tcp" {
			isSSH = probeSSHServer(host, port, timeout)
			if isSSH {
				if *verbose {
					fmt.Println(color.Ize(color.Blue, fmt.Sprintf("[Verbose] SSH service detected on host %s:%d, attempting authentication", host, port)))
				}
				sshClient, err = authenticateSSH(host, port, *username, *password, timeout)
				if err != nil {
					if *verbose {
						fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] SSH authentication failed for host %s:%d: %s", host, port, err)))
					}
					results = append(results, DetectionResult{Host: host, Port: port, IsHoneypot: true, HoneypotType: "generic"})
					continue
				}
				defer sshClient.Close()
			}
		}

		if !isSSH {
			if *verbose {
				fmt.Println(color.Ize(color.White, fmt.Sprintf("[Verbose] Establishing regular %s connection to host %s:%d", proto, host, port)))
			}
			conn, err = connectToNetworkService(host, port, proto, timeout)
			if err != nil {
				if *verbose {
					fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Unable to connect to host %s:%d: %s", host, port, err)))
				}
				results = append(results, DetectionResult{Host: host, Port: port, IsHoneypot: false})
				continue
			}
			defer conn.Close()
		}

		for _, signature := range signatures {
			if *bypassPortCheck || isPortMatch(port, signature.Port) {
				if *verbose {
					fmt.Println(color.Ize(color.Green, fmt.Sprintf("[Verbose] Testing signature '%s' on host %s:%d", signature.Name, host, port)))
				}

				response := ""
				if signature.InputType == "ssh" && sshClient != nil {
					response, err = executeSSHCommand(sshClient, signature.Output)
					if err != nil {
						if *verbose {
							fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Error executing SSH command: %s", err)))
						}
						continue
					}
				} else {
					conn, err = sendRequest(host, port, signature, timeout)
					if err != nil {
						if *verbose {
							fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Error sending request: %s", err)))
						}
						continue
					}
					response, err = readResponse(conn)
					if err != nil {
						if *verbose {
							fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Error reading response: %s", err)))
						}
						continue
					}
				}

				if isResponseMatch(response, signature.OutputMatchType, signature.Output) {
					honeypotDetected = true
					honeypotType = signature.Name
					break
				}
			}
		}

		if *verbose && !honeypotDetected {
			fmt.Println(color.Ize(color.White, fmt.Sprintf("[Verbose] No honeypot detected on host %s:%d", host, port)))
		}
		results = append(results, DetectionResult{Host: host, Port: port, IsHoneypot: honeypotDetected, HoneypotType: honeypotType})
	}

	return results
}

func isPortMatch(port int, signaturePort string) bool {
	if signaturePort == "web-ports" {
		webPorts := []int{80, 88, 8080, 8888, 443, 8443}
		for _, webPort := range webPorts {
			if port == webPort {
				return true
			}
		}
		return false
	} else if strings.Contains(signaturePort, "-") {
		rangeParts := strings.Split(signaturePort, "-")
		startPort, _ := strconv.Atoi(rangeParts[0])
		endPort, _ := strconv.Atoi(rangeParts[1])
		return port >= startPort && port <= endPort
	} else {
		signaturePortInt, _ := strconv.Atoi(signaturePort)
		return port == signaturePortInt
	}
}

func sendRequest(host string, port int, signature HoneypotSignature, timeout int) (net.Conn, error) {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout(signature.Proto, address, time.Duration(timeout)*time.Second)
	if err != nil {
		if *verbose {
			fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Error dialing %s: %s", address, err)))
		}
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))

	var request []byte
	switch signature.InputType {
	case "string":
		request = []byte(signature.Input + "\n")
	case "hex":
		request, err = hex.DecodeString(signature.Input)
		if err != nil {
			if *verbose {
				fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Error decoding hex string: %s", err)))
			}
			return nil, err
		}
	case "GET", "POST":
		request = []byte(fmt.Sprintf("%s / HTTP/1.1\r\nHost: %s\r\n\r\n", signature.Input, host))
	default:
		errMsg := fmt.Sprintf("unsupported input type: %s", signature.InputType)
		if *verbose {
			fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] %s", errMsg)))
		}
		return nil, fmt.Errorf(errMsg)
	}

	if *verbose {
		fmt.Println(color.Ize(color.Green, fmt.Sprintf("[Verbose] Sending request to %s", address)))
	}

	_, err = conn.Write(request)
	if err != nil {
		if *verbose {
			fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Error sending request: %s", err)))
		}
		return nil, err
	}

	if *verbose {
		fmt.Println(color.Ize(color.Green, "[Verbose] Request sent successfully"))
	}

	return conn, nil
}

func readResponse(conn net.Conn) (string, error) {
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		if *verbose {
			fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Error reading response: %s", err)))
		}
		return "", err
	}
	response := string(buffer[:n])

	if *verbose {
		fmt.Println(color.Ize(color.Green, fmt.Sprintf("[Verbose] Response received: %s", response)))
	}

	return response, nil
}

func isResponseMatch(response, matchType, matchPattern string) bool {
	trimmedResponse := strings.TrimSpace(response)

	if *verbose {
		fmt.Println(color.Ize(color.Blue, fmt.Sprintf("[Verbose] Trimmed Response: %s", trimmedResponse)))
		fmt.Println(color.Ize(color.Blue, fmt.Sprintf("[Verbose] Expected Output: %s %s", matchPattern, matchType)))
	}

	switch matchType {
	case "string":
		if *verbose {
			fmt.Println(color.Ize(color.Blue, fmt.Sprintf("[Verbose] Comparing string: Response contains Output? %t", strings.Contains(trimmedResponse, matchPattern))))
		}
		return strings.Contains(trimmedResponse, matchPattern)
	case "hex":
		hexResponse := hex.EncodeToString([]byte(trimmedResponse))
		return strings.Contains(hexResponse, matchPattern)
	case "regex":
		matched, err := regexp.MatchString(matchPattern, trimmedResponse)
		if err != nil {
			return false
		}
		return matched
	default:
		return false
	}
}

func generateReport(results []DetectionResult, reportType string) {
	switch reportType {
	case "json":
		reportJSON(results)
	case "csv":
		reportCSV(results)
	default:
		if *verbose {
			fmt.Println("[Verbose] Invalid report type specified. No report generated.")
		}
	}
}

func reportJSON(results []DetectionResult) {
	data, err := json.Marshal(results)
	if err != nil {
		fmt.Printf("Error generating JSON report: %s\n", err)
		return
	}
	fmt.Println(string(data))
}

func reportCSV(results []DetectionResult) {
	writer := csv.NewWriter(os.Stdout)
	defer writer.Flush()
	writer.Write([]string{"Host", "IsHoneypot", "HoneypotType"})

	for _, result := range results {
		record := []string{result.Host, fmt.Sprintf("%t", result.IsHoneypot), result.HoneypotType}
		writer.Write(record)
	}
}

func enhancedHelpOutput() {
	logo()
	fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
	fmt.Println("\nExamples:")
	fmt.Println(color.Ize(color.White, "  Scan a single host on port 2822 in verbose mode: ./honeydet -host 192.168.1.1 -port 2822 -verbose"))
	fmt.Println(color.Ize(color.White, "  Scan hosts from a file with 100 threads checking for a ping before scanning, with a 5 second timeout, and create a json report as report.json: ./honeydet -hostfile hosts.txt -threads 100 -timeout 5 -checkping -report json -output report.json"))
	fmt.Println(color.Ize(color.White, "  Run in webserver mode to expose an API endpoint: ./honeydet -webserver"))
	fmt.Println(color.Ize(color.Blue, "                         curl 'http://localhost:8080/scan?host=192.168.1.1/24'"))
	fmt.Println(color.Ize(color.Blue, "                         interface 'http://localhost:8080/'"))
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	if *verbose {
		log.Printf(color.Ize(color.White, fmt.Sprintf("Received request: %s", r.URL.String())))
	}

	params := r.URL.Query()
	checkPing, _ := strconv.ParseBool(params.Get("checkPing"))
	bypassPortCheck, _ := strconv.ParseBool(params.Get("bypassPortCheck"))

	if _, found := params["report"]; !found {
		params.Set("report", "json")
	}

	args := []string{}
	for key, values := range params {
		for _, value := range values {
			value = sanitizeInput(value)
			if !isValidInput(key, value) {
				errMsg := fmt.Sprintf("Invalid input for key: %s, Value: %s", key, value)
				if *verbose {
					log.Printf(color.Ize(color.Red, errMsg))
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": errMsg})
				return
			}

			if key != "checkPing" && key != "bypassPortCheck" {
				args = append(args, fmt.Sprintf("-%s", key), value)
			}

			if *verbose {
				log.Printf(color.Ize(color.Blue, fmt.Sprintf("Parameter: %s, Value: %s", key, value)))
			}
		}
	}

	if checkPing {
		args = append(args, "-checkPing")
	}
	if bypassPortCheck {
		args = append(args, "-bypassPortCheck")
	}

	cmd := exec.Command("./honeydet", args...)
	if *verbose {
		log.Printf(color.Ize(color.Blue, fmt.Sprintf("Executing command: ./honeydet %s", strings.Join(args, " "))))
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		if *verbose {
			log.Printf(color.Ize(color.Red, fmt.Sprintf("Error executing command: %s, Output: %s", err, string(output))))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Error executing command: %s", err)})
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	if _, err := w.Write(output); err != nil {
		log.Printf(color.Ize(color.Red, fmt.Sprintf("Error sending response: %s", err)))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Error sending response: %s", err)})
		return
	}
	if *verbose {
		log.Printf(color.Ize(color.White, "Response sent"))
	}
}

func sanitizeInput(input string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9,./-]`)
	return strings.TrimSpace(re.ReplaceAllString(input, ""))
}

func isValidInput(key, value string) bool {
	switch key {
	case "threads", "timeout":
		return isValidNumber(value)
	case "port":
		return isValidPort(value)
	case "host":
		return isValidHost(value)
	case "username", "password", "proto", "report":
		return isValidString(value)
	case "checkPing", "bypassPortCheck":
		return isValidBoolean(value)
	default:
		return false
	}
}

func isValidBoolean(value string) bool {
	_, err := strconv.ParseBool(value)
	return err == nil
}

func isValidNumber(value string) bool {
	if _, err := strconv.Atoi(value); err != nil {
		return false
	}
	return true
}

func isValidPort(value string) bool {
	pattern := `^(\d{1,5}(,\d{1,5})*|\d{1,5}-\d{1,5})$`
	re := regexp.MustCompile(pattern)

	if !re.MatchString(value) {
		return false
	}

	if strings.Contains(value, "-") {
		parts := strings.Split(value, "-")
		start, _ := strconv.Atoi(parts[0])
		end, _ := strconv.Atoi(parts[1])
		return start > 0 && start <= 65535 && end > 0 && end <= 65535 && start <= end
	} else {
		for _, portStr := range strings.Split(value, ",") {
			port, _ := strconv.Atoi(portStr)
			if port <= 0 || port > 65535 {
				return false
			}
		}
	}

	return true
}

func isValidHost(value string) bool {
	pattern := `^([a-zA-Z0-9.-]+|` + // Hostname
		`\d{1,3}(\.\d{1,3}){3}|` + // Single IP address
		`\d{1,3}(\.\d{1,3}){3}/\d{1,2}|` + // CIDR notation
		`\d{1,3}(\.\d{1,3}){3}-\d{1,3}(\.\d{1,3}){3})$` // IP range

	hosts := strings.Split(value, ",")
	re := regexp.MustCompile(pattern)

	for _, host := range hosts {
		trimmedHost := strings.TrimSpace(host)
		if !re.MatchString(trimmedHost) {
			return false
		}
	}
	return true
}

func isValidString(value string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)
	return re.MatchString(value)
}

func logo() {
	fmt.Println(color.Ize(color.Red, `                                                        ~+
                                                        I7
  ,                                                   ~II7II,
 ?I  II                          jamesbrine.com.au    =?II,
 +I: 7?                                                 ?I,
 ~I= I+   ~II   +I7II~          ~I:  :7+    7I          ?I,
 :I? I=   IIII  II?,II    ?III= ~I=  II~    7I    ?III= ?I,
 :III7I  ~III7  ?I, +I:  ?I= ?I::I? ,II     I7   ?I= ?I:?I,
:III:I~  +I?:I: +I: ~I: :I?  ~II II ?I7 ~II77I  :I?  ~II?I,
 ,II:I=  +I~ 7I +I~ ~I: ?I,~7I?  II:III~I? ,7I, ?I,~7I? ?I,
  II I=  II~ II =I~ =7: IIIII    ~IIII=?I,  ~7: IIIII   ?I,
  II I=  II, II,=I+ +I::III  ~7   7III:II   ,I~:III  ~7 ?I,
  II I+ =I+  =I:~I+ ?7,II=   ,I+  :~II,?I   ,7+II=   ,I+?I,
  II I? ?I:  ,I~~I+ II 7I:    I7    7I ?I:   II7I:    I7?I,
  II II II,   I=:I= II ~I~    II    II ~I=   7I~I~    II?I,
  II II I7    I+:I= I7 :I+    II   ,I?  I?   7I:I+    II+7:
 ,II II II    I+:I= I7  II    II   :I=  II,  7I II    II+I:
 ,I? ?I,I7    I=:I= I7  ?I,   II   =I~  ~I?  II ?I,   II+I:
 ,II +I:I7,  ?I:~I= I7  ,I?   I7   =I,   II: II ,I?   I7=7~
  I+ :I+=I+  7I =I+ I7   I7~ :I?   +I,    II,II  I7~ :I?=I=
      =, I7III: =I= I7    IIIII    +I,     II7I   IIIII ~I+

      Go Honeypot Detector, Dec 2023, Version 0.9.40
`))
}

func main() {
	flag.Usage = enhancedHelpOutput
	flag.Parse()

	if len(os.Args) <= 1 {
		flag.Usage()
		return
	}

	if *webserver {
		logo()

		fs := http.FileServer(http.Dir("./assets"))
		http.Handle("/assets/", http.StripPrefix("/assets/", fs))
		http.HandleFunc("/scan", scanHandler)
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				http.ServeFile(w, r, filepath.Join(".", "index.html"))
			} else {
				http.NotFound(w, r)
			}
		})

		log.Println("Starting web server on :8888")
		log.Fatal(http.ListenAndServe(":8888", nil))

		return
	}

	var allHosts []string
	var err error
	var portList []int

	if *host != "" {
		hostInputs := strings.Split(*host, ",")
		for _, hostInput := range hostInputs {
			hosts, err := parseHostInput(hostInput)
			if err != nil {
				log.Fatalf("Error parsing host input: %s", err)
			}
			allHosts = append(allHosts, hosts...)
		}
	} else if *hostFile != "" {
		allHosts, err = readHostsFromFile(*hostFile)
		if err != nil {
			fmt.Printf("Error reading hosts: %s\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("Either a single host (-host) or a host file (-hostfile) must be specified.")
		os.Exit(1)
	}

	portList, err = parsePortInput(*port)
	if err != nil {
		fmt.Printf("Error parsing port input: %s\n", err)
		os.Exit(1)
	}

	signatures, err := readSignatures(*signatureFile)
	if err != nil {
		fmt.Printf("Error reading signatures: %s\n", err)
		os.Exit(1)
	}

	numHostsPerThread := len(allHosts) / *threads
	if len(allHosts)%*threads != 0 {
		numHostsPerThread++
	}

	var wg sync.WaitGroup
	resultsChan := make(chan []DetectionResult, *threads)

	for i := 0; i < *threads; i++ {
		start := i * numHostsPerThread
		end := start + numHostsPerThread
		if end > len(allHosts) {
			end = len(allHosts)
		}
		if start >= len(allHosts) {
			break
		}

		wg.Add(1)
		go func(hosts []string) {
			defer wg.Done()
			var combinedResults []DetectionResult
			for _, host := range hosts {
				if *verbose {
					fmt.Println(color.Ize(color.Blue, fmt.Sprintf("[Verbose] Processing host: %s", host)))
				}
				if *checkPing && !hostRespondsToPing(host) {
					if *verbose {
						fmt.Printf("[Verbose] Host %s does not respond to ping, skipping\n", host)
					}
					continue
				}
				for _, port := range portList {
					if *verbose {
						fmt.Printf("[Verbose] Scanning host %s on port %d\n", host, port)
					}
					results := detectHoneypot(host, []int{port}, *proto, signatures, *timeout)
					combinedResults = append(combinedResults, results...)
				}
			}
			resultsChan <- combinedResults
		}(allHosts[start:end])
	}

	wg.Wait()
	close(resultsChan)

	var finalResults []DetectionResult
	for results := range resultsChan {
		finalResults = append(finalResults, results...)
	}

	if *verbose {
		fmt.Println(color.Ize(color.Green, "[Verbose] Scan completed, compiling results"))
	}

	var reportData []byte
	if *reportType == "json" {
		reportData, err = json.Marshal(finalResults)
	} else if *reportType == "csv" {
		var b bytes.Buffer
		writer := csv.NewWriter(&b)
		writer.Write([]string{"Host", "Port", "IsHoneypot", "HoneypotType"})
		for _, result := range finalResults {
			record := []string{result.Host, strconv.Itoa(result.Port), fmt.Sprintf("%t", result.IsHoneypot), result.HoneypotType}
			writer.Write(record)
		}
		writer.Flush()
		reportData = b.Bytes()
	}

	if err != nil {
		fmt.Printf("Error generating report: %s\n", err)
		os.Exit(1)
	} else if *output != "" {
		if *verbose {
			fmt.Println(color.Ize(color.Green, fmt.Sprintf("[Verbose] Writing report to file: %s", *output)))
		}
		err = os.WriteFile(*output, reportData, 0644)
		if err != nil {
			fmt.Printf("Error writing to file: %s\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Print(string(reportData))
	}
}
