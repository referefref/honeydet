package main

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/TwiN/go-color"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
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
	Host          string
	Port          int
	IsHoneypot    bool
	HoneypotType  string
	DetectionTime time.Time
}

type Scan struct {
	ScanID     int64
	StartTime  time.Time
	EndTime    time.Time
	Parameters string
}

func initializeDatabase() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "./scans.db")
	if err != nil {
		return nil, err
	}

	createScansTableSQL := `
    CREATE TABLE IF NOT EXISTS scans (
        scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
        start_time DATETIME,
        end_time DATETIME,
        parameters TEXT
    );`
	_, err = db.Exec(createScansTableSQL)
	if err != nil {
		return nil, err
	}

	createScanResultsTableSQL := `
    CREATE TABLE IF NOT EXISTS scan_results (
        result_id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        host TEXT,
        port INTEGER,
        is_honeypot BOOLEAN,
        honeypot_type TEXT,
        detection_time DATETIME,
	FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
    );`
	_, err = db.Exec(createScanResultsTableSQL)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func insertScanResults(db *sql.DB, scanID int64, results []DetectionResult) error {
	stmt, err := db.Prepare("INSERT INTO scan_results(scan_id, host, port, is_honeypot, honeypot_type, detection_time) VALUES(?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, result := range results {
		if *verbose {
			log.Printf(color.Ize(color.Cyan, fmt.Sprintf("[Verbose] Inserting result into database: ScanID=%d, Host=%s, Port=%d, IsHoneypot=%t, HoneypotType=%s, DetectionTime=%s", scanID, result.Host, result.Port, result.IsHoneypot, result.HoneypotType, result.DetectionTime)))

		}
		_, err := stmt.Exec(scanID, result.Host, result.Port, result.IsHoneypot, result.HoneypotType, result.DetectionTime)
		if err != nil {
			return err
		}
	}

	return nil
}

func insertScanData(db *sql.DB, startTime time.Time, parameters string) (int64, error) {
	stmt, err := db.Prepare("INSERT INTO scans(start_time, parameters) VALUES(?, ?)")
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	res, err := stmt.Exec(startTime, parameters)
	if err != nil {
		return 0, err
	}

	scanID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	return scanID, nil
}

func updateScanStatus(db *sql.DB, scanID int64, endTime time.Time) error {
	stmt, err := db.Prepare("UPDATE scans SET end_time = ? WHERE scan_id = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(endTime, scanID)
	return err
}

func getScans(db *sql.DB) ([]map[string]interface{}, error) {
	rows, err := db.Query(`
        SELECT s.scan_id, s.start_time, s.end_time, s.parameters,
               r.result_id, r.host, r.port, r.is_honeypot, r.honeypot_type, r.detection_time
        FROM scans s
        LEFT JOIN scan_results r ON s.scan_id = r.scan_id
        ORDER BY s.scan_id, r.result_id
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans = make(map[int64]map[string]interface{})
	for rows.Next() {
		var scanID int64
		var startTime, endTime, detectionTime sql.NullString
		var resultID sql.NullInt64
		var host sql.NullString
		var port sql.NullInt64
		var parameters string
		var isHoneypot sql.NullBool
		var honeypotType sql.NullString

		err = rows.Scan(&scanID, &startTime, &endTime, &parameters, &resultID, &host, &port, &isHoneypot, &honeypotType, &detectionTime)
		if err != nil {
			return nil, err
		}

		scan, exists := scans[scanID]
		if !exists {
			scan = make(map[string]interface{})
			scan["scan_id"] = scanID
			scan["start_time"] = startTime.String
			scan["end_time"] = endTime.String
			scan["results"] = make([]map[string]interface{}, 0)
			scan["target_hosts"] = extractHostsFromParameters(parameters)
			scan["target_ports"] = extractPortsFromParameters(parameters)
		}

		if host.Valid && port.Valid {
			result := map[string]interface{}{
				"result_id":      resultID.Int64,
				"host":           host.String,
				"port":           int(port.Int64),
				"is_honeypot":    isHoneypot.Bool,
				"honeypot_type":  honeypotType.String,
				"detection_time": detectionTime.String,
			}
			scan["results"] = append(scan["results"].([]map[string]interface{}), result)
		}

		scans[scanID] = scan
	}

	var scanSlice []map[string]interface{}
	for _, scan := range scans {
		scanSlice = append(scanSlice, scan)
	}

	return scanSlice, nil
}

func extractHostsFromParameters(parameters string) string {
	query := strings.TrimPrefix(parameters, "/scan?")
	parsedParams, err := url.ParseQuery(query)
	if err != nil {
		log.Printf("Error parsing parameters: %s", err)
		return "N/A"
	}

	hosts, ok := parsedParams["host"]
	if !ok || len(hosts) == 0 {
		return "N/A"
	}

	return hosts[0]
}

func extractPortsFromParameters(parameters string) string {
	query := strings.TrimPrefix(parameters, "/scan?")
	parsedParams, err := url.ParseQuery(query)
	if err != nil {
		log.Printf("Error parsing parameters: %s", err)
		return "N/A"
	}

	ports, ok := parsedParams["port"]
	if !ok || len(ports) == 0 {
		return "N/A"
	}

	return ports[0]
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
	hostInputs := strings.Split(input, ",")
	for _, hostInput := range hostInputs {
		trimmedHostInput := strings.TrimSpace(hostInput)
		if strings.Contains(trimmedHostInput, "/") {
			_, ipNet, err := net.ParseCIDR(trimmedHostInput)
			if err != nil {
				return nil, err
			}
			for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
				ips = append(ips, ip.String())
			}
		} else if strings.Contains(trimmedHostInput, "-") {
			parts := strings.Split(trimmedHostInput, "-")
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
			ips = append(ips, trimmedHostInput)
		}
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

func hostRespondsToPing(host string, timeout int) bool {
	if *verbose {
		fmt.Printf("[Verbose] Checking if host %s responds to ping\n", host)
	}

	cmd := exec.Command("ping", "-c", "1", "-W", strconv.Itoa(timeout), host)
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

func detectHoneypot(host string, ports []int, proto string, signatures []HoneypotSignature, timeout int, bypassPortCheck bool) []DetectionResult {
	var results []DetectionResult
	detectionTime := time.Now()

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
					results = append(results, DetectionResult{Host: host, Port: port, IsHoneypot: true, HoneypotType: "generic", DetectionTime: detectionTime})
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
				results = append(results, DetectionResult{Host: host, Port: port, IsHoneypot: false, DetectionTime: detectionTime})
				continue
			}
			defer conn.Close()
		}

		for _, signature := range signatures {
			if bypassPortCheck || isPortMatch(port, signature.Port) {
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
		results = append(results, DetectionResult{Host: host, Port: port, IsHoneypot: honeypotDetected, HoneypotType: honeypotType, DetectionTime: detectionTime})
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
	db, err := initializeDatabase()
	if err != nil {
		log.Printf(color.Ize(color.Red, fmt.Sprintf("Error initializing database: %s", err)))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	if *verbose {
		log.Printf(color.Ize(color.White, "Received request: "+r.URL.String()))
	}

	checkPing, _ := strconv.ParseBool(r.URL.Query().Get("checkPing"))
	bypassPortCheck, _ := strconv.ParseBool(r.URL.Query().Get("bypassPortCheck"))
	threads, err := strconv.Atoi(r.URL.Query().Get("threads"))
	if err != nil || threads <= 0 {
		threads = 1
	}

	hosts, err := parseHostInput(r.URL.Query().Get("host"))
	if err != nil {
		log.Printf(color.Ize(color.Red, "Error parsing host input: "+err.Error()))
		return
	}

	ports, err := parsePortInput(r.URL.Query().Get("port"))
	if err != nil {
		log.Printf(color.Ize(color.Red, "Error parsing port input: "+err.Error()))
		return
	}

	proto := r.URL.Query().Get("proto")
	timeout, _ := strconv.Atoi(r.URL.Query().Get("timeout"))
	if timeout == 0 {
		timeout = 5
	}

	signatures, err := readSignatures(*signatureFile)
	if err != nil {
		log.Printf(color.Ize(color.Red, "Error reading signatures: "+err.Error()))
		return
	}

	var responsiveHosts []string
	if checkPing {
		log.Printf(color.Ize(color.Blue, "Ping check enabled. Starting to ping hosts."))
		var pingWg sync.WaitGroup
		for _, host := range hosts {
			pingWg.Add(1)
			go func(h string) {
				defer pingWg.Done()
				log.Printf(color.Ize(color.Blue, "Pinging host: "+h))
				if hostRespondsToPing(h, timeout) {
					responsiveHosts = append(responsiveHosts, h)
					if *verbose {
						log.Printf(color.Ize(color.Green, "Host "+h+" responds to ping"))
					}
				} else {
					log.Printf(color.Ize(color.Yellow, "No response from host: "+h))
				}
			}(host)
		}
		pingWg.Wait()
		log.Printf(color.Ize(color.Blue, "Ping check completed."))
	} else {
		responsiveHosts = hosts
	}

	totalWorkUnits := len(responsiveHosts) * len(ports)
	workUnitsPerThread := totalWorkUnits / threads
	if totalWorkUnits%threads != 0 {
		workUnitsPerThread++
	}

	var scanWg sync.WaitGroup
	resultsChan := make(chan []DetectionResult, threads)

	for i := 0; i < threads; i++ {
		scanWg.Add(1)
		go func(threadID int) {
			defer scanWg.Done()
			var combinedResults []DetectionResult
			for j := threadID; j < totalWorkUnits; j += threads {
				hostIndex := j / len(ports)
				portIndex := j % len(ports)
				if hostIndex < len(responsiveHosts) {
					host := responsiveHosts[hostIndex]
					port := ports[portIndex]
					if *verbose {
						log.Printf(color.Ize(color.Blue, "Processing host: "+host+" on port "+strconv.Itoa(port)))
					}
					results := detectHoneypot(host, []int{port}, proto, signatures, timeout, bypassPortCheck)
					combinedResults = append(combinedResults, results...)
				}
			}
			resultsChan <- combinedResults
		}(i)
	}

	scanWg.Wait()
	close(resultsChan)

	var finalResults []DetectionResult
	for results := range resultsChan {
		finalResults = append(finalResults, results...)
	}

	startTime := time.Now()
	scanParameters := r.URL.String()
	scanID, err := insertScanData(db, startTime, scanParameters)
	if err != nil {
		log.Printf(color.Ize(color.Red, "Error inserting scan data: "+err.Error()))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	err = insertScanResults(db, scanID, finalResults)
	if err != nil {
		log.Printf(color.Ize(color.Red, "Error inserting scan results: "+err.Error()))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	endTime := time.Now()
	err = updateScanStatus(db, scanID, endTime)
	if err != nil {
		log.Printf(color.Ize(color.Red, "Error updating scan status: "+err.Error()))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(finalResults)
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
	pattern := `^([a-zA-Z0-9.-]+|` +
		`\d{1,3}(\.\d{1,3}){3}|` +
		`\d{1,3}(\.\d{1,3}){3}/\d{1,2}|` +
		`\d{1,3}(\.\d{1,3}){3}-\d{1,3}(\.\d{1,3}){3})$`

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

      Go Honeypot Detector, Dec 2023, Version 0.9.128
`))
}

func main() {
	flag.Usage = enhancedHelpOutput
	flag.Parse()

	var err error
	db, err := initializeDatabase()
	if err != nil {
		log.Fatalf("Error initializing database: %s", err)
	}
	defer db.Close()

	if len(os.Args) <= 1 {
		flag.Usage()
		return
	}

	if *webserver {
		logo()

		fs := http.FileServer(http.Dir("./assets"))
		http.Handle("/assets/", http.StripPrefix("/assets/", fs))
		http.HandleFunc("/scan", scanHandler)
		http.HandleFunc("/getScans", func(w http.ResponseWriter, r *http.Request) {
			scans, err := getScans(db)
			if err != nil {
				log.Printf("Error retrieving scans: %s", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			if scans == nil {
				scans = make([]map[string]interface{}, 0)
			}
			json.NewEncoder(w).Encode(scans)
		})
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

	var pingWg sync.WaitGroup
	pingResults := make(map[string]bool)
	var pingResultsMutex sync.Mutex

	for _, host := range allHosts {
		pingWg.Add(1)
		go func(h string) {
			defer pingWg.Done()
			pingResult := hostRespondsToPing(h, *timeout)
			pingResultsMutex.Lock()
			pingResults[h] = pingResult
			pingResultsMutex.Unlock()
		}(host)
	}
	pingWg.Wait()

	var responsiveHosts []string
	for host, isResponsive := range pingResults {
		if isResponsive {
			responsiveHosts = append(responsiveHosts, host)
		}
	}

	responsiveHostsMap := make(map[string]bool)
	for _, host := range responsiveHosts {
		responsiveHostsMap[host] = true
	}

	totalWorkUnits := len(allHosts) * len(portList)
	workUnitsPerThread := totalWorkUnits / *threads
	if totalWorkUnits%*threads != 0 {
		workUnitsPerThread++
	}

	var wg sync.WaitGroup
	resultsChan := make(chan []DetectionResult, *threads)
	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func(threadID int) {
			defer wg.Done()
			var combinedResults []DetectionResult
			for j := threadID; j < totalWorkUnits; j += *threads {
				hostIndex := j / len(portList)
				portIndex := j % len(portList)
				if hostIndex < len(allHosts) {
					host := allHosts[hostIndex]
					port := portList[portIndex]
					if *verbose {
						fmt.Println(color.Ize(color.Blue, fmt.Sprintf("[Verbose] Processing host: %s on port %d", host, port)))
					}
					if *checkPing && !responsiveHostsMap[host] {
						if *verbose {
							fmt.Printf("[Verbose] Host %s does not respond to ping, skipping\n", host)
						}
						continue
					}
					results := detectHoneypot(host, []int{port}, *proto, signatures, *timeout, *bypassPortCheck)
					for _, result := range results {
						if *verbose {
							log.Printf(color.Ize(color.Green, fmt.Sprintf("[Verbose] Result for host %s on port %d: IsHoneypot=%t, HoneypotType=%s", result.Host, result.Port, result.IsHoneypot, result.HoneypotType)))
						}
					}
					combinedResults = append(combinedResults, results...)
				}
			}
			resultsChan <- combinedResults
		}(i)
	}

	wg.Wait()
	close(resultsChan)

	var finalResults []DetectionResult
	for results := range resultsChan {
		finalResults = append(finalResults, results...)
	}

	if *verbose {
		fmt.Println(color.Ize(color.Green, "[Verbose] Scan completed, compiling results"))
		log.Println(color.Ize(color.Green, "[Verbose] Final aggregated scan results:"))
		for _, result := range finalResults {
			log.Printf(color.Ize(color.Yellow, fmt.Sprintf("[Verbose] Host: %s, Port: %d, IsHoneypot: %t, HoneypotType: %s", result.Host, result.Port, result.IsHoneypot, result.HoneypotType)))
		}
	}

	startTime := time.Now()
	scanParameters := fmt.Sprintf("Host: %s, Port: %s, Threads: %d, Protocol: %s", *host, *port, *threads, *proto)
	scanID, err := insertScanData(db, startTime, scanParameters)
	if err != nil {
		log.Fatalf("Error inserting scan data: %s", err)
	}

	err = insertScanResults(db, scanID, finalResults)
	if err != nil {
		log.Fatalf("Error inserting scan results: %s", err)
	}

	endTime := time.Now()
	err = updateScanStatus(db, scanID, endTime)
	if err != nil {
		log.Fatalf("Error updating scan status: %s", err)
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

func init() {
	if os.Geteuid() != 0 {
		fmt.Println("This program requires root privileges. Run as root or with sudo.")
		os.Exit(1)
	}
}
