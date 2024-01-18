package main

import (
	"encoding/hex"
	"fmt"
	"github.com/TwiN/go-color"
	"github.com/gosnmp/gosnmp"
	_ "github.com/mattn/go-sqlite3"
	"github.com/simonvetter/modbus"
	"golang.org/x/crypto/ssh"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

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

func detectHoneypot(host string, ports []int, proto string, signatures Signatures, timeout int, bypassPortCheck bool) []DetectionResult {
	var results []DetectionResult
	detectionTime := time.Now()

	for _, port := range ports {
		var conn net.Conn
		var err error
		var sshClient *ssh.Client
		var modbusClient *modbus.ModbusClient
		var isSSH, isModbus, honeypotDetected bool
		var honeypotType string = ""

		if *username != "" && *password != "" && proto == "tcp" && port != 161 {
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
					continue
				}
				defer sshClient.Close()
			}
		} else if port == 502 {
			isModbus = true
			modbusClient, err := setupModbusClient(host, port, time.Duration(timeout)*time.Second)
			if err != nil {
				if *verbose {
					fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Error setting up Modbus client for host %s: %s", host, err)))
				}
				continue
			}
			defer modbusClient.Close()
		}

		var snmpClient *gosnmp.GoSNMP
		if port == 161 {
			snmpClient, err = setupSNMPClient(host, timeout)
			if err != nil {
				if *verbose {
					fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Error setting up SNMP client for host %s: %s", host, err)))
				}
				continue
			}
			defer snmpClient.Conn.Close()
		}

		if !isSSH && port != 161 && port != 502 {
			if *verbose {
				fmt.Println(color.Ize(color.White, fmt.Sprintf("[Verbose] Establishing regular %s connection to host %s:%d", proto, host, port)))
			}
		}
		conn, err = connectToNetworkService(host, port, proto, timeout)
		if err != nil {
			if *verbose {
				fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Unable to connect to host %s:%d: %s", host, port, err)))
			}
			result := DetectionResult{
				Host:          host,
				Port:          port,
				IsHoneypot:    false,
				HoneypotType:  "",
				Confidence:    "High",
				Comment:       fmt.Sprintf("Host did not respond to %s connection", proto),
				DetectionTime: detectionTime,
			}
			results = append(results, result)
			continue // Skip to next port
		}
		defer conn.Close()

		for _, signature := range signatures.Signatures {
			if bypassPortCheck || isPortMatch(port, signature.Port) {
				if *verbose {
					fmt.Println(color.Ize(color.Green, fmt.Sprintf("[Verbose] Testing signature '%s' on host %s:%d", signature.Name, host, port)))
				}

				for _, step := range signature.Steps {
					var response string
					if port == 161 {
						response, err = sendSNMPRequest(snmpClient, step)
						if err != nil {
							if *verbose {
								fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] SNMP request failed for signature '%s' on host %s:%d: %s", signature.Name, host, port, err)))
							}
							break
						}
					} else if isModbus {
						var modbusResponse string
						modbusResponse, err := sendModbusRequest(modbusClient, step)
						if err != nil {
							if *verbose {
								fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Modbus request failed for signature '%s' on host %s:%d: %s", signature.Name, host, port, err)))
							}
							break
						}
						response = modbusResponse
					} else if isSSH && sshClient != nil {
						response, err = executeSSHCommand(sshClient, step.Input)
						if err != nil {
							if *verbose {
								fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Error executing SSH command: %s", err)))
							}
							break
						}
					} else {
						conn, err = sendRequest(host, port, step, timeout)
						if err != nil {
							if *verbose {
								fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Error sending request: %s", err)))
							}
							break
						}
						response, err = readResponse(conn)
					}

					if isResponseMatch(response, step.OutputMatchType, step.Output) {
						honeypotDetected = true
						honeypotType = signature.Name
						if *verbose {
							fmt.Println(color.Ize(color.Green, fmt.Sprintf("[Verbose] Match found for signature '%s'", signature.Name)))
						}
						break
					}
				}
			}

			if honeypotDetected {
				result := DetectionResult{
					Host:          host,
					Port:          port,
					IsHoneypot:    true,
					HoneypotType:  honeypotType,
					Confidence:    signature.Confidence,
					Comment:       signature.Comment,
					DetectionTime: detectionTime,
				}
				results = append(results, result)
				break // Exit the loop as honeypot is detected
			}
		}

		if !honeypotDetected {
			result := DetectionResult{
				Host:          host,
				Port:          port,
				IsHoneypot:    false,
				HoneypotType:  "",
				Confidence:    "",
				Comment:       "",
				DetectionTime: detectionTime,
			}
			results = append(results, result)
		}
	}
	return results
}

func sendRequest(host string, port int, step Step, timeout int) (net.Conn, error) {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout(*proto, address, time.Duration(timeout)*time.Second)
	if err != nil {
		if *verbose {
			fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Error dialing %s: %s", address, err)))
		}
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))

	var request []byte

	if *verbose {
		fmt.Println(color.Ize(color.Cyan, fmt.Sprintf("[Verbose] Step info: InputType=%s, Input=%s", step.InputType, step.Input)))
	}
	switch step.InputType {
	case "string":
		request = []byte(step.Input + "\n")
	case "hex":
		request, err = hex.DecodeString(step.Input)
		if err != nil {
			if *verbose {
				fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Error decoding hex string: %s", err)))
			}
			return nil, err
		}
	case "GET", "POST":
		request = []byte(fmt.Sprintf("%s / HTTP/1.1\r\nHost: %s\r\n\r\n", step.Input, host))
	default:
		errMsg := fmt.Sprintf("unsupported input type: %s", step.InputType)
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
	case "no-response":
		return response == "" || response == "<no-response-indicator>"
	case "hex":
		hexResponse := hex.EncodeToString([]byte(trimmedResponse))
		return strings.Contains(hexResponse, matchPattern)
	case "not-equals":
		return response != matchPattern
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
ro
