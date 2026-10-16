package main

import (
	"encoding/hex"
	"fmt"
	"github.com/TwiN/go-color"
	"github.com/gosnmp/gosnmp"
	"github.com/simonvetter/modbus"
	"github.com/tomsteele/go-shodan"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func isPublicIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP.IsLoopback() || parsedIP.IsPrivate() {
		return false
	}
	return true
}

func connectToNetworkService(host string, port int, proto string, timeout int) (net.Conn, error) {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	var conn net.Conn
	var err error

	if *verbose {
		fmt.Println(color.Ize(color.Purple, fmt.Sprintf("[Verbose] Attempting to connect to %s:%d over %s with timeout %d seconds", host, port, proto, timeout)))
	}

	switch proto {
	case "tcp", "udp":
		conn, err = net.DialTimeout(proto, address, time.Duration(timeout)*time.Second)
		if err != nil {
			if *debug {
				fmt.Printf("[Debug] Failed to connect: %s", err)
			}
			return nil, err
		}
		deadline := time.Now().Add(time.Duration(timeout) * time.Second)
		if err := conn.SetDeadline(deadline); err != nil {
			if *debug {
				fmt.Printf("[Debug] Failed to set deadline: %s", err)
			}
			conn.Close()
			return nil, err
		}
	default:
		err = fmt.Errorf("unsupported protocol: %s", proto)
		if *debug {
			fmt.Printf("[Debug] Unsupported protocol: %s", proto)
		}
		return nil, err
	}

	return conn, nil
}

func hostRespondsToPing(host string, timeout int) bool {
	if *verbose {
		fmt.Println(color.Ize(color.Green, fmt.Sprintf("[Verbose] Checking if host %s responds to ping", host)))
	}

	cmd := exec.Command("ping", "-c", "1", "-W", strconv.Itoa(timeout), host)
	err := cmd.Run()
	return err == nil
}

func detectHoneypot(host string, ports []int, proto string, signatures Signatures, timeout int, bypassPortCheck bool, shodanClient *shodan.Client, username, password string) []DetectionResult {
	var results []DetectionResult
	detectionTime := time.Now()

	var shodanInfo *shodan.Host
	if *useShodan {
		if shodanClient != nil && isPublicIP(host) {
			var err error
			opts := url.Values{}
			shodanInfo, err = shodanClient.Host(host, opts)
			if err != nil {
				if *debug {
					fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Debug]Error fetching Shodan data for host %s: %s", host, err)))
				}
			}
		}
	}

	for _, port := range ports {
		var sshClient *ssh.Client
		var modbusClient *modbus.ModbusClient
		var isSSH, isModbus bool
		var err error

		if username != "" && password != "" && proto == "tcp" && port != 161 {
			isSSH = probeSSHServer(host, port, timeout)

			if isSSH {
				if *debug {
					fmt.Println(color.Ize(color.Purple, fmt.Sprintf("[Debug] SSH service detected on host %s:%d, attempting authentication", host, port)))
				}
				sshClient, err = authenticateSSH(host, port, username, password, timeout)
				if err != nil {
					if *debug {
						fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Debug] SSH authentication failed for host %s:%d: %s", host, port, err)))
					}
					// Report the port rather than dropping it: a refused login is itself evidence of a genuine server
					results = append(results, DetectionResult{
						Host:          host,
						Port:          port,
						IsHoneypot:    false,
						Comment:       "SSH login refused",
						DetectionTime: detectionTime,
						ShodanInfo:    shodanInfo,
					})
					continue
				}
				defer sshClient.Close()
			}
		} else if port == 502 {
			isModbus = true
			modbusClient, err := setupModbusClient(host, port, time.Duration(timeout)*time.Second)
			if err != nil {
				if *debug {
					fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Debug] Error setting up Modbus client for host %s: %s", host, err)))
				}
				continue
			}
			defer modbusClient.Close()
		}

		var snmpClient *gosnmp.GoSNMP
		if port == 161 {
			snmpClient, err = setupSNMPClient(host, timeout)
			if err != nil {
				if *debug {
					fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Debug] Error setting up SNMP client for host %s: %s", host, err)))
				}
				continue
			}
			defer snmpClient.Conn.Close()
		}

		for _, signature := range signatures.Signatures {
			if bypassPortCheck || isPortMatch(port, signature.Port) {
				// SNMP (161) and Modbus (502) signatures send OIDs and register requests rather
				// than raw payloads, so only run them where the protocol client is in use
				if (signature.Port == "161" && port != 161) || (signature.Port == "502" && port != 502) {
					continue
				}
				if *verbose {
					fmt.Println(color.Ize(color.Green, fmt.Sprintf("[Verbose] Testing signature '%s' on host %s:%d", signature.Name, host, port)))
				}

				var conn net.Conn
				if !isSSH && !isModbus && port != 161 {
					conn, err = connectToNetworkService(host, port, proto, timeout)
					if err != nil {
						if *debug {
							fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Debug] Unable to connect to host %s:%d: %s", host, port, err)))
						}
						continue
					}
					defer conn.Close()
				}

				// Some SSH honeypots (e.g. Cowrie) drop the connection after an exec
				// from the Go client, so use a fresh connection per signature
				if isSSH {
					if sshClient != nil {
						sshClient.Close()
					}
					sshClient, err = authenticateSSH(host, port, username, password, timeout)
					if err != nil {
						if *debug {
							fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Debug] SSH re-authentication failed for signature '%s': %s", signature.Name, err)))
						}
						sshClient = nil
						continue
					}
				}

				signatureMatched := true
				for _, step := range signature.Steps {
					var response string
					if port == 161 {
						response, err = sendSNMPRequest(snmpClient, step)
						if err != nil {
							if *debug {
								fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Debug] SNMP request failed for signature '%s' on host %s:%d: %s", signature.Name, host, port, err)))
							}
							// A refused port (ICMP unreachable) is closed, not silent: fail the signature.
							// Otherwise (timeout) treat as no response, so only no-response steps can match
							if strings.Contains(err.Error(), "connection refused") {
								signatureMatched = false
								break
							}
							response = ""
						}
					} else if isModbus {
						var modbusResponse string
						modbusResponse, err := sendModbusRequest(modbusClient, step)
						if err != nil {
							if *debug {
								fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Debug] Modbus request failed for signature '%s' on host %s:%d: %s", signature.Name, host, port, err)))
							}
							// Treat as no response: only no-response steps can match
							modbusResponse = ""
						}
						response = modbusResponse
					} else if isSSH && sshClient != nil {
						response, err = executeSSHCommand(sshClient, step.Input)
						if err != nil {
							if *debug {
								fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Debug] Error executing SSH command: %s", err)))
							}
							// Match on any output received; fail the signature only if there was none
							if response == "" {
								signatureMatched = false
								break
							}
						}
					} else {
						err = sendRequest(conn, step, timeout)
						if err != nil {
							if *debug {
								fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Debug] Error sending request: %s", err)))
							}
							signatureMatched = false
							break
						}
						response, err = readResponse(conn)
						if err != nil {
							if *debug {
								fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Debug] Error reading response: %s", err)))
							}
							signatureMatched = false
							break
						}
					}

					// Default to false when invert_match is omitted, rather than skipping the check
					invertMatch := false
					if step.InvertMatch != "" {
						invertMatch, err = strconv.ParseBool(step.InvertMatch)
						if err != nil {
							if *debug {
								fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Debug] Error parsing InvertMatch: %s", err)))
							}
							signatureMatched = false
							break
						}
					}
					if !isResponseMatch(response, step.OutputMatchType, step.Output, invertMatch) {
						signatureMatched = false
						break
					}
				}

				if signatureMatched {
					result := DetectionResult{
						Host:          host,
						Port:          port,
						IsHoneypot:    true,
						HoneypotType:  signature.Name,
						Confidence:    signature.Confidence,
						Comment:       signature.Comment,
						DetectionTime: detectionTime,
						ShodanInfo:    shodanInfo,
					}
					results = append(results, result)
				}
			}
		}

		if len(results) == 0 {
			results = append(results, DetectionResult{
				Host:          host,
				Port:          port,
				IsHoneypot:    false,
				DetectionTime: detectionTime,
				ShodanInfo:    shodanInfo,
			})
		}
	}
	return results
}

func sendRequest(conn net.Conn, step Step, timeout int) error {
	conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))

	var request []byte

	if *debug {
		fmt.Println(color.Ize(color.Cyan, fmt.Sprintf("[Debug] Step info: InputType=%s, Input=%s", step.InputType, step.Input)))
	}
	switch step.InputType {
	case "string":
		request = []byte(step.Input + "\n")
	case "hex":
		var err error
		request, err = hex.DecodeString(step.Input)
		if err != nil {
			if *debug {
				fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Debug] Error decoding hex string: %s", err)))
			}
			return err
		}
	case "GET", "POST":
		request = []byte(fmt.Sprintf("%s / HTTP/1.1\r\nHost: %s\r\n\r\n", step.Input, conn.RemoteAddr().String()))
	default:
		errMsg := fmt.Sprintf("unsupported input type: %s", step.InputType)
		if *debug {
			fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Debug] %s", errMsg)))
		}
		return fmt.Errorf("%s", errMsg)
	}

	if *debug {
		fmt.Println(color.Ize(color.Yellow, "[Debug] Sending request"))
	}

	_, err := conn.Write(request)
	if err != nil {
		if *debug {
			fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Debug] Error sending request: %s", err)))
		}
		return err
	}

	if *debug {
		fmt.Println(color.Ize(color.Yellow, "[Verbose] Request sent successfully"))
	}

	return nil
}

func readResponse(conn net.Conn) (string, error) {
	var response strings.Builder
	buffer := make([]byte, 16048)
	for {
		n, err := conn.Read(buffer)
		if n > 0 {
			response.Write(buffer[:n])
			if *debug {
				fmt.Println(color.Ize(color.Purple, fmt.Sprintf("[Debug] Partial Response received: %s", string(buffer[:n]))))
			}
			// Services often send a reply in several packets (one per line), so keep
			// reading until the connection has been idle briefly
			conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() && response.Len() > 0 {
				break
			}
			if *debug {
				fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Debug] Error reading response: %s", err)))
			}
			return "", err
		}
	}

	fullResponse := response.String()
	if *debug {
		fmt.Println(color.Ize(color.Green, fmt.Sprintf("[Debug] Full Response received: %s", fullResponse)))
	}

	return fullResponse, nil
}
func isResponseMatch(response, matchType, matchPattern string, invertMatch bool) bool {
	trimmedResponse := strings.TrimSpace(response)

	if *debug {
		fmt.Println(color.Ize(color.Purple, fmt.Sprintf("[Debug] Trimmed Response: %s", trimmedResponse)))
		fmt.Println(color.Ize(color.Purple, fmt.Sprintf("[Debug] Match Type: %s", matchType)))
		fmt.Println(color.Ize(color.Purple, fmt.Sprintf("[Debug] Expected Output Pattern: %s", matchPattern)))
	}

	match := false
	switch matchType {
	case "string":
		match = strings.Contains(trimmedResponse, matchPattern)
		if *debug {
			fmt.Println(color.Ize(color.Green, fmt.Sprintf("[Debug] Comparing string: Response contains Output? %t", match)))
		}
	case "no-response":
		match = response == "" || response == "<no-response-indicator>"
	case "hex":
		hexResponse := hex.EncodeToString([]byte(trimmedResponse))
		match = strings.Contains(hexResponse, matchPattern)
	case "not-equals":
		match = response != matchPattern
	case "regex":
		var err error
		match, err = regexp.MatchString(matchPattern, trimmedResponse)
		if err != nil {
			if *debug {
				fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Debug] Regex match error: %s", err)))
			}
			match = false
		}
		if *debug {
			fmt.Println(color.Ize(color.Purple, fmt.Sprintf("[Debug] Regex match result: %t", match)))
		}
	default:
		if *debug {
			fmt.Println(color.Ize(color.Red, "[Debug] Unknown match type"))
		}
		match = false
	}

	if invertMatch {
		if *debug {
			fmt.Println(color.Ize(color.Yellow, "[Debug] Inverting match as inverMatch set on rule"))
		}
		return !match
	}
	return match
}
