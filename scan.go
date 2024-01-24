package main

import (
	"encoding/hex"
	"fmt"
	"github.com/TwiN/go-color"
	"github.com/gosnmp/gosnmp"
	_ "github.com/mattn/go-sqlite3"
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
	address := fmt.Sprintf("%s:%d", host, port)
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

func detectHoneypot(host string, ports []int, proto string, signatures Signatures, timeout int, bypassPortCheck bool, shodanClient *shodan.Client) []DetectionResult {
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

		if *username != "" && *password != "" && proto == "tcp" && port != 161 {
			isSSH = probeSSHServer(host, port, timeout)

			if isSSH {
				if *debug {
					fmt.Println(color.Ize(color.Purple, fmt.Sprintf("[Debug] SSH service detected on host %s:%d, attempting authentication", host, port)))
				}
				sshClient, err = authenticateSSH(host, port, *username, *password, timeout)
				if err != nil {
					if *debug {
						fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Debug] SSH authentication failed for host %s:%d: %s", host, port, err)))
					}
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

				signatureMatched := true
				for _, step := range signature.Steps {
					var response string
					if port == 161 {
						response, err = sendSNMPRequest(snmpClient, step)
						if err != nil {
							if *debug {
								fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Debug] SNMP request failed for signature '%s' on host %s:%d: %s", signature.Name, host, port, err)))
							}
							break
						}
					} else if isModbus {
						var modbusResponse string
						modbusResponse, err := sendModbusRequest(modbusClient, step)
						if err != nil {
							if *debug {
								fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Debug] Modbus request failed for signature '%s' on host %s:%d: %s", signature.Name, host, port, err)))
							}
							break
						}
						response = modbusResponse
					} else if isSSH && sshClient != nil {
						response, err = executeSSHCommand(sshClient, step.Input)
						if err != nil {
							if *debug {
								fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Debug] Error executing SSH command: %s", err)))
							}
							break
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

					invertMatch, err := strconv.ParseBool(step.InvertMatch)
					if err != nil {
						if *debug {
							fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Debug] Error parsing InvertMatch: %s", err)))
						}
						continue
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
		return fmt.Errorf(errMsg)
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
		if err != nil {
			if err != io.EOF {
				if *debug {
					fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Debug] Error reading response: %s", err)))
				}
				return "", err
			}
			break
		}

		response.Write(buffer[:n])

		if *debug {
			fmt.Println(color.Ize(color.Purple, fmt.Sprintf("[Debug] Partial Response received: %s", string(buffer[:n]))))
		}

		if n < len(buffer) {
			break
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
