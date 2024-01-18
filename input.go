package main

import (
	"bufio"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

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

func truncateString(str string, maxLength int) string {
	if len(str) > maxLength {
		return str[:maxLength] + "..."
	}
	return str
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
