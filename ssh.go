package main

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"net"
	"strings"
	"time"
)

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
