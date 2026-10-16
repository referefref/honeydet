package main

import (
	"fmt"
	"io"
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
		fmt.Printf("[Verbose] Opening SSH session channel to execute command\n")
	}

	// Use a raw channel and send exec without want-reply. Some honeypots (e.g. Cowrie)
	// send output and close the channel before replying to the exec request, which makes
	// session.Run/CombinedOutput return EOF and discard the output.
	channel, requests, err := client.OpenChannel("session", nil)
	if err != nil {
		if *verbose {
			fmt.Printf("[Verbose] Failed to open SSH session channel: %s\n", err)
		}
		return "", err
	}
	defer channel.Close()
	go ssh.DiscardRequests(requests)

	if *verbose {
		fmt.Printf("[Verbose] SSH channel open. Executing command: %s\n", command)
	}

	payload := ssh.Marshal(struct{ Command string }{command})
	if _, err := channel.SendRequest("exec", false, payload); err != nil {
		return "", err
	}

	type readResult struct {
		data []byte
		err  error
	}
	stdoutCh := make(chan readResult, 1)
	stderrCh := make(chan readResult, 1)
	go func() { d, e := io.ReadAll(channel); stdoutCh <- readResult{d, e} }()
	go func() { d, e := io.ReadAll(channel.Stderr()); stderrCh <- readResult{d, e} }()

	var output strings.Builder
	deadline := time.After(10 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case r := <-stdoutCh:
			output.Write(r.data)
		case r := <-stderrCh:
			output.Write(r.data)
		case <-deadline:
			channel.Close()
			if *verbose {
				fmt.Printf("[Verbose] SSH command timed out\n")
			}
			return output.String(), fmt.Errorf("SSH command timed out")
		}
	}

	if *verbose {
		fmt.Printf("[Verbose] Command executed. Output: %s\n", output.String())
	}

	return output.String(), nil
}
