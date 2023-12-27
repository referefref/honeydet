package main

import (
    "bufio"
    "bytes"
    "encoding/csv"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    "os"
    "os/exec"
    "strings"
    "sync"
    "time"
    "github.com/TwiN/go-color"
    "golang.org/x/crypto/ssh"
)

var (
    host          = flag.String("host", "", "Single host or range of hosts to scan (i.e. 1.1.1.1, 10.1.1.1/24, 172.16.10.20-172.16.10.30)")
    hostFile      = flag.String("hostfile", "", "File containing a list of hosts to scan")
    port          = flag.Int("port", 22, "Target port to scan")
    proto         = flag.String("proto", "tcp", "Protocol (tcp or udp)")
    username      = flag.String("username", "", "Username for authentication")
    password      = flag.String("password", "", "Password for authentication")
    signatureFile = flag.String("signatures", "signatures.csv", "File with signatures")
    verbose       = flag.Bool("verbose", false, "Enable verbose output")
    delay         = flag.Int("delay", 0, "Delay in milliseconds between requests to a single host")
    threads       = flag.Int("threads", 1, "Number of concurrent threads")
    reportType    = flag.String("report", "none", "Type of report to generate (none, json, csv)")
    timeout       = flag.Int("timeout", 5, "Connection timeout in seconds")
    checkPing     = flag.Bool("checkping", false, "Check if the host responds to ping before scanning")
    output        = flag.String("output", "", "Output file for the report (default is stdout)")
    webserver	  = flag.Bool("webserver",false, "Run as a web server on port 8080")
)

type HoneypotSignature struct {
    Type     string
    Request  string
    Response string
}

type DetectionResult struct {
    Host        string
    IsHoneypot  bool
    HoneypotType string
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
        return nil, err
    }
    defer file.Close()

    var signatures []HoneypotSignature
    reader := csv.NewReader(bufio.NewReader(file))

    if *verbose {
        fmt.Printf("[Verbose] Reading signatures from file: %s\n", filePath)
    }

    for {
        record, err := reader.Read()
        if err == io.EOF {
            break
        }
        if err != nil {
            return nil, err
        }
        if len(record) != 3 {
            if *verbose {
                fmt.Println("[Verbose] Skipping malformed line in signature file")
            }
            continue
        }
        signatures = append(signatures, HoneypotSignature{
            Type:     record[0],
            Request:  record[1],
            Response: record[2],
        })
    }

    if *verbose {
        fmt.Printf("[Verbose] Loaded %d signatures\n", len(signatures))
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

func probeWithSignature(conn net.Conn, signature HoneypotSignature) bool {
    if *verbose {
        fmt.Printf("[Verbose] Sending probe: %s\n", signature.Request)
    }

    _, err := conn.Write([]byte(signature.Request + "\n"))
    if err != nil {
        if *verbose {
            fmt.Printf("[Verbose] Error sending probe: %s\n", err)
        }
        return false
    }

    response := make([]byte, 1024)
    _, err = conn.Read(response)
    if err != nil {
        if *verbose {
            fmt.Printf("[Verbose] Error reading response: %s\n", err)
        }
        return false
    }

    if *verbose {
        fmt.Printf("[Verbose] Received response: %s\n", string(response))
    }

    return strings.Contains(string(response), signature.Response)
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

func detectHoneypot(host string, port int, proto string, signatures []HoneypotSignature, timeout int) DetectionResult {
    var conn net.Conn
    var err error
    var sshClient *ssh.Client
    var isSSH bool = false

    if *username != "" && *password != "" && proto == "tcp" {
        isSSH = probeSSHServer(host, port, timeout)
        if isSSH {
            if *verbose {
                fmt.Printf("[Verbose] SSH service detected on host %s:%d, attempting authentication\n", host, port)
            }
            if sshClient == nil {
                sshClient, err = authenticateSSH(host, port, *username, *password, timeout)
                if err != nil {
                    if *verbose {
                        fmt.Printf("[Verbose] SSH authentication failed for host %s:%d: %s\n", host, port, err)
                    }
		    isSSH = false
                } else {
		    isSSH = true
                    defer sshClient.Close()
                }
            }
        }
    }

    if !isSSH {
        if *verbose {
            fmt.Printf("[Verbose] Establishing regular %s connection to host %s:%d\n", proto, host, port)
        }
        conn, err = connectToNetworkService(host, port, proto, timeout)
        if err != nil {
            if *verbose {
                fmt.Printf("[Verbose] Unable to connect to host %s:%d: %s\n", host, port, err)
            }
            return DetectionResult{Host: host, IsHoneypot: false}
        }
        defer conn.Close()
    }

    if isSSH && sshClient != nil {
        for _, signature := range signatures {
            response, err := executeSSHCommand(sshClient, signature.Request)
            if err != nil {
                if *verbose {
                    fmt.Printf("[Verbose] Error executing command via SSH: %s\n", err)
                }
		return DetectionResult{Host: host, IsHoneypot: true, HoneypotType: "generic"}
            }
            if strings.Contains(response, signature.Response) {
                return DetectionResult{Host: host, IsHoneypot: true, HoneypotType: signature.Type}
            }
        }
    } else {
        for _, signature := range signatures {
            if probeWithSignature(conn, signature) {
                if *verbose {
                    fmt.Printf("[Verbose] Honeypot detected on host %s\n", host)
                }
                return DetectionResult{Host: host, IsHoneypot: true, HoneypotType: signature.Type}
            }
        }
    }

    if *verbose {
        fmt.Printf("[Verbose] No honeypot detected on host %s\n", host)
    }
    return DetectionResult{Host: host, IsHoneypot: false}
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
    fmt.Println(color.Ize(color.Red,`                                                        ~+
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

      Go Honeypot Detector, Dec 2023, Version 0.6.3
`))

    fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
    flag.PrintDefaults()
    fmt.Println( "\nExamples:")
    fmt.Println(color.Ize(color.White,"  Scan a single host on port 2822 in verbose mode: ./honeydet -host 192.168.1.1 -port 2822 -verbose"))
    fmt.Println(color.Ize(color.White,"  Scan hosts from a file with 100 threads checking for a ping before scanning, with a 5 second timeout, and create a json report as report.json: ./honeydet -hostfile hosts.txt -threads 100 -timeout 5 -checkping -report json -output report.json"))
    fmt.Println(color.Ize(color.White,"  Run in webserver mode to expose an API endpoint: ./honeydet -webserver"))
    fmt.Println(color.Ize(color.Blue,"                         curl 'http://localhost:8080/scan?targets=192.168.1.1/24'"))
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
    if *verbose {
        log.Printf("Received request: %s\n", r.URL.String())
    }
    params := r.URL.Query()

    if *verbose {
        for key, value := range params {
            log.Printf("Parameter: %s, Value: %s\n", key, value)
        }
    }

    argsBase := []string{}
    if reportType := params.Get("report"); reportType != "" {
        argsBase = append(argsBase, "-report", reportType)
    }
    if username := params.Get("username"); username != "" {
        argsBase = append(argsBase, "-username", username)
    }
    if password := params.Get("password"); password != "" {
        argsBase = append(argsBase, "-password", password)
    }
    if port := params.Get("port"); port != "" {
        argsBase = append(argsBase, "-port", port)
    }
    if proto := params.Get("proto"); proto != "" {
        argsBase = append(argsBase, "-proto", proto)
    }
    if delay := params.Get("delay"); delay != "" {
        argsBase = append(argsBase, "-delay", delay)
    }
    if threads := params.Get("threads"); threads != "" {
        argsBase = append(argsBase, "-threads", threads)
    }
    if timeout := params.Get("timeout"); timeout != "" {
        argsBase = append(argsBase, "-timeout", timeout)
    }
    if checkPing := params.Get("checkping"); checkPing != "" {
        argsBase = append(argsBase, "-checkping", checkPing)
    }

    resultsChan := make(chan []byte)
    var wg sync.WaitGroup

    if targets, ok := params["targets"]; ok && len(targets) > 0 {
        var hosts []string
        var err error

        hosts, err = parseHostInput(targets[0])
        if err != nil {
            if *verbose {
                log.Printf("Error parsing target input: %s", err)
            }
            http.Error(w, fmt.Sprintf("Invalid target input: %s", err), http.StatusBadRequest)
            return
        }

        for _, host := range hosts {
            wg.Add(1)
            go func(host string) {
                defer wg.Done()
                args := append(argsBase, "-host", strings.TrimSpace(host))
                cmd := exec.Command("./honeydet", args...)
                if *verbose {
                    log.Printf("Executing command for host: %s\n", host)
                }
                output, err := cmd.CombinedOutput()
                if err != nil {
                    if *verbose {
                        log.Printf("Error scanning host %s: %s", host, err)
                    }
                    resultsChan <- nil
                    return
                }
                resultsChan <- output
            }(host)
        }
    }

    go func() {
        wg.Wait()
        close(resultsChan)
    }()

    var combinedOutput []byte
    for output := range resultsChan {
        if output != nil {
            combinedOutput = append(combinedOutput, output...)
        }
    }

    w.Header().Set("Content-Type", "text/plain")
    w.Write(combinedOutput)
    if *verbose {
        log.Printf("Response sent: %s\n", string(combinedOutput))
    }
}


func main() {
    flag.Usage = enhancedHelpOutput
    flag.Parse()

    if len(os.Args) <= 1 {
        flag.Usage()
        return
    }

    if *webserver {
        http.HandleFunc("/scan", scanHandler)
        log.Println("Starting web server on :8080")
        log.Fatal(http.ListenAndServe(":8080", nil))
        return
    }

    var hosts []string
    var err error

    if *host != "" {
        hosts, err = parseHostInput(*host)
	if err != nil {
		log.Fatalf("Error parsing host input: %s", err)
	}
    } else if *hostFile != "" {
        hosts, err = readHostsFromFile(*hostFile)
        if err != nil {
            fmt.Printf("Error reading hosts: %s\n", err)
            os.Exit(1)
        }
    } else {
        fmt.Println("Either a single host (-host) or a host file (-hostfile) must be specified.")
        os.Exit(1)
    }

    signatures, err := readSignatures(*signatureFile)
    if err != nil {
        fmt.Printf("Error reading signatures: %s\n", err)
        os.Exit(1)
    }

    var results []DetectionResult
    var wg sync.WaitGroup
    hostChan := make(chan string, *threads)

    for i := 0; i < *threads; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for host := range hostChan {
                if *checkPing && !hostRespondsToPing(host) {
                    if *verbose {
                        fmt.Printf("[Verbose] Host %s does not respond to ping, skipping\n", host)
                    }
                    continue
                }
                result := detectHoneypot(host, *port, *proto, signatures, *timeout)
                results = append(results, result)
                time.Sleep(time.Millisecond * time.Duration(*delay))
            }
        }()
    }

    for _, host := range hosts {
        hostChan <- host
    }
    close(hostChan)

    wg.Wait()

    var reportData []byte
    if *reportType == "json" {
        reportData, err = json.Marshal(results)
    } else if *reportType == "csv" {
        var b bytes.Buffer
        writer := csv.NewWriter(&b)
        writer.Write([]string{"Host", "IsHoneypot", "HoneypotType"})
        for _, result := range results {
            record := []string{result.Host, fmt.Sprintf("%t", result.IsHoneypot), result.HoneypotType}
            writer.Write(record)
        }
        writer.Flush()
        reportData = b.Bytes()
    }
    if err != nil {
        fmt.Printf("Error generating report: %s\n", err)
    } else if *output != "" {
        err = os.WriteFile(*output, reportData, 0644)
        if err != nil {
            fmt.Printf("Error writing to file: %s\n", err)
        }
    } else {
        fmt.Print(string(reportData))
    }
}
