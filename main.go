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
)

var (
    host          = flag.String("host", "", "Single host to scan")
    hostFile      = flag.String("hostfile", "", "File containing a list of hosts to scan")
    port          = flag.Int("port", 22, "Target port to scan")
    proto         = flag.String("proto", "tcp", "Protocol (tcp or udp)")
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

func readHosts(filePath string) ([]string, error) {
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
            continue // Skip malformed lines
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
    case "tcp":
        conn, err = net.DialTimeout("tcp", address, time.Duration(timeout)*time.Second)
    case "udp":
        conn, err = net.DialTimeout("udp", address, time.Duration(timeout)*time.Second)
    default:
        err = fmt.Errorf("unsupported protocol: %s", proto)
    }

    if err != nil && *verbose {
        fmt.Printf("[Verbose] Failed to connect: %s\n", err)
    }

    return conn, err
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

func detectHoneypot(host string, port int, proto string, signatures []HoneypotSignature, timeout int) DetectionResult {
    if *verbose {
        fmt.Printf("[Verbose] Detecting honeypot on host %s\n", host)
    }

    conn, err := connectToNetworkService(host, port, proto, timeout)
    if err != nil {
        if *verbose {
            fmt.Printf("[Verbose] Unable to connect to host %s: %s\n", host, err)
        }
        return DetectionResult{Host: host, IsHoneypot: false}
    }
    defer conn.Close()

    for _, signature := range signatures {
        if probeWithSignature(conn, signature) {
            if *verbose {
                fmt.Printf("[Verbose] Honeypot detected on host %s\n", host)
            }
            return DetectionResult{Host: host, IsHoneypot: true, HoneypotType: signature.Type}
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

      Go Honeypot Detector, Dec 2023, Version 0.4.5
`))

    fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
    flag.PrintDefaults()
    fmt.Println( "\nExamples:")
    fmt.Println(color.Ize(color.White,"  Scan a single host on port 2822 in verbose mode: ./honeydet -host 192.168.1.1 -port 2822 -verbose"))
    fmt.Println(color.Ize(color.White,"  Scan hosts from a file with 100 threads checking for a ping before scanning, with a 5 second timeout, and create a json report as report.json: ./honeydet -hostfile hosts.txt -threads 100 -timeout 5 -checkping -report json -output report.json"))
    fmt.Println(color.Ize(color.White,"  Run in webserver mode to expose an API endpoint: ./honeydet -webserver"))
    fmt.Println(color.Ize(color.Blue,"   ----- curl 'http://10.1.1.33:8080/scan?targets=10.1.1.99,10.1.1.100,10.1.1.101'"))
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
    params := r.URL.Query()
    argsBase := []string{}

    reportType := params.Get("report")
    if reportType == "" {
        reportType = "json"
    }
    argsBase = append(argsBase, "-report", reportType)

    var combinedOutput []byte
    
    for key, values := range params {
        if len(values) > 0 {
            value := values[0]
            switch key {
            case "checkping", "verbose":
                if value == "true" {
                    argsBase = append(argsBase, fmt.Sprintf("-%s", key))
                }
            case "host", "proto":
                argsBase = append(argsBase, fmt.Sprintf("-%s", key), value)
            case "delay", "port", "threads", "timeout":
                argsBase = append(argsBase, fmt.Sprintf("-%s", key), value)
            }
        }
    }

    // Process 'targets' parameter for multiple hosts
    if targets, ok := params["targets"]; ok {
        for _, host := range strings.Split(targets[0], ",") {
            args := append([]string(nil), argsBase...)
            args = append(args, "-host", strings.TrimSpace(host))

            cmd := exec.Command("./honeydet", args...)
            output, err := cmd.CombinedOutput()

            if err != nil {
                http.Error(w, err.Error(), http.StatusInternalServerError)
                return
            }

            combinedOutput = append(combinedOutput, output...)
        }
    }

    w.Header().Set("Content-Type", "text/plain")
    w.Write(combinedOutput)
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
        hosts = append(hosts, *host)
    } else if *hostFile != "" {
        hosts, err = readHosts(*hostFile)
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
