package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/TwiN/go-color"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"net/http"
	"os"
	"path/filepath"
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
	signatureFile   = flag.String("signatures", "signatures.yaml", "File with signatures")
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
	Name       string `yaml:"name"`
	Port       string `yaml:"port"`
	Proto      string `yaml:"proto"`
	Steps      []Step `yaml:"steps"`
	Confidence string `yaml:"confidence"`
	Comment    string `yaml:"comment"`
}

type Step struct {
	InputType       string `yaml:"input_type"`
	Input           string `yaml:"input"`
	OutputMatchType string `yaml:"output_match_type"`
	Output          string `yaml:"output"`
}

type Signatures struct {
	Signatures []HoneypotSignature `yaml:"signatures"`
}

type DetectionResult struct {
	Host          string
	Port          int
	IsHoneypot    bool
	HoneypotType  string
	Confidence    string
	Comment       string
	DetectionTime time.Time
}

type Scan struct {
	ScanID     int64
	StartTime  time.Time
	EndTime    time.Time
	Parameters string
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

      Go Honeypot Detector, Dec 2023, Version 1.1.81
`))
}

func main() {
	flag.Usage = enhancedHelpOutput
	flag.Parse()

	logo()

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
		fs := http.FileServer(http.Dir("./assets"))
		http.Handle("/assets/", http.StripPrefix("/assets/", fs))
		http.HandleFunc("/scan", scanHandler)
		http.HandleFunc("/clearDatabase", clearDatabaseHandler)
		http.HandleFunc("/deleteScan", deleteScanHandler)
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

	var responsiveHostsMutex sync.Mutex
	var responsiveHosts []string
	if *checkPing {
		log.Printf(color.Ize(color.Blue, "Ping check enabled. Starting to ping hosts."))
		var pingWg sync.WaitGroup
		for _, host := range allHosts {
			pingWg.Add(1)
			go func(h string) {
				defer pingWg.Done()
				log.Printf(color.Ize(color.Blue, "Pinging host: "+h))
				if hostRespondsToPing(h, *timeout) {
					responsiveHostsMutex.Lock()
					responsiveHosts = append(responsiveHosts, h)
					responsiveHostsMutex.Unlock()
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
		responsiveHosts = allHosts
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
