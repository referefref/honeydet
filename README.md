[![Active Development](https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen.svg)](https://gist.github.com/cheerfulstoic/d107229326a01ff0f333a1d3476e068d)

# honeydet Go Honeypot Detector
![image](https://github.com/referefref/honeydet/assets/56499429/563eacf3-8b3b-42d5-962a-bfc2e42f420f)

### What does honeydet do?

honeydet is a signature based, multi-step, high interaction, multi-threaded honeypot detection tool written in Golang.
It can detect honeypots based upon the premise that, given a set of specifically crafted requests they will generate a unique and identifying response.
It can be run either as a web server, a command line tool, or as a web API.
Signatures support multi-step, hex, string and regex detection on TCP and UDP.
Features a SQL backend for persistent scans which can be managed through the web interface.
Shodan API integration for non-private IPs, automatically adds shodan host information when the flag is set (currently CLI only)

### Signatures
The signature list is growing as I run through different methods of fuzzing, reverse engineering and comparing real protocols and servers to their emulated counterparts. I continue to add features to the signature format as required, and will extend the applications support of protocols using additional libraries as needed for things like DICOM and Modbus.

### Frontend Features:
- Multi-threaded, and now super fast. /24 single port scan in around 1 second
- Supports single and multiple targets with csv, range, and CIDR
- Supports single and multiple ports with range and csv list
- Adjust execution options to ignore signature port mapping, pingtest host before test, threads, timeout and delay
- Pagination, table search and export
- Remove individual scans and clear database functionality

### Wish-list/To-do
* Docker image and docker-compose file for simple installation
* SSL
* JA4+, HASSH, and other fingerprinting support
* Add shodan flag to frontend
* PDF Reports
* Active port detection (without requiring root), and passive port detection using Shodan API in place of specific ports or ranges

### Web Interface
![image](https://github.com/referefref/honeydet/assets/56499429/fdb710ea-9389-45b9-b56d-6fa1e2009efa)

### Installation

#### Build from source
```
git clone https://github.com/referefref/honeydet.git
cd honeydet
go get honeydet
go build
```

#### Use docker compose
```
# Note that scans.db will persist in the docker-compose file directory, if you need to map this somewhere else, edit the docker compose file
wget https://raw.githubusercontent.com/referefref/honeydet/main/docker-compose.yml
docker compose up
```

### Command line options
```
  -H string
    	Short form of -hostfile
  -P string
    	Short form of -proto (default "tcp")
  -T int
    	Short form of -timeout (default 5)
  -b	Short form of -bypassPortCheck
  -bypassPortCheck
    	Bypass port match checking and run all signatures against all ports
  -c	Short form of -checkPing
  -checkPing
    	Check if the host responds to ping before scanning
  -d int
    	Short form of -delay
  -debug
    	Enable extra verbose (debug) output
  -delay int
    	Delay in milliseconds between requests to a single host
  -h string
    	Short form of -host
  -host string
    	Single host or range of hosts to scan (i.e. 1.1.1.1, 10.1.1.1/24, 1.2.37.10.20-1.2.37.10.30)
  -hostfile string
    	File containing a list of hosts to scan
  -o string
    	Short form of -output
  -output string
    	Output file for the report (default is stdout)
  -p string
    	Short form of -port (default "22")
  -password string
    	Password for authentication
  -port string
    	Target port(s) to scan, single (22), range (22-80), or list (22,80,443) (default "22")
  -proto string
    	Protocol (tcp or udp) (default "tcp")
  -pw string
    	Short form of -password
  -r string
    	Short form of -report (default "none")
  -report string
    	Type of report to generate (none, json, csv) (default "none")
  -s string
    	Short form of -signatures (default "signatures.yaml")
  -shodan
    	Enable Shodan API enrichment
  -signatures string
    	File with signatures (default "signatures.yaml")
  -t int
    	Short form of -threads (default 1)
  -threads int
    	Number of concurrent threads (default 1)
  -timeout int
    	Connection timeout in seconds (default 5)
  -u string
    	Short form of -username
  -username string
    	Username for authentication
  -v	Short form of -verbose
  -verbose
    	Enable verbose output
  -vv
    	Enable extra verbose (debug) output
  -w	Short form of -webserver
  -webserver
    	Run as a web server on port 8080
```
### Examples
* Scan a single host on port 2822 in verbose mode:
```
./honeydet -host 192.168.1.1 -port 2822 -verbose
```
* Scan a range of hosts in debug (extra verbose) mode:
```
./honeydet -host 192.168.1.1-192.168.1.30 -vv
```
* Scan hosts from a file with 100 threads checking for a ping before scanning, with a 5 second timeout, append shodan API information, and create a json report as report.json
```
./honeydet -hostfile hosts.txt -t 100 -T 5 -c -r json -o report.json -shodan
```
* Run in verbose webserver mode to expose an API endpoint:
```
./honeydet -webserver -verbose
curl 'http://localhost:8080/scan?targets=10.1.1.1/24&report=json&port=3389'
```

## How to write a signature
Any contibutions to the signatures and detection logic are welcomed and will be integrated with proof, just submit the yaml as a PR.
Unique signature id's will be allocated upon collation of submitted signatures. If there's enough interest, i'll add author and reference url fields to the signature.

Add a new section to signatures.yaml or create a new signature yaml file with the following format
```
signatures:
  - name: "signature name"
    id: 1337
    port: port number
    proto: udp/tcp
    steps:
      - input_type: string/hex
        input: "input string or hex value"
        output_match_type: string/hex/regex
        output: "output match string, hex value or regex expression"
        invert_match: false
      - input_type: string/hex
        input: "second step input"
        output_match_type: string/hex/regex
        output: "output match string for step 2"
        invert_match: false
  confidence: "High/Medium/Low"
  comment: "Comment explaining the signature and its detection mechanism"
```
