[![Active Development](https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen.svg)](https://gist.github.com/cheerfulstoic/d107229326a01ff0f333a1d3476e068d)

# honeydet Go Honeypot Detector
![image](https://github.com/referefref/honeydet/assets/56499429/563eacf3-8b3b-42d5-962a-bfc2e42f420f)

### What does honeydet do?

honeydet is a signature based, multi-threaded honeypot detection tool written in Golang.
It can detect honeypots based upon the premise that given a specifically crafted request they will generate a unique and identifying response to tcp/udp packets.
It can be run either as a web server, a command line tool, or as a web API.
Signatures support hex, string and regex detection methods on TCP and UDP.
Features a SQL backend for persistent scans which can be managed throuhg the web interface.

### Frontend Features:
- Multi-threaded, and now super fast. /24 single port scan in around 1 second
- Supports single and multiple targets with csv, range, and CIDR
- Supports single and multiple ports with range and csv list
- Download results as json or csv
- Adjust execution options to ignore signature port mapping, pingtest host before test, threads, timeout and delay

### Wish-list
* SSL
* Scan data charts
* PDF Reports
* Active port detection (without requiring root)
* Change csv based signatures to yaml and allow for multi-step signatures that interact with services

### What doesn't it do (just yet)?
Honeydet comes with a few example signatures for detecting honeypots, now that the code is in a useable state, signature development will continue.

### Web Interface
![image](https://github.com/referefref/honeydet/assets/56499429/e6d8c6fe-daa9-46eb-8122-0add1cd83754)

### Installation
```
git clone https://github.com/referefref/honeydet.git
cd honeydet
go get honeydet
go build
```

### Command line options
```
  -bypassPortCheck
    	Bypass port match checking and run all signatures against all ports
  -checkPing
    	Check if the host responds to ping before scanning
  -delay int
    	Delay in milliseconds between requests to a single host
  -host string
    	Single host or range of hosts to scan (i.e. 1.1.1.1, 10.1.1.1/24, 172.16.10.20-172.16.10.30)
  -hostfile string
    	File containing a list of hosts to scan
  -output string
    	Output file for the report (default is stdout)
  -password string
    	Password for authentication
  -port string
    	Target port(s) to scan, single (22), range (22-80), or list (22,80,443) (default "22")
  -proto string
    	Protocol (tcp or udp) (default "tcp")
  -report string
    	Type of report to generate (none, json, csv) (default "none")
  -signatures string
    	File with signatures (default "signatures.csv")
  -threads int
    	Number of concurrent threads (default 1)
  -timeout int
    	Connection timeout in seconds (default 5)
  -username string
    	Username for authentication
  -verbose
    	Enable verbose output
  -webserver
    	Run as a web server on port 8080
```
### Examples
* Scan a single host on port 2822 in verbose mode:
```
./honeydet -host 192.168.1.1 -port 2822 -verbose
```
* Scan a range of hosts in verbose mode:
```
./honeydet -host 192.168.1.1-192.168.1.30 -verbose
```
* Scan hosts from a file with 100 threads checking for a ping before scanning, with a 5 second timeout, and create a json report as report.json
```
./honeydet -hostfile hosts.txt -threads 100 -timeout 5 -checkping -report json -output report.json
```
* Run in verbose webserver mode to expose an API endpoint:
```
./honeydet -webserver -verbose
curl 'http://localhost:8080/scan?targets=10.1.1.1/24&report=json&port=3389'
```
