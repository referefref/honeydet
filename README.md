[![Active Development](https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen.svg)](https://gist.github.com/cheerfulstoic/d107229326a01ff0f333a1d3476e068d)

# honeydet Go Honeypot Detector
![image](https://github.com/referefref/honeydet/assets/56499429/563eacf3-8b3b-42d5-962a-bfc2e42f420f)



### What does honeydet do?

honeydet is a signature based, multi-threaded honeypot detection tool written in Golang.
It can detect honeypots based upon the premise that given a specifically crafted request they will generate a unique and identifying response to tcp/udp packets.
Running in webserver mode, you can easily scan multiple IP addresses and ports, from the interface or through the API.
Checks for SSH servers and connects with supplied username and password, noting deviations in implementations of SSH sessions to generically detect SSH honeypots such as Cowrie (high false positive rate).

### What doesn't it do (just yet)?

honeydet is not bundled with a library of request/response signatures for honeypots, it's bundled with an example detection for Opencanary Redis server. More detections signatures will be made available in future.

### Installation
```
git clone https://github.com/referefref/honeydet.git
cd honeydet
go get honeydet
```

### Command line options
```
-checkping
    	Check if the host responds to ping before scanning
  -delay int
    	Delay in milliseconds between requests to a single host
  -host string
    	Single host or range of hosts to scan (i.e. 1.1.1.1, 10.1.1.1/24, 172.16.10.20-172.16.10.30)
  -hostfile string
    	File containing a list of hosts to scan
  -output string
    	Output file for the report (default is stdout)
  -port int
    	Target port(s) to scan, single (22), range (22-80), or list (22,80,443)
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
  -verbose
    	Enable verbose output
  -webserver
    	Run as a web server (API and interface) on port 8080
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

### Web Interface
![image](https://github.com/referefref/honeydet/assets/56499429/70ad59af-12b2-4118-bc40-385d125266b2)
Basic web interface making use of the exposed API
- Supports single and multiple targets with csv, range, and CIDR
- Supports single and multiple ports with range and csv list
- Download results as json or csv
- Filter and search results
- Control threads and protocol



### Wish-list
* Extend signatures to include port, request and response type, and regex matching
* Add option to check all signatures on all ports if flag is set
* Add checkPing, username, password, timeout, delay to web interface
* PDF Reports
* Active port detection
* Heuristic based detection including multi-command query and response
