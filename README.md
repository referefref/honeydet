[![Active Development](https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen.svg)](https://gist.github.com/cheerfulstoic/d107229326a01ff0f333a1d3476e068d)

# honeydet Go Honeypot Detector, Dec 2023, Version 0.4.7
![honeydetlogo](https://github.com/referefref/honeydet/assets/56499429/88e9b508-46e1-4822-94e1-e25edb83d0ba)


### What does honeydet do?

honeydet is a signature based, multi-threaded honeypot detection tool written in Golang.
It can detect honeypots based upon the premise that given a specifically crafted request they will generate a unique and identifying response to tcp/udp packets.
Running in webserver mode, you can easily scan multiple IP addresses and return the result in json or csv, this runs multithreaded as default.

### What doesn't it do (just yet)?

honeydet is not bundled with a library of request/response signatures for honeypots, this is something I'm privately working on and will share once completed - or at least in a semi-useful state.

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
    	Single host to scan
  -hostfile string
    	File containing a list of hosts to scan
  -output string
    	Output file for the report (default is stdout)
  -port int
    	Target port to scan (default 22)
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
    	Run as a web server (API) on port 8080
```
### Examples
* Scan a single host on port 2822 in verbose mode:
```
./honeydet -host 192.168.1.1 -port 2822 -verbose
```
* Scan hosts from a file with 100 threads checking for a ping before scanning, with a 5 second timeout, and create a json report as report.json
```
./honeydet -hostfile hosts.txt -threads 100 -timeout 5 -checkping -report json -output report.json
```
* Run in webserver mode to expose an API endpoint:
```
./honeydet -webserver
curl 'http://localhost:8080/scan?targets=1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4,5.5.5.5,6.6.6.6,7.7.7.7,8.8.8.8,9.9.9.9&report=csv&port=3389'
```

### Wish-list
* Web interface
* PDF Reports
* Subnet scanning
* Active port detection
* Heuristic based detection including multi-command query and response
