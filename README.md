[![Active Development](https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen.svg)](https://gist.github.com/cheerfulstoic/d107229326a01ff0f333a1d3476e068d)

# honeydet Go Honeypot Detector, Dec 2023, Version 0.3.2
![honeydetlogo](https://github.com/referefref/honeydet/assets/56499429/88e9b508-46e1-4822-94e1-e25edb83d0ba)


### What does honeydet do?

honeydet is a signature based, multi-threaded honeypot detection tool written in Golang.
It can detect honeypots based upon the premise that they were generate a unique and identifying response to tcp/udp packets.
While this could have been implemented as an nmap/zmap script, containing it within a Golang application allows for it's future potential to be extended to be a web application rather than just a command line tool.

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
```

### Wish-list
* API Endpoints
* Web interface
* PDF Reports
* Subnet scanning
* Active port detection
* Heuristic based detection including multi-command query and response
