[![Actively Maintained](https://img.shields.io/badge/Maintenance%20Level-Actively%20Maintained-green.svg)](https://gist.github.com/cheerfulstoic/d107229326a01ff0f333a1d3476e068d)

# honeydet
                                                        ~+
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

      Go Honeypot Detector, Dec 2023, Version 0.3.2

### What does honeydet do?

honeydet is a signature based, multi-threaded honeypot detection tool written in Golang.
It can detect honeypots based upon the premise that they were generate a unique and identifying response to tcp/udp packets.
While this could have been implemented as an nmap/zmap script, containing it within a Golang application allows for it's future potential to be extended to be a web application rather than just a command line tool.

### Command line options
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

### Wish-list
* API Endpoints
* Web interface
* PDF Reports
* Subnet scanning
* Active port detection
* Heuristic based detection including multi-command query and response
