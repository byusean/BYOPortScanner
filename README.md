Dependencies:
	1. Install python 2.7
	2. Install scapy (I installed latest release here: http://scapy.readthedocs.io/en/latest/installation.html)
	
FEATURES
  This project allows a user to use command line switches to specify host and port for port scanning. It also allows more than one host and port to be specified for a single scan. The user can give as a parameter a text file containing the addresses/ports/protocols/timeouts, or can supply these on the command line. Hosts can be specified in a range of ways, as shown in the section ADDRESS SPECIFICATION below. This port scanner supports TCP, UDP, and ICMP pinging. It also allows the user to perform a traceroute to the specified hosts. The user can also output to a file, which can be opened up in any web browser.
  KEY PHRASES: more than one host, read from text file, read from command line, different ways to specify, more than one port, TCP, ICMP, UDP, Tracefroute, HTML report


ADDRESS SPECIFICATION
  When you see the term <address>, it can take many forms.
    e.g. 192.168.0.0 - single address
    e.g. 192.168.0.0-192.168.0.255 - address range, this example specifies 256 addresses
    e.g. 192.168.0.0,192.168.0.1 - comma separated, this example specifies 2 addresses
    e.g. 192.168.0.0/24 - CIDR notation, this example specifies 256 addresses
    e.g. addresses.txt - input file, this example will read in the text file, and look for input like the four examples above


PORT SPECIFICATION
  When you see the term <port>, it can take many forms.
    e.g. 22 - single port
    e.g. 1-1024 - port range, this example specifies 1024 ports
    e.g. 22,139 - comma separated, this example specifies 2 ports
    e.g. ports.txt - input file, this example will read in the text file, and look for input like the three examples above


PORT SCANNING USAGE
  Base Usage: scanports.py -a <address> -p <port>
  Additional Options:
    --timeout=<timeout>, where <timeout> can be specified as either single, range, comma separated, or input file
    --protocol=<protocol>, where <protocol> can be specified as either single, comma separated, or input file. Possible values are tcp, udp, icmp
    --outfile=<outfile>, where <outfile> should be a html file where the output will be stored.


TRACEROUTE USAGE
  Base Usage: scanports.py -a <address> --traceroute
  Additional Options:
    --outfile=<outfile>, where <outfile> should be a html file where the output will be stored.

