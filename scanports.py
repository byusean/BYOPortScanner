#!/usr/bin/python

from scapy.all import sr,sr1,IP,ICMP,UDP,TCP,traceroute

import sys, getopt, random

def printHelp():
	print '****************************************************************'
	print 'Welcome to Sean Jensen\'s Port Scanner!'
	print '****************************************************************'
	print '\nFEATURES'
	print '  Port Scanning'
	print '  Traceroute'


	print '\n\nADDRESS SPECIFICATION'
	print '  When you see the term <address>, it can take many forms.'
	print '    e.g. 192.168.0.0 - single address'
	print '    e.g. 192.168.0.0-192.168.0.255 - address range, this example specifies 256 addresses'
	print '    e.g. 192.168.0.0,192.168.0.1 - comma separated, this example specifies 2 addresses'
	print '    e.g. 192.168.0.0/24 - CIDR notation, this example specifies 256 addresses'
	print '    e.g. addresses.txt - input file, this example will read in the text file, and look for input like the four examples above'


	print '\n\nPORT SPECIFICATION'
	print '  When you see the term <port>, it can take many forms.'
	print '    e.g. 22 - single port'
	print '    e.g. 1-1024 - port range, this example specifies 1024 ports'
	print '    e.g. 22,139 - comma separated, this example specifies 2 ports'
	print '    e.g. ports.txt - input file, this example will read in the text file, and look for input like the three examples above'

	print '\n\nPORT SCANNING USAGE'
	print '  Base Usage: scanports.py -a <address> -p <port>'
	print '  Additional Options:'
	print '    --timeout=<timeout>, where <timeout> can be specified as either single, range, comma separated, or input file'
	print '    --protocol=<protocol>, where <protocol> can be specified as either single, range, comma separated, or input file. Possible values are tcp, udp, icmp'

	print '\n\nTRACEROUTE USAGE'
	print '  Base Usage: scanports.py -a <address> --traceroute'

def ipToNum(octets):
	return octets[0] + octets[1]*(2**8) + octets[2]*(2**16) + octets[3]*(2**24)

def numToIP(num):
	octets = []
	octets.insert(0,num & 0x000000FF)
	octets.insert(1,(num & 0x0000FF00) >> 8)
	octets.insert(2,(num & 0x00FF0000) >> 16)
	octets.insert(3,(num & 0xFF000000) >> 24)
	return octets

def ipsFromCidr(octets, rasterbits):
	ret = []
	num = ipToNum(octets)
	mask = 0xFFFFFFFF
	mask &= 0xFFFFFFFF<<rasterbits
	# print "{0:b}".format(mask)
	for i in range(0,2**rasterbits):
		ins = ''
		retOctets = numToIP((num&mask)+i)
		ins += str(retOctets[3]) + '.' + str(retOctets[2]) + '.' + str(retOctets[1]) + '.' + str(retOctets[0])
		ret.insert(i,ins)
	# print ret
	return ret

def handleCommaSeparated(param):
	return param.split(',')

def handleCIDR(param):
	ipaddr_s = param[:param.index('/')]
	maskbits_i = int(param[param.index('/')+1:])
	# print 'ip address is', ipaddr_s
	# print 'maskbits is', maskbits_i
	rasterbits = 32 - maskbits_i
	octets = map(int, ipaddr_s.split('.'))
	# we want the highest order bits to be in octets[3]
	octets.reverse()
	return ipsFromCidr(octets, rasterbits)

def handleRange(param):
	ret = []
	# this is an IP address
	if '.' in param:
		firstIPAddr_s = param[:param.index('-')]
		secondIPAddr_s = param[param.index('-')+1:]
		firstIPAddr_o = map(int, firstIPAddr_s.split('.'))
		secondIPAddr_o = map(int, secondIPAddr_s.split('.'))
		firstIPAddr_o.reverse()
		secondIPAddr_o.reverse()
		firstIPAddr_i = ipToNum(firstIPAddr_o)
		secondIPAddr_i = ipToNum(secondIPAddr_o)
		difference = secondIPAddr_i - firstIPAddr_i
		for i in range(0, difference+1):
			ins = ''
			retOctets = numToIP(firstIPAddr_i+i)
			ins += str(retOctets[3]) + '.' + str(retOctets[2]) + '.' + str(retOctets[1]) + '.' + str(retOctets[0])
			ret.insert(i, ins)
		print ret
		return ret
	# this is a port range
	else:
		lowNum_i = int(param[:param.index('-')])
		highNum_i = int(param[param.index('-')+1:])
		difference = highNum_i - lowNum_i
		for i in range(0, difference+1):
			ret.insert(i, str(difference+i))
		print ret
		return ret

def sanitize(param):
	# if we are reading from a text file
	if ".txt" in param:
		with open(param, "r") as filestream:
			for line in filestream:
				# This is a list, separated by commas
				if ',' in line:
					return handleCommaSeparated(line)

				# if it is CIDR notation
				if '/' in line:
					return handleCIDR(line)

				# if it is a range
				if '-' in line:
					return handleRange(line)
	
	# if it is a comma separated list
	if ',' in param:
		return handleCommaSeparated(param)

	# if it is CIDR notation
	if '/' in param:
		return handleCIDR(param)

	# if it is a range
	if '-' in param:
		return handleRange(param)

	# if it is a single
	thisList = []
	thisList.insert(0,param)
	return thisList

def portscan(addressList, portList, protocolList, timeoutList):
	for protocol in protocolList:
		if protocol == 'tcp':	
			for address in addressList:
				for port in portList:
					for timeout in timeoutList:
						sport = random.randint(1,1024)
						print "Sending TCP packet to " + address + " on port " + port + " (timeout = " + timeout + ")"
						resp = sr1(IP(dst=address)/TCP(sport=sport, dport=int(port), flags="S"), timeout=int(timeout))			#Sync
						if str(type(resp)) == "<type 'NoneType'>" :
							print "\tClosed"
						elif resp.haslayer(TCP) :
							if resp.getlayer(TCP).flags == 0x12:
								rst = sr1(IP(dst=address)/TCP(sport=sport, dport=int(port), flags="AR"),timeout=int(timeout))	#Ack Req
								print "\tOpen"
							elif resp.getlayer(TCP).flags == 0x14:
								print "\tClosed"
		elif protocol == 'udp':
			for address in addressList:
				for port in portList:
					for timeout in timeoutList:
						print "Sending UDP packet to " + address + " on port " + port + "(timeout = " + timeout + ")"
						resp = sr1(IP(dst=address)/UDP(dport=int(port)), timeout=int(timeout))
						if str(type(resp)) == "<type 'NoneType'>":
							print "\tOpen|Filtered"
						elif (resp.haslayer(UDP)):
							return "\tOpen"
						elif(resp.haslayer(ICMP)):
							if(int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) == 3):
								return "\tClosed"
							elif(int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1,2,9,10,13]):
								return "\tFiltered"
		elif protocol == 'icmp':
			for address in addressList:
				print "Sending ICMP packet to " + address
				resp = sr1(IP(dst=address)/ICMP())
				print resp

def callTraceroute(addressList):
	for address in addressList:
		print "Traceroute to " + address
		trace, _ = traceroute(address,verbose=0)
		hosts = trace.get_trace().values()[0]
		ips = [jpsts[i][0] for i in range(1, len(hosts) + 1)]
		print hosts
		#print ips

def main(argv):
	address = None
	port = None
	protocol = None
	timeout = None
	tracert = False
	addressList = []
	portList = []
	protocolList = ['tcp']
	timeoutList = ['1']
	try:
		opts, args = getopt.getopt(argv,"ha:p:t",["address=","port=","protocol=","timeout=","traceroute"])
	except getopt.GetoptError:
		print 'ERROR: USAGE scanports.py -a <address> -p <port>'
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			printHelp()
			sys.exit()
		elif opt in ("-a", "--address"):
			address = arg
			addressList = sanitize(address)
		elif opt in ("-p", "--port"):
			port = arg
			portList = sanitize(port)
		elif opt == "--protocol":
			protocol = arg
			protocolList = sanitize(protocol)
		elif opt =="--timeout":
			timeout = arg
			timeoutList = sanitize(timeout)
		elif opt in ("-t", "--traceroute"):
			tracert = True;
		else:
			assert False, "unhandled option"

	if tracert == True:
		traceroute(addressList)
	else:
		#print "addressList " + str(addressList)
		#print "portList " + str(portList)
		#print "protocolList " + str(protocolList)
		#print "timeoutList " + str(timeoutList)
		portscan(addressList, portList, protocolList, timeoutList)

if __name__ == "__main__":
   main(sys.argv[1:])
