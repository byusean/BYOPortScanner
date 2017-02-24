#!/usr/bin/python

from scapy.all import sr1,IP,ICMP,UDP

import sys, getopt

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

def portscan(addressList, portList, protocolList, timeoutList):


def main(argv):
	address = ''
	port = ''
	protocol = 'tcp'
	timeout = '10'
	try:
		opts, args = getopt.getopt(argv,"hta:p:",["address=","port=","protocol=","timeout="])
	except getopt.GetoptError:
		print 'scanports.py -a <address> -o <port>'
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print 'scanports.py -a <address> -o <port> --protocol=<protocol> --timeout=<timeout>'
			sys.exit()
		elif opt in ("-a", "--address"):
			address = arg
		elif opt in ("-p", "--port"):
			port = arg
		elif opt in ("--protocol"):
			protocol = arg
		elif opt in ("-t", "--timeout"):
			protocol = arg

	addressList = sanitize(address)
	portList = sanitize(port)
	protocolList = sanitize(protocol)
	timeoutList = sanitize(timeout)

	portscan(addressList, portList, protocolList, timeoutList)

if __name__ == "__main__":
   main(sys.argv[1:])
