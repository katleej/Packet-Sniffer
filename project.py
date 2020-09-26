import socket
from struct import *
from binascii import *
import pcapy
import re

def main():

	devices = pcapy.findalldevs()
	#give user choice of device
	print("Which device would you like to sniff? :")
	for i in range(len(devices)) :
		print (str(i) + '. ' + devices[i])
	
	index = input("Enter the device number : ")
	device = devices[int(index)]
	
	#tell user which device was chosen
	print("You are sniffing device " + device)

	#this value will be used to filter out between http and dns
	selected = int(input("Which header do you want to sniff? Enter the number (HTTP=1, DNS=2): "))
	print("Sniffing...")

	cap = pcapy.open_live(device , 65535 , 1 , 0)

	#counter
	num = 1

	#start sniffing packets
	while(num) :
		(header, packet) = cap.next()
		num = sniff_packet(packet, num, selected)

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
	b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
	return b

#function to parse a packet
def sniff_packet(packet, num, selected) :
	
	#parse ethernet header
	eth_length = 14
	
	eth_header = packet[:eth_length]
	eth = unpack('!6s6sH' , eth_header)
	eth_protocol = socket.ntohs(eth[2])

	#Parse IP packets, IP Protocol number = 8
	if eth_protocol == 8 :
		#Parse IP header
		#take first 20 characters for the ip header
		ip_header = packet[eth_length:20+eth_length]
		
		#now unpack them :)
		iph = unpack('!BBHHHBBH4s4s' , ip_header)

		version_ihl = iph[0]
		version = version_ihl >> 4
		ihl = version_ihl & 0xF

		iph_length = ihl * 4

		protocol = iph[6]
		s_addr = socket.inet_ntoa(iph[8]);
		d_addr = socket.inet_ntoa(iph[9]);

		#TCP protocol
		if protocol == 6 :
			t = iph_length + eth_length
			tcp_header = packet[t:t+20]

			#now unpack them :)
			tcph = unpack('!HHLLBBHHH' , tcp_header)
			
			source_port = tcph[0]
			dest_port = tcph[1]
			sequence = tcph[2]
			acknowledgement = tcph[3]
			doff_reserved = tcph[4]
			tcph_length = doff_reserved >> 4

			if selected == 1:
				#case is HTTP

				#handle http request (http request is when destination is 80)
				if (str(dest_port) == "80"):

					h_size = eth_length + iph_length + tcph_length * 4
					
					#get remaining values of packet
					data = packet[h_size:]
					headers_text = data.partition(b'\r\n\r\n')[0].decode('utf-8', errors='ignore')

					#filter out invalid data files
					if "HTTP" in headers_text:
						print(str(num) + ' ' + str(s_addr) + ':' + str(source_port) + ' ' + str(d_addr) + ':' + str(dest_port) + ' HTTP REQUEST')
						num += 1
						print(headers_text)
						print('\n')

				#handle http response (http response is when source is 80)
				if (str(source_port) == "80"):
				
					h_size = eth_length + iph_length + tcph_length * 4
					
					#get remaining values of packet
					data = packet[h_size:]
					headers_text = data.partition(b'\r\n\r\n')[0].decode('utf-8', errors='ignore')

					#filter out invalid data files: 
					if "HTTP" in headers_text: 
						print(str(num) + ' ' + str(s_addr) + ':' + str(source_port) + ' ' + str(d_addr) + ':' + str(dest_port) + ' HTTP RESPONSE')
						num += 1
						print(headers_text)
						print('\n')

			else:
				if (str(dest_port) == "53" or str(source_port) == '53'):
					h_size = eth_length + iph_length + tcph_length * 4
					
					#get remaining values of packet
					data = packet[h_size:]
					headers_text = data.partition(b'\r\n\r\n')[0].decode('utf-8', errors='ignore')

					#filter out invalid data files: 
					print(str(num) + ' ' + str(s_addr) + ':' + str(source_port) + ' ' + str(d_addr) + ':' + str(dest_port) + ' HTTP RESPONSE')
					num += 1
					print(headers_text)
					print('\n')

		if protocol == 17 and selected == 2:
			u = iph_length + eth_length
			udph_length = 8
			udp_header = packet[u:u+8]

			#now unpack them :)
			udph = unpack('!HHHH' , udp_header)
			
			source_port = udph[0]
			dest_port = udph[1]
			length = udph[2]
			checksum = udph[3]
			
			print(str(num) + ' ' + str(s_addr) + ':' + str(source_port) + ' ' + str(d_addr) + ':' + str(dest_port))
			
			h_size = eth_length + iph_length + udph_length
			data_size = len(packet) - h_size
			
			#get data from the packet
			data = packet[h_size:]
			#headers_text = data.partition('ID')[0].decode('utf-8')
			#print('Data : ' + headers_text)

	return num	

main()