import socket
from struct import *
import pcapy

def main():

	devices = pcapy.findalldevs()
	#give user choice of device
	print("Which device would you like to sniff? :")
	for i in range(len(devices)) :
		print (str(i) + '. ' + devices[i])
	
	index = input("Enter the device number : ")
	device = devices[int(index)]
	
	#tell user which device was chosen
	print("Device chosen: " + device)
	#this value will be used to filter out between http and dns
	selected = int(input("Which header do you want to sniff? Enter the number (HTTP=1, DNS=2): "))
	print("Sniffing...")

	cap = pcapy.open_live(device , 65535 , 1 , 0)

	#this value will be used at the beginning of each packet to keep track of total number of packets being sniffed
	num = 1

	#start sniffing packets by calling sniff_packet(packet, numbering packet, http or dns)
	while(num) :
		header, packet = cap.next()
		num = sniff_packet(packet, num, selected)

def sniff_packet(packet, num, selected) :

	eth_length = 14
	
	#we are going to look at the first 14 bytes to get dest, source, type(protocol)
	dest, source, protocol = unpack('!6s6sH' , packet[:14])
	eth_protocol = socket.htons(protocol)

	#Parse IP packets, IP Protocol number = 8
	if eth_protocol == 8 :
		#Parse IP header
		#take first 20 bytes for the ip header because we don't need the rest
		ip_header = packet[eth_length:20+eth_length]
		iph = unpack('!BBHHHBBH4s4s' , ip_header)

		#get version and IHL that each take 2 bits 
		version_ihl = iph[0]
		version = version_ihl >> 4
		ihl = version_ihl & 15

		#entire length of header is kept to trim correctly for next step
		iph_length = ihl * 4

		protocol = iph[6]
		source_address = socket.inet_ntoa(iph[8]);
		destination_address = socket.inet_ntoa(iph[9]);

		#TCP protocol
		if protocol == 6 :
			t = iph_length + eth_length
			tcp_header = packet[t:t+20]

			tcph = unpack('!HHLLBBHHH' , tcp_header)
			source_port = tcph[0]
			destination_port = tcph[1]
			offset = tcph[4]
			tcph_length = offset >> 4 

			#case when user selected HTTP option
			if selected == 1:

				#handle http request (http request is when destination is 80)
				if (str(destination_port) == "80"):

					total_length = eth_length + iph_length + tcph_length * 4
					data = packet[total_length:]
					headers = data.partition(b'\r\n\r\n')[0].decode('utf-8', errors='ignore')

					#filter out invalid data files
					if "HTTP" in headers:
						print(str(num) + ' ' + str(source_address) + ':' + str(source_port) + ' ' + str(destination_address) + ':' + str(destination_port) + ' HTTP REQUEST')
						num += 1
						print(headers)
						print('\n')

				#handle http response (http response is when source is 80)
				if (str(source_port) == "80"):
				
					total_length = eth_length + iph_length + tcph_length * 4
					data = packet[total_length:]
					headers = data.partition(b'\r\n\r\n')[0].decode('utf-8', errors='ignore')

					#filter out invalid data files: 
					if "HTTP" in headers: 
						print(str(num) + ' ' + str(source_address) + ':' + str(source_port) + ' ' + str(destination_address) + ':' + str(destination_port) + ' HTTP RESPONSE')
						num += 1
						print(headers)
						print('\n')

			#case when user selected DNS option
			else:
				if (str(destination_port) == "53" or str(source_port) == '53'):
					total_length = eth_length + iph_length + tcph_length * 4
					data = packet[total_length:]
					headers = data.partition(b'\r\n\r\n')[0].decode('utf-8', errors='ignore')

					#filter out invalid data files: 
					print(str(num) + ' ' + str(source_address) + ':' + str(source_port) + ' ' + str(destination_address) + ':' + str(destination_port) + ' DNS')
					num += 1
					print(headers_text)
					print('\n')


		#UDP protocol
		if protocol == 17 and selected == 2:
			u = iph_length + eth_length
			udph_length = 8
			udp_header = packet[u:u+8]

			#now unpack them :)
			udph = unpack('!HHHH' , udp_header)
			
			source_port = udph[0]
			destination_port = udph[1]
			length = udph[2]
			checksum = udph[3]

			if (str(destination_port) == "53" or str(source_port) == '53'):
				h_size = eth_length + iph_length + udph_length
				data_size = len(packet) - h_size
				dns_data = packet[h_size:h_size+12]
				dnsh = unpack('!HHHHHH', dns_data)

				#bit operation for the multi-bit values
				middle_values = dnsh[1]
				QR = str(middle_values >> 15)
				Opcode = format((middle_values >> 11) & 15, '04b')
				AA = str((middle_values >> 10) & 1)
				TC = str((middle_values >> 9) & 1)
				RD = str((middle_values >> 8) & 1)
				RA = str((middle_values >> 7) & 1)
				Z = format((middle_values >> 4) & 7, '03b')
				RCODE = format(middle_values & 15, '04b')
				print(str(num) + ' ' + str(source_address) + ':' + str(source_port) + ' ' + str(destination_address) + ':' + str(destination_port) + '  DNS ID: ' + hex(dnsh[0]))
				print(QR + ' | ' + Opcode + ' | ' + AA + ' | ' + TC + ' | ' + RD + ' | ' + RA + ' | ' + Z + ' | ' + RCODE)
				print('QDCOUNT: ' + str(dnsh[2]))
				print('ANCOUNT: ' + str(dnsh[3]))
				print('NSCOUNT: ' + str(dnsh[4]))
				print('ARCOUNT: ' + str(dnsh[5]))

	#return this number to update the num
	return num	

main()