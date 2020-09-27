import socket
from struct import *
import pcapy

def main():
	#give user choice of device
	devices = pcapy.findalldevs()
	print("Which device would you like to sniff? :")
	for i in range(len(devices)) :
		print (str(i) + '. ' + devices[i])
	index = input("Enter the device number : ")
	device = devices[int(index)]
	print("Device chosen: " + device)
	selected = int(input("Which header do you want to sniff? Enter the number (HTTP=1, DNS=2): "))
	print("Sniffing...")

	#start sniffing packets by calling sniff_packet(packet, numbering packet, http or dns)
	cap = pcapy.open_live(device , 65535 , 1 , 0)
	num = 1
	while(num) :
		header, packet = cap.next()
		num = sniff_packet(packet, num, selected)

def sniff_packet(packet, num, selected) :
	#ETHERNET
	protocol = unpack('!H' , packet[12:14])[0]
	ethernet_protocol = socket.htons(protocol)
	ethernet_size = 14

	#IP
	if ethernet_protocol == 8 :
		#only 20 bytes for ip header because we don't need the rest
		ip_header = unpack('!BBHHHBBH4s4s' , packet[ethernet_size:20+ethernet_size])

		#get IHL that each take 2 bits. Entire length of header is kept to trim correctly for next step
		ihl = ip_header[0] & 15
		ip_size = ihl * 4
		protocol = ip_header[6]
		source_address = socket.inet_ntoa(ip_header[8])
		destination_address = socket.inet_ntoa(ip_header[9])

		#TCP protocol
		if protocol == 6 :
			index = ip_size + ethernet_size
			tcp_header = unpack('!HHLLB' , packet[index:index+13])
			source_port = tcp_header[0]
			destination_port = tcp_header[1]
			offset = tcp_header[4]
			tcp_size = offset >> 4 
			total_length = ethernet_size + ip_size + tcp_size * 4

			#case when user selected HTTP option
			if selected == 1:
				http_data = packet[total_length:]
				http_header = http_data.partition(b'\r\n\r\n')[0].decode('utf-8', errors='ignore')

				#define http request and response (request: destiation is 80, response: source is 80)
				if (str(destination_port) == "80"):
					if "HTTP" in http_header:
						print(str(num) + ' ' + str(source_address) + ':' + str(source_port) + ' ' + str(destination_address) + ':' + str(destination_port) + ' HTTP REQUEST')
						print(http_header)
						print('\n')
						num += 1

				if (str(source_port) == "80"):
					if "HTTP" in http_header: 
						print(str(num) + ' ' + str(source_address) + ':' + str(source_port) + ' ' + str(destination_address) + ':' + str(destination_port) + ' HTTP RESPONSE')
						print(http_header)
						print('\n')
						num += 1

			#case when user selected DNS option
			else:
				if (str(destination_port) == "53" or str(source_port) == '53'):
					dns_data = packet[total_length:total_length+12]
					dns_header = unpack('!HHHHHH', dns_data)
					print(str(num) + ' ' + str(source_address) + ':' + str(source_port) + ' ' + str(destination_address) + ':' + str(destination_port) + '  DNS ID: ' + hex(dns_header[0]))
					handle_dns(dns_header)
					num += 1


		#UDP protocol
		if protocol == 17 and selected == 2:
			index = ip_size + ethernet_size
			udp_length = 8
			udp_header = unpack('!HHHH' , packet[index:index+8])
			
			source_port = udp_header[0]
			destination_port = udp_header[1]
			length = udp_header[2]

			if (str(destination_port) == "53" or str(source_port) == '53'):
				total_length = ethernet_size + ip_size + udp_length
				dns_data = packet[total_length:total_length+12]
				dns_header = unpack('!HHHHHH', dns_data)
				print(str(num) + ' ' + str(source_address) + ':' + str(source_port) + ' ' + str(destination_address) + ':' + str(destination_port) + '  DNS ID: ' + hex(dns_header[0]))
				handle_dns(dns_header)
				num += 1

	#return this number to update the num
	return num	

def handle_dns(dns_header):
	middle_values = dns_header[1]
	QR = str(middle_values >> 15)
	Opcode = format((middle_values >> 11) & 15, '04b')
	AA = str((middle_values >> 10) & 1)
	TC = str((middle_values >> 9) & 1)
	RD = str((middle_values >> 8) & 1)
	RA = str((middle_values >> 7) & 1)
	Z = format((middle_values >> 4) & 7, '03b')
	RCODE = format(middle_values & 15, '04b')
	print(QR + ' | ' + Opcode + ' | ' + AA + ' | ' + TC + ' | ' + RD + ' | ' + RA + ' | ' + Z + ' | ' + RCODE)
	print('QDCOUNT: ' + str(dns_header[2]))
	print('ANCOUNT: ' + str(dns_header[3]))
	print('NSCOUNT: ' + str(dns_header[4]))
	print('ARCOUNT: ' + str(dns_header[5]))
	print('\n')

main()