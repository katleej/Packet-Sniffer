import socket
import struct
import pcapy

def main():
    devs = pcapy.findalldevs()
    print(devs)

main()