#!/usr/bin/env python3
import argparse
import time
import os
import sys

from datetime import datetime
#from scapy.all import sniff, Dot11, Dot11QoS, Dot11Elt
from scapy.all import *

#Devices which are known to be constantly probing
IGNORE_LIST = set(['00:00:00:00:00:00', '01:01:01:01:01:01'])
SEEN_DEVICES = set() #Devices which have had their probes recieved
d = {'00:00:00:00:00:00':'Example MAC Address'} #Dictionary of all named devices

#======== Global Settings (temp) =========
global total_count
global pkt_list
global packet_count

total_count = 0
pkt_list = []
packet_count = 500


#def handle_packet(pkt):
    #print('==========================================')
    #print(pkt.type)
    #print(pkt.subtype)
    #if(pkt.addr2):
        ##log.success(pkt.addr2 + ' - ' + pkt[Dot11].payload.info.decode('utf-8') + ' - ' + pkt[Dot11].payload.name)
        #print(pkt.addr2 + ' - ' + pkt[Dot11].payload.info.decode('utf-8') + ' - ' + pkt[Dot11].payload.name)
    ##global_list.append(pkt)
    ##if(pkt.haslayer(Dot11)):
        ##log.success(pkt[Dot11].addr1)
        ##log.success(pkt[Dot11].addr2)
        ##log.success(pkt[Dot11].addr3)
        ##print(pkt[Dot11].info)
        ##print(type(info))
    ##if(pkt.haslayer(Dot11)):
        ##if('fh' in pkt[Dot11].info.decode('utf-8')):
            ##print('=======')
            ##print(pkt[Dot11].info)
        ##else:
            ##print(len(global_list), end='\r')
    ##if(pkt.haslayer(Dot11QoS)):
        ##log.success('existen dot 11 QoS')
        ##for p in pkt[Dot11QoS]:
            ##log.warning('elemento')
            ##log.success(p)
    ##print(pkt.show())
    ##if(pkt.haslayer(Dot11Elt) and pkt.type == 0 and pkt.subtype == 8):
        ##for p in pkt[Dot11Elt]:
            ##log.success(p)

def checkMacAddress(mac):
	allowed_chars = '0123456789abcdef'
	mac = mac.replace(':','').lower()
	if(len(mac) != 12):
		return False
	for c in mac:
		if(c not in allowed_chars):
			return False
	return True

def handleAPPkts(verbose, bssid, essid, channel):
	def handler(pkt):
		global total_count
		total_count += 1
		#if(verbose == True):
			#print(f'{total_count} - {len(pkt_list)} - \r', end='')
		print(f'channel {channel}: {total_count} - total stations: {len(pkt_list)} - \r', end='')
		if(pkt.haslayer(Dot11) and pkt.haslayer(Dot11Elt)):
			if(pkt[Dot11].type == 0 and pkt[Dot11].subtype == 8):
				det=''
				#It's a Beacon Frame
				if(bssid == None and essid == None):
					det = f'{pkt[Dot11].channel:02} - {pkt[Dot11].addr2} - {pkt[Dot11Elt].info.decode("utf-8")}'
				elif(bssid is not None and pkt[Dot11].addr2.replace(':','').lower() == bssid):
					det = f'{pkt[Dot11].channel:02} - {pkt[Dot11].addr2} - {pkt[Dot11Elt].info.decode("utf-8")}'
				elif(essid is not None and essid.lower().strip() in pkt[Dot11Elt].info.decode("utf-8").lower().strip()):
					det = f'{pkt[Dot11].channel:02} - {pkt[Dot11].addr2} - {pkt[Dot11Elt].info.decode("utf-8")}'
				if(det not in pkt_list):
					pkt_list.append(det)
					if(verbose == True):
						print(det)
	return handler
            #print(f'{pkt[Dot11].channel} - {pkt[Dot11].addr2} - {pkt[Dot11Elt].info.decode("utf-8")}')

#def handleStationPkts(pkt):
    #global total_count
    #total_count += 1
    #print(f'{total_count} - {len(pkt_list)} - \r', end='')
    #if(pkt.haslayer(Dot11) and pkt.haslayer(Dot11Elt)):
        #if(pkt[Dot11].type == 0 and pkt[Dot11].subtype == 4):
            ##It's a Beacon Frame
            #det = f'{pkt[Dot11].channel} - {pkt[Dot11].addr2} - {pkt[Dot11Elt].info.decode("utf-8")}'
            #if(det not in pkt_list):
                #pkt_list.append(det)
	

def getAPs(channels, interface, bssid, essid, verbose):
    #Function that gets Clients for a specific Access Point
	for channel in channels:
		if(verbose == True):
			print(f'#channel {channel} on: {interface}')
		command = f'iw dev {interface} set channel {channel}'
		os.system(command)
		#Sleep 1 sec so that the monitor device is not overloaded
		time.sleep(1)
		sniff(iface=interface, count=packet_count, prn=handleAPPkts(verbose, bssid, essid, channel))
		pkt_list.sort()
	if(verbose):
		os.system('clear')
		print(f'Results: =====================')
	for i in pkt_list:
		print(i)

def deauthAP(channels, interface, bssid, essid):
	command = 'aireplay-ng -0 5 -a {bssid} {interface}'
	os.system(f'{command}')

def main():
	try:
		global packet_count
		interface = 'mon0'
		channels = ['1','6','11'] #Each channel listens to ±2 channels in frequency so the complete spectrum can be listened with these 3 channels
		bssid = None
		essid = None
		verbose = False
		if(not os.getuid() == 0 or not os.geteuid() == 0):
			print('Must be run as root or with root privileges')
			sys.exit(1)
		parser = argparse.ArgumentParser(description='Sniffs client/AP wifi MAC addresses and deauth them if needed')
		#Argument list
		parser.add_argument('-c','--channel', help='Selects (comma separated) channels, if none selected jumps through all (1, 6, 11)')
		parser.add_argument('-i','--interface', help='Selects specific interface (default mon0)', type=str)
		parser.add_argument('-p','--packets', help='Scan a specific amount of packets for each channel (default 500)', type=int)
		parser.add_argument('-a','--access-point', help='Shows only Access Points', action='store_true')
		parser.add_argument('-d','--deauth', help='deauth every station of the specificied AP (bssid or essid)', action='store_true')
		parser.add_argument('-e','--essid', help='Shows stations for this specific ESSID (name)', type=str)
		parser.add_argument('-b','--bssid', help='Shows stations for this specific BSSID (MAC address)', type=str)
		parser.add_argument('-v','--verbose', help='Verbose mode on', action='store_true')
		args = parser.parse_args()
		if(args.channel is not None):
			channels = [ x.strip(',') for x in args.channel.split(',') ]
		if(args.interface is not None):
			interface = args.interface
		if(args.packets is not None):
			packet_count = args.packets
		if(args.verbose == True):
			verbose = True
		if(args.bssid is not None):
			if(checkMacAddress(args.bssid)):
				bssid = args.bssid.replace(':','').lower()
			else:
				print('Wrong BSSID Format! must be XX:XX:XX:XX:XX:XX or XXXXXXXXXXXX')
				sys.exit(1)
		if(args.essid is not None):
			essid = args.essid
		if(args.access_point):
			if(args.deauth):
				print('Options access-point and deauth are mutually exclusive')
				sys.exit(1)
			getAPs(channels=channels, interface=interface, bssid=bssid, essid=essid, verbose=verbose)
		elif(args.deauth):
			if(args.access_point):
				print('Options access-point and deauth are mutually exclusive')
				sys.exit(1)
			if(bssid == None and essid == None):
				print('This option needs bssid (-b) or essid (-e)')
			else:
				deauthAP(channels=channels, interface=interface, bssid=bssid, essid=essid)
		else:
			print('No choice selected (-a or -d) ')
        #elif(args.stations is not None):
            #getStations(arg.stations)
	except KeyboardInterrupt:
		print('Exiting...')
	except Exception as e:
		print('Error: ' + str(e))

		#TODO:
			#List AP	####### DONE #######
			#Show amount of packets captured for each AP ####### DONE #######
			#List all Clients for AP
			#Deauth attack
			#Log as follows: date-time-AP-Client-Prev_Connected_AP

if __name__ == '__main__':
	main()

