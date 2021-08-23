#!/usr/bin/env python3
import argparse
import time
import os
import sys

from datetime import datetime
#from scapy.all import sniff, Dot11, Dot11QoS, Dot11Elt
#from scapy.all import *

#Devices which are known to be constantly probing
IGNORE_LIST = set(['00:00:00:00:00:00', '01:01:01:01:01:01'])
SEEN_DEVICES = set() #Devices which have had their probes recieved
d = {'00:00:00:00:00:00':'Example MAC Address'} #Dictionary of all named devices

#======== Global Settings (temp) =========
global total_count
global pkt_list
global interface
global packet_count

total_count = 0
pkt_list = []
interface = 'mon0'
packet_count = 100

def handle_packet(pkt):
    print('==========================================')
    print(pkt.type)
    print(pkt.subtype)
    if(pkt.addr2):
        #log.success(pkt.addr2 + ' - ' + pkt[Dot11].payload.info.decode('utf-8') + ' - ' + pkt[Dot11].payload.name)
        print(pkt.addr2 + ' - ' + pkt[Dot11].payload.info.decode('utf-8') + ' - ' + pkt[Dot11].payload.name)
    #global_list.append(pkt)
    #if(pkt.haslayer(Dot11)):
        #log.success(pkt[Dot11].addr1)
        #log.success(pkt[Dot11].addr2)
        #log.success(pkt[Dot11].addr3)
        #print(pkt[Dot11].info)
        #print(type(info))
    #if(pkt.haslayer(Dot11)):
        #if('fh' in pkt[Dot11].info.decode('utf-8')):
            #print('=======')
            #print(pkt[Dot11].info)
        #else:
            #print(len(global_list), end='\r')
    #if(pkt.haslayer(Dot11QoS)):
        #log.success('existen dot 11 QoS')
        #for p in pkt[Dot11QoS]:
            #log.warning('elemento')
            #log.success(p)
    #print(pkt.show())
    #if(pkt.haslayer(Dot11Elt) and pkt.type == 0 and pkt.subtype == 8):
        #for p in pkt[Dot11Elt]:
            #log.success(p)

def main_args():
    parser = argparse.ArgumentParser(description='Sniffs client/AP wifi MAC addresses and logs them')
    #parser.add_argument('-i','--interface', help='Selects specific interface (default mon0)', type=str)
    #parser.add_argument('-p','--packets', help='Number of packets to retrieve per channel (default 100)', type=str )
    #parser.add_argument('-a','--access-point', help='Shows only Access Points', action='store_true')
    #parser.add_argument('-c','--channel', help='Selects (comma separated) channels, if none selected jumps through all (1, 6, 11)', type=int )

    #parser.add_argument('-d','--deauth', help='Deauthenticates specified mac (case unsensitive with or without ":")', action='store_true')

    #parser.add_argument('-cl','--client', help='Shows only clients', action='store_true')
    #parser.add_argument('-v','--verbosity', help='increases verbosity', action="count")
    #parser.add_argument('-s','--search', help='Search for specific AP to show (if SSID contains case unsensitive searchword)', type=str )
    args = parser.parse_args()

    #if(args.verbosity == 1):
        #print("Verbose on")
    #elif(args.verbosity == 2):
        #print("More verbosity")
    #elif(args.verbosity == 3):
        #print("Moar verbosity")
    #sniff(iface=eth0, prn=

#================================================================================================


def handle_AP_pkts(pkt):
    global total_count
    total_count += 1
    print(f'{total_count} - {len(pkt_list)} - \r', end='')
    if(pkt.haslayer(Dot11) and pkt.haslayer(Dot11Elt)):
        if(pkt[Dot11].type == 0 and pkt[Dot11].subtype == 8):
            #It's a Beacon Frame
            det = f'{pkt[Dot11].channel} - {pkt[Dot11].addr2} - {pkt[Dot11Elt].info.decode("utf-8")}'
            if(det not in pkt_list):
                pkt_list.append(det)
                print(det)
            #log.success(f'{pkt[Dot11].channel} - {pkt[Dot11].addr2} - {pkt[Dot11Elt].info.decode("utf-8")}')

def get_APs(c=None):
    #Function that gets Access Points beacons for all channels
        if(c == None):
            #Each channel listens to ±2 channels in frequency
            #so the complete spectrum can be listened with these 3 channels
            channels = [1, 6, 11]
        else:
            channels = c.split(',')
        for i in channels:
            #log.info(f'Jumping to #channel {i} on interface: {interface}')
            print(f'Jumping to #channel {i} on interface: {interface}')
            command = f'iw dev {interface} set channel {i}'
            os.system(command)
            #Sleep 1 sec so that the monitor device is not overloaded
            time.sleep(1)
            #log.success(f'channel {i} +/-1 ok')
            sniff(iface='mon0', count=packet_count, prn=handle_AP_pkts)
        pkt_list.sort()
        for i in pkt_list:
            #log.success(i)
            print(i)

def main():
    try:
        global interface
        if(not os.getuid() == 0 or not os.geteuid() == 0):
            print('Must be run as root or with root privileges')
            #log.failure('Must be run as root or with root privileges')
            sys.exit(1)
        parser = argparse.ArgumentParser(description='Sniffs client/AP wifi MAC addresses and logs them')
        #Argument list
        parser.add_argument('-c','--channel', help='Selects (comma separated) channels, if none selected jumps through all (1, 6, 11)')
        parser.add_argument('-a','--access-point', help='Shows only Access Points', action='store_true')
        parser.add_argument('-cl','--clients', help='Shows clients for this specific AP''s MAC address', action='store_true')
        parser.add_argument('-i','--interface', help='Selects specific interface (default mon0)', type=str)

        args = parser.parse_args()

        #log.info('Starting...')
        print('Starting...')
        if(args.channel is not None):
            channels = [ x.strip(',') for x in args.channel.split(',') ]
        time.sleep(1)
        if(args.interface != ''):
            #log.info(str(args.interface))
            print(str(args.interface))
            interface = args.interface
        time.sleep(1)
        if(args.access_point):
            get_APs()

        time.sleep(1)
    except KeyboardInterrupt:
        print('Exiting...')
        #log.warning('Exiting...')
    #except PwnlibException as msg:
        #print('pwntools exception with message: ' + str(msg))
        #pass
        #print(f'{msg}')
    except Exception as e:
        print('Error: ' + str(e))

    #TODO:
        #List AP
        #List all Clients for AP
        #Deauth attack
        #Log as follows: date-time-AP-Client-Prev_Connected_AP

if __name__ == '__main__':
	main()

