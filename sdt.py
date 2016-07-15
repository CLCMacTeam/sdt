'''
Service Discovery Tool
This tool broadcasts requests for DHCP and BSDP,
returning the results to a plist or screen.

For more information use:
    sdt.py -h

Requires: python3

Written Rusty Myers June 2016 with much help from @frogor and @bruienne.
Original writtn by hassane: http://code.activestate.com/recipes/577649-dhcp-query/ Created on Mar 27, 2011
notes:  BSDP format - https://static.afp548.com/mactips/bootpd.html
        http://stackoverflow.com/questions/24196932/how-can-i-get-the-ip-address-of-eth0-in-python
        https://www.ietf.org/rfc/rfc2132.txt
        http://stackoverflow.com/questions/24131812/plistlib-to-update-existing-plist-file
'''
import socket, argparse, struct, plistlib, os
from uuid import getnode as get_mac
from random import randint

# Get the MAC address in bytes
def getMacInBytes():
    mac = str(hex(get_mac()))
    mac = mac[2:]
    while len(mac) < 12 :
        mac = '0' + mac
    macb = b''
    for i in range(0, 12, 2) :
        m = int(mac[i:i + 2], 16)
        macb += struct.pack('!B', m)
    return macb

# Get the IP Address
# http://stackoverflow.com/questions/24196932/how-can-i-get-the-ip-address-of-eth0-in-python
def get_ip_address():
    # create a new socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # connect on 80
    s.connect(("8.8.8.8", 80))
    # get IP from socket
    return s.getsockname()[0]

# Get the IP Address in Bytes
def getIPInBytes():
    currIP=get_ip_address().split('.') # put IP address into list
    # print(currIP) # print current IP for testing
    bcurrIP=b'' # Create new byte holder
    for i in currIP:
        # add each part of IP as byte into byte holder
        bcurrIP += struct.pack("!B", int(i))
    # return byte formated IP
    return bcurrIP

def openSocket(port):
    # defining the socket
    dhcps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    #internet, UDP
    dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) #broadcast

    try:
        if packetType is "dhcp":
            dhcps.bind(('', port))    #we want to listen on 68 for DHCP
        else:
            dhcps.bind(('', port))    #we want to listen on 993 for BSDP
    except Exception as e:
        print('port 68 in use...')
        dhcps.close()
        input('press any key to quit...')
        exit(0)
    return dhcps
    
# Deal with Vendor block from BSDP packet
def parse_vendor(v_opts):
    # Vendor Options Breakdown:
    # [1,1,1] = BSDP message type (1), length (1), value (1 = list)
    # [4,2,255,255] = Server priority message type 4, length 2, value 0xffff (65535 - Highest)
    # [7,4, x, x] = Option 7 (4) Default Boot Image ID number
    # [9,l, x] Boot Image List option 9 (l = random length) x = image names
    
    # Example Codes:    
    # Vendor Option Block
    #\x01\x01\x01 - [1,1,1] = BSDP message type (1), length (1), value (1 = list)
    #\x04\x02\xd6\xcb - [4,2,255,255] = Server priority message type 4, length 2, value 0xffff (65535 - Highest)
    #\x07\x04\x81\x00\x13\xba - Option 7 (4bytes long) Default Boot Image ID
    #\x09\x11\x81\x00\x13\xba\x0c\x43\x4c\x4d\x42\x75\x69\x6c\x64\x4d\x65\x6e\x75 - Boot Image List option (option 9)
    
    # Create and array of bytes to deal with it
    b = bytearray(v_opts)
    results = dict()
    while b:
        option_code  = b.pop(0)
        option_len   = b.pop(0)
        option_value = b[0:option_len]
        del b[0:option_len]
        if option_code == 9:
            # We found our list
            # Now to consume it
            # the list can have multiple entries and each will have its NBI ID 4 bytes as header
            # the full list length will be ALL of those entries - length of name plus 4-byte ID header
            nbi_list = []
            while option_value:
                nbi_id   = struct.unpack('!H', option_value[2:4])
                del option_value[0:4]
                nbi_len  = option_value.pop(0)
                nbi_name = option_value[0:nbi_len]
                del option_value[0:nbi_len]
                nbi_list.append((nbi_id[0], nbi_name.decode('utf-8')))
            results['nbi_list'] = nbi_list
        elif option_code == 7:
            default_nbi = struct.unpack('!H', option_value[2:4])
            results['default_nbi'] = default_nbi[0]
    return results

def writeDHCPPlist(plistPath,offer):
    '''
    Write DHCP info to Plist for Serice Discovery Tool
    '''
    dhcpServer = offer.DHCPServerIdentifier
    ipAdd = offer.offerIP
    # Check for existing DHCP Info
    if os.path.exists(plistPath):
        try:
            pldata = plistlib.readPlist(plistPath)
        except:
            print("Can't read plist.")
        try:
            # Update to current values
            pldata["dhcp"]["dhcpserverip"] = dhcpServer
        
            pldata["dhcp"]["ipaddress"] = ipAdd
            #print("Found existing DHCP Settings, Updating Plist...")
        except:
            print("Couldn't Write DHCP Settings.")
    else:
        pldata = dict(bsdp = [],dhcp = dict(dhcpserverip=dhcpServer, ipaddress=ipAdd))
        
    try:
        plistlib.writePlist(pldata, plistPath)
    except NameError as e:
        print("Failed to write plist!")
        print(e)
        
def writeBSDPPlist(plistPath,offers):
    '''
    Write BSDP info to Plist for Service Discovery Tool.
    Test with QnA: 
    concatenations " " of  ("Server:"; concatenations " nbis=(" of  ( strings "ip" of it; ( concatenations "; " of (concatenation ", " of (strings "name" of it; strings "id" of it; booleans "default" of it as string) ) of dictionaries of values of arrays "nbis" of it ) );")" ) of dictionaries of values of array "bsdp" of dictionary of file "/tmp/new.plist"

    '''
    
    # Create Variables for DHCP Info
    dhcpServer = ""
    ipAdd = ""
    # Check for existing DHCP Info
    if os.path.exists(plistPath):
        try:
            p = plistlib.readPlist(plistPath)
        except:
            print("Can't read plist.")    
        try:
            # Update to current values
            dhcpServer = p["dhcp"]["dhcpserverip"]
            ipAdd = p["dhcp"]["ipaddress"]
            #print("Found existing DHCP Settings, Updating Plist...")
        except:
            print("Couldn't Find DHCP Settings. No bother.")
            
    # Setup basic structure for BSDP and DHCP
    pldata = dict(bsdp = [],dhcp = dict(dhcpserverip=dhcpServer, ipaddress=ipAdd))
    
    #print("Received {0} offers".format(len(offers)))
    for N in range(0, len(offers)):
        # Gather some data from the offer
        # Example Offer vendorOptionResults: 
        #{'nbi_list': [(1095, 'DSR-1095'), (864, 'NetInstall of Install OS X El Capitan 10.11.3 - 15D21')], 'default_nbi': 1095}
        # Update BSDP array with first offer nbi_list
        
        # Get Server IP
        offerServerIP = offers[N].BSDPServerIP
        #print(offerServerIP)
        # Get Default NBI
        defaultOfferNBI = offers[N].vendorOptionResults['default_nbi']
        #print(defaultOfferNBI)
    
        # Create new Server Dictionary
        serverDict = {}
        serverDict['ip'] = offerServerIP
        serverDict['nbis'] = []
    
        # Update BSDP array 
        for anNBI in offers[N].vendorOptionResults['nbi_list']:
            offerID = anNBI[0]
            offerName = anNBI[1]
            #print(offerName, offerID)
            # Is this our default?
            if defaultOfferNBI == offerID:
                # This is default
                defaultNBI = True
            else:
                defaultNBI = False
                
            serverDict['nbis'].append(dict(
                name=offerName,
                id=str(offerID),
                default=defaultNBI))
        
        pldata['bsdp'].append(serverDict)

    # print(pldata)
    
    try:
        plistlib.writePlist(pldata, plistPath)
    except e:
        print("Failed to write plist!")
        print(e)

def testOne():
    # Test Data from OS X 10.11 NetBoot Server and exit
    data=b'\x02\x01\x06\x00\re\x88\xa4\x00\x00\x00\x00\n\x00\x01]\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\xe6P\t\xed\xa2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x82Sc5\x01\x056\x04\n\x00\x01\x07<\tAAPLBSDPC+V\x01\x01\x01\x04\x02\x7f\xfe\x07\x04\x82\x00\x04G\tG\x82\x00\x04G\x08DSR-1095\x81\x00\x03`5NetInstall of Install OS X El Capitan 10.11.3 - 15D21\xff'
    offer = BSDPOffer(data, b'\x0d\x65\x88\xa4')
    offer.printBSDPOffer()
    plistPath="/tmp/org.network.plist"
    writeBSDPPlist(plistPath, [offer])
    exit(0)
        
class DHCPDiscover:
    def __init__(self):
        self.transactionID = b''
        for i in range(4):
            t = randint(0, 255)
            self.transactionID += struct.pack('!B', t) 

    def buildPacket(self,packType):
        macb = getMacInBytes()
        if packType is "dhcp":
            packet = b''
            packet += b'\x01'   #Message type: Boot Request (1)
            packet += b'\x01'   #Hardware type: Ethernet
            packet += b'\x06'   #Hardware address length: 6
            packet += b'\x00'   #Hops: 0 
            packet += self.transactionID       #Transaction ID
            packet += b'\x00\x00'    #Seconds elapsed: 0
            packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
            packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
            packet += b'\x00\x00\x00\x00'   #Your (client) IP address: 0.0.0.0
            packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
            packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
            #packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
            packet += macb
            packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
            packet += b'\x00' * 67  #Server host name not given
            packet += b'\x00' * 125 #Boot file name not given
            packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
            # DHCP IP Address
            packet += b'\x35\x01\x01'   #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
            packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
            packet += b'\x3d\x06' + macb
            packet += b'\x37\x03\x03\x01\x06'   #Option: (t=55,l=3) Parameter Request List
            packet += b'\xff'   #End Option
            packet += b'\x00' * 6
            return packet
        else:
            # Build BSDP Packet
            clientIPb = getIPInBytes()
            packet = b''
            packet += b'\x01'   #Message type: Boot Request (1)
            packet += b'\x01'   #Hardware type: Ethernet
            packet += b'\x06'   #Hardware address length: 6
            packet += b'\x00'   #Hops: 0 
            packet += self.transactionID       #Transaction ID
            packet += b'\x00\x00'    #Seconds elapsed: 0
            packet += b'\x00\x00'   #Bootp flags: 0x0000 (Unicast) + reserved flags
            packet += clientIPb # Client IP address
            #packet += b'\x00\x00\x00\x00'   # Client IP address: 0.0.0.0
            packet += b'\x00\x00\x00\x00'   #Your (client) IP address: 0.0.0.0
            packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
            packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
            #packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
            packet += macb
            packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
            packet += b'\x00' * 67  #Server host name not given
            packet += b'\x00' * 125 #Boot file name not given
            packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
            # NetBoot List Request
            packet += b'\x35\x01\x08'   #Option: (t=53,l=1) DHCP Message Type = DHCP INFORM[LIST]
            packet += b'\x37\x02\x3c\x2b'   #Option: (t=55,l=2) Parameter Request List - Option 60 (3c) and 43 (2b)
            packet += b'\x39\x02\x05\xdc' # Option 57, length 2, max dhcp message sizeL 1500
            # Short APLBSDPC
            # packet += b'\x3c\x39\x41\x41\x50\x4c\x42\x53\x44\x50\x43' # #Option: (t=60,l=9) Client identifier APLBSDPC
            # Long APLBSDPC
            packet += b'\x3c\x17\x41\x41\x50\x4c\x42\x53\x44\x50\x43' # #Option: (t=60,l=23) Client identifier APLBSDPC + next line
            packet += b'\x2f\x69\x33\x38\x36\x2f\x69\x4d\x61\x63\x31\x34\x2c\x32' #Model /i386/iMac14,2
            packet += b'\x2b\x0f\x01\x01\x01\x02\x02\x01\x01\x05\x02\x03\xe1\x0c\x02\x20\x00' #Option 43 vendor specific???        
            packet += b'\xff'   #End Option
            return packet

class BSDPOffer:
    def __init__(self, data, transID):
        self.type = "bsdp"
        self.data = data
        self.transID = transID
        self.message_type = ''
        self.hardware_type = ''
        self.hardware_length = ''
        self.hops = ''
        self.ClientIP = ''
        self.nextServerIP = ''
        self.vendorOptionResults = {}
        self.BSDPServerIP = ''
        self.vendorClassID = ''
        self.unpack()
    
    def unpack(self):
        print(self.data) # print out the data for testing
        if self.data[4:8] == self.transID :
            # print('{0}{1}'.format('Length: ', len(self.data)))
            # print(self.transID)
            b = bytearray(self.data)
            results = dict()
            self.message_type = b.pop(0)
            # print(self.message_type)
            self.hardware_type = b.pop(0)
            # print(self.hardware_type)
            self.hardware_length = b.pop(0)
            # print(self.hardware_length)
            self.hops = b.pop(0)
            # print(self.hops)
            del b[0:4] # transaction ID
            del b[0:2] # seconds elapsed
            del b[0:2] # bootpflags
            self.ClientIP = '.'.join(map(lambda x:str(x), b[0:4]))
            del b[0:4]
            del b[0:4] # Your (client) IP Address
            del b[0:4] # Next server IP Address
            del b[0:4] # Relay Agent IP Address
            del b[0:self.hardware_length] # Client MAC Address
            del b[0:10] # Client hardware address padding
            del b[0:64] # Server Host Name Not given
            del b[0:128] # Boot file name not given
            del b[0:4] # Magic Cookie
            while b:
                option_code  = b.pop(0)
                if option_code == 255:
                    # if we get option code 255, we're at the resturant at the end of the packet.
                    break
                option_len   = b.pop(0)
                option_value = b[0:option_len]
                # print("Code: {0}  Length: {1} - Value: {2}".format(option_code, option_len, option_value))
                if option_code == 43:
                    self.vendorOptionResults = parse_vendor(option_value)
                    # print(self.vendorOptionResults)
                if option_code == 54:
                    self.BSDPServerIP = '.'.join(map(lambda x:str(x), b[0:option_len]))
                    # print(self.BSDPServerIP)
                if option_code == 60:
                    self.vendorClassID = "".join(map(chr, b[0:option_len]))
                # Remove the option to process the next
                del b[0:option_len]

    def printBSDPOffer(self):
        print('{0:20s} : {1:15s}'.format('BSDP Server IP', self.BSDPServerIP))
        print('{0:20s}{1}'.format('NetBoot Image Names ', ' : ' , end=''))
        # Indexes greater than 4096 are globally unique
        if self.vendorOptionResults['nbi_list'][0]:
            if self.vendorOptionResults['default_nbi'] == self.vendorOptionResults['nbi_list'][0][0]:
                print('{0:10s}  (ID: {2:4d}) {1} (Default)'.format(' ', self.vendorOptionResults['nbi_list'][0][1], self.vendorOptionResults['nbi_list'][0][0]))
            else:
                print('{0:10s}  (ID: {2:4d}) {1:15s} '.format(' ', self.vendorOptionResults['nbi_list'][0][1], self.vendorOptionResults['nbi_list'][0][0]))
            
        if len(self.vendorOptionResults['nbi_list']) > 1:
            for i in range(1, len(self.vendorOptionResults['nbi_list'])): 
                print('{0:10s}  (ID: {2:4d}) {1:15s} '.format(' ', self.vendorOptionResults['nbi_list'][i][1], self.vendorOptionResults['nbi_list'][i][0]))


    def printBSDPDetailOffer(self):
        key = ['Client IP', 'BSDP Server IP' , 'Vendor Class ID']
        val = [self.ClientIP, self.BSDPServerIP, self.vendorClassID]
        for i in range(3):
            print('{0:20s} : {1:15s}'.format(key[i], val[i]))
        
        # print(self.vendorOptionResults['nbi_list'])
        print('{0:20s}{1}'.format('NetBoot Image Names ', ' : ' , end=''))
        if self.vendorOptionResults['nbi_list'][0]:
            print('{0:21s}  (ID: {2:4d}) {1:15s} '.format(' ', self.vendorOptionResults['nbi_list'][0][1], self.vendorOptionResults['nbi_list'][0][0]))
        if len(self.vendorOptionResults['nbi_list']) > 1:
            for i in range(1, len(self.vendorOptionResults['nbi_list'])): 
                print('{0:21s}  (ID: {2:4d}) {1:15s} '.format(' ', self.vendorOptionResults['nbi_list'][i][1], self.vendorOptionResults['nbi_list'][i][0]))

        print('{0:20s} : {1:3d}'.format('Default Image ID ', self.vendorOptionResults['default_nbi']))


class DHCPOffer:
    def __init__(self, data, transID):
        self.type = "dhcp"
        self.plistName = "/tmp/com.example.dhcptest.plist"
        self.data = data
        self.transID = transID
        self.offerIP = ''
        self.nextServerIP = ''
        self.DHCPServerIdentifier = ''
        self.leaseTime = ''
        self.router = ''
        self.subnetMask = ''
        self.DNS = []
        self.unpack()
    
    def unpack(self):
        print('{0}{1}'.format('Length: ', len(self.data)))
        if self.data[4:8] == self.transID :
            self.offerIP = '.'.join(map(lambda x:str(x), data[16:20]))
            self.nextServerIP = '.'.join(map(lambda x:str(x), data[20:24]))  #c'est une option
            self.DHCPServerIdentifier = '.'.join(map(lambda x:str(x), data[245:249]))
            self.leaseTime = str(struct.unpack('!L', data[251:255])[0])
            self.router = '.'.join(map(lambda x:str(x), data[257:261]))
            self.subnetMask = '.'.join(map(lambda x:str(x), data[263:267]))
            dnsNB = int(data[268]/4)
            # dnsNB = ord(data[268])/4 
            for i in range(0, 4 * dnsNB, 4):
                self.DNS.append('.'.join(map(lambda x:str(x), data[269 + i :269 + i + 4])))
                
    def printOffer(self):
        key = ['DHCP Server', 'Offered IP address', 'subnet mask', 'lease time (s)' , 'default gateway']
        val = [self.DHCPServerIdentifier, self.offerIP, self.subnetMask, self.leaseTime, self.router]
        for i in range(5):
            print('{0:20s} : {1:15s}'.format(key[i], val[i]))
        
        print('{0:20s}{1}'.format('DNS Servers ', ' : ' , end=''))
        if self.DNS:
            print('{0:21s}  {1:15s}'.format(' ', self.DNS[0]))
        if len(self.DNS) > 1:
            for i in range(1, len(self.DNS)): 
                print('{0:22s} {1:15s}'.format(' ', self.DNS[i])) 

    def writePlist(self, plistPath):
        try:
            p = plistlib.readPlist(sysrecord.plistPath)
            p["ipaddress"] = attr_
            plistlib.writePlist(p, sysrecord.plistPath)
        except:
            print("Failured to write plist: ")
        infoPlist = dict(dhcp=dict(
            ipaddress = self.offerIP,
            dhcpserverip = self.DHCPServerIdentifier))
        with open(plistPath, 'wb') as fp:
            plistlib.dump(infoPlist, fp)

if __name__ == '__main__':
    # Get our arguments
    parser = argparse.ArgumentParser(description='Check, Print, and Save DHCP & BSDP Information.')
    parser.add_argument('-d', '--dhcp', action='store_true', \
                dest='choiceDHCP', help='Send DHCP Broadcast and process results.')
    parser.add_argument( '-b', '--bsdp', action='store_true', \
                dest='choiceBSDP', help='Send BSDP Inform and process results.')
    parser.add_argument('-p', '-plist' , action='store', default='/Library/Preferences/org.network.plist', \
                dest='plistPath', help='Path to plist for saving results to plist. Default: /Library/Preferences/org.network.plist')
    parser.add_argument('-t1', '--testOne', action='store_true', \
                dest='testONE', help='Test code with stored BSDP response from OS X Server, writing to /tmp/org.network.plist.')
    args = parser.parse_args()
    
    # Pull out Arguments
    plistPath = args.plistPath
    
    if args.testONE:
        testOne()

    # Process Arguments
    if args.choiceDHCP:
        packetType="dhcp"
        dhcps = openSocket(68)
        #buiding and sending the DHCPDiscover packet
        discoverPacket = DHCPDiscover()
        dhcps.sendto(discoverPacket.buildPacket(packetType), ('<broadcast>', 67))
        print('DHCP Discover sent waiting for reply...\n')
        #receiving DHCPOffer packet  
        dhcps.settimeout(5)
        try:
            while True:
                data = dhcps.recv(1024)
                offer = DHCPOffer(data, discoverPacket.transactionID)
                if offer.offerIP:
                    offer.printOffer()
                    # Write plist location from argparse
                    # Update/Write plist with DHCP settings
                    writeDHCPPlist(plistPath, offer)
                    break
        except socket.timeout as e:
            print(e)
        dhcps.close()   #we close the socket
        
    if args.choiceBSDP:
        packetType="bsdp"
        dhcps = openSocket(993)
        #buiding and sending the DHCPDiscover packet
        discoverPacket = DHCPDiscover()
        dhcps.sendto(discoverPacket.buildPacket(packetType), ('<broadcast>', 67))
        print('BSDP Discover sent waiting for reply...\n')
        
        bsdpOffers = []
        #receiving DHCPOffer packet  
        dhcps.settimeout(10)
        try:
            while True:
                data = dhcps.recv(1024)
                offer = BSDPOffer(data, discoverPacket.transactionID)
                if offer.BSDPServerIP:
                    bsdpOffers.append(offer)
        except socket.timeout as e:
            print(e)
            print("Results : ")
        # Close the socket connection
        dhcps.close()
        # Print the offers
        bsdpOffers[0].printBSDPOffer()
        if len(bsdpOffers) > 1:
            for i in range(1, len(bsdpOffers)):
                bsdpOffers[1].printBSDPOffer()
        # send writeBSDPPlist the name of the plist and a list of offers
        writeBSDPPlist(plistPath,bsdpOffers)
        
    # Yay
    exit()
