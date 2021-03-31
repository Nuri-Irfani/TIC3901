import argparse, os, sys, socket, datetime
import dpkt, pprint, xlsxwriter
from collections import defaultdict
from dpkt.compat import compat_ord
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from tqdm import tqdm



#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~CONSTANTS~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
#Fingerprint IPs that performed 3 or more of the same set of actions
SRATIO = 3
ACKRATIO = 10 #fragmented ACK attack may indicate DDOS attack, might require higher number to be considered suspicious.


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~FUNCTIONS~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#


# from dpkt's example code
###########################################################
def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)

    

# Use dpkt to check what flags are set in a packet, then pass into a list
###########################################################
def tcpFlags(tcp):
    ret = list()

    if tcp.flags & dpkt.tcp.TH_SYN  != 0:
        ret.append('SYN')
    if tcp.flags & dpkt.tcp.TH_RST  != 0:
        ret.append('RST')
    if tcp.flags & dpkt.tcp.TH_FIN != 0:
        ret.append('FIN')
    if tcp.flags & dpkt.tcp.TH_PUSH != 0:
        ret.append('PSH')
    if tcp.flags & dpkt.tcp.TH_ACK  != 0:
        ret.append('ACK')
    if tcp.flags & dpkt.tcp.TH_URG  != 0:
        ret.append('URG')
    if tcp.flags & dpkt.tcp.TH_ECE  != 0:
        ret.append('ECE')
    if tcp.flags & dpkt.tcp.TH_CWR  != 0:
        ret.append('CWR')
    
    return ret




# dpkt test: list all src and dst ips.
###########################################################
def pcap_IPlist(file_name):
    
    #pass to dpkt's reader
    pcap = dpkt.pcap.Reader(file_name)
    
    # Dictionary to store key:IP and value:flags
    # KEY: IP   VALUE: SYN, RST, FIN, PSH, ACK, URG, ECE, CWR
    flagchk = defaultdict(list)
    # Dictionary to store IP information
    logIP = defaultdict(list)
    

    print('processing packets... \n')
    
    # iterate through packets
    for timestamp, buf in pcap:    
        try:
            #unpack ethernet frame to read data
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                    continue
            except (dpkt.dpkt.UnpackError, IndexError):
                continue

            #get IP packet
            ip = eth.data
            if not ip:
                continue

            tcp = ip.data
            if type(tcp) != dpkt.tcp.TCP:
                continue

            #get list flags that are set in the packet
            tcpFlag = tcpFlags(tcp)
            #check if flags are set in the list
            #print(tcpFlag) 
            
            tmstmp = str(datetime.datetime.utcfromtimestamp(timestamp))


            #convert IP addresses into string format.
            src = socket.inet_ntop(socket.AF_INET, ip.src)
            dst = socket.inet_ntop(socket.AF_INET, ip.dst)

            # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
            # obtained from example code provided by dpkt
            do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
            more_fragments = bool(ip.off & dpkt.ip.IP_MF)
            fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
            
            
            # Store all IP and its info uniquely in logIP.
            if ( (src not in logIP.keys()) and (dst not in logIP.values()) ):
                logIP[src] = [ dst, ip.len, ip.ttl, mac_addr(eth.src), mac_addr(eth.dst), eth.type ]
            
            
            # put each IP and its list of set flags in another dictionary, 
            # dictionary structure: 
            # KEY: IP   VALUE: SYN, RST, FIN, PSH, ACK, URG, ECE, CWR
            if ( (src not in flagchk.keys()) and (dst not in flagchk.values()) ):
                flagchk[src] = [dst, 0, 0, 0, 0, 0, 0, 0, 0]
                

            if 'SYN' in tcpFlag:
                flagchk[src][1] += 1
            if 'RST' in tcpFlag:
                flagchk[src][2] += 1
            if 'FIN' in tcpFlag:
                flagchk[src][3] += 1
            if 'PSH' in tcpFlag:
                flagchk[src][4] += 1
            if 'ACK' in tcpFlag:
                flagchk[src][5] += 1
            if 'URG' in tcpFlag:
                flagchk[src][6] += 1
            if 'ECE' in tcpFlag:
                flagchk[src][7] += 1
            if 'CWR' in tcpFlag:
                flagchk[src][8] += 1
                
                
            
                    
        ### print checks ###
        #-------------------#
            #print(flagchk[src])

        except:
            pass
     
    
### print checks ###
#-------------------#

    print('Fingerprinting suspects... \n')
    for (src,v) in flagchk.items():
        # check for flag combinations and fingerprint them if more than 3 counts
        # SYN scans: SYN or SYN+RST
        if ( (flagchk[src][1] >= SRATIO) or (flagchk[src][1]>= SRATIO and flagchk[src][2]>= SRATIO) ):
            #flagchk[src][9] = 'SYN'
            flagchk[src].extend(['SYN'])

        # X-MAS scans: URG+PSH+ACK. Assume suspicious even if count is 1
        elif ( (flagchk[src][4]>= 1) and (flagchk[src][5]>= 1) and (flagchk[src][6] >= 1) ):
            #flagchk[src][9] = 'X-MAS'
            flagchk[src].extend(['X-MAS'])

        # Full connect: SYN+ACK || SYN+ACK+RST
        elif ( ((flagchk[src][1]>= SRATIO) and (flagchk[src][5]>= SRATIO)) or 
               ((flagchk[src][1]>= SRATIO) and (flagchk[src][2]>= SRATIO) and (flagchk[src][5]>= SRATIO)) ):
            #flagchk[src][9] = 'FULL_CONNECT'
            flagchk[src].extend(['FULL-CONNECT'])
        
        #Fragmented ACK attack: ACK || PSH+ACK
        elif ( (flagchk[src][4]>= ACKRATIO) or ((flagchk[src][4]>= ACKRATIO) and (flagchk[src][5]>= ACKRATIO)) ):
            #flagchk[src][9] = 'Frag-ACK'
            flagchk[src].extend(['Frag-ACK'])

        # if no flags are set, NULL
        elif ( (flagchk[src][1] == 0) and (flagchk[src][2] == 0) and (flagchk[src][3] == 0) and (flagchk[src][4] == 0) and 
             (flagchk[src][5] == 0) and (flagchk[src][6] == 0) and (flagchk[src][7] == 0) and (flagchk[src][8] == 0) ):
            #flagchk[src][9] = 'NULL'
            flagchk[src].extend(['NULL'])

        # if all flags are set, fingerprint also. assume suspicious even if count is 1
        elif ( (flagchk[src][1] >= 1) and (flagchk[src][2] >= 1) and (flagchk[src][3] >= 1) and (flagchk[src][4] >= 1) and 
             (flagchk[src][5] >= 1) and (flagchk[src][6] >= 1) and (flagchk[src][7] >= 1) and (flagchk[src][8] >= 1) ):
            #flagchk[src][9] = 'ALL_FLAG'
            flagchk[src].extend(['ALL_FLAG'])
            
        else:
            flagchk[src].extend(['-'])
            

    ### print checks ###
    #-------------------#            
    #for (k,v) in flagchk.items():
    #   print (k,v)
    
    #for (k,v) in logIP.items():
    #   print (k,v)
    
    #print("{:<20} {:<20} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8} {:<15} \n".format('Source', 'Destination', 'SYN', 'RST', 'FIN', 'PSH', 'ACK', 'URG', 'ECE', 'CWR', 'SCAN_TYPE'))
    #for (k,v) in flagchk.items():
    #   DST, SYN, RST, FIN, PSH, ACK, URG, ECE, CWR, SCANTYPE = v
    #   print("{:<20} {:<20} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8} {:<15}".format(k, DST, SYN, RST, FIN, PSH, ACK, URG, ECE, CWR, SCANTYPE))
    
    #logIP[src] = [ dst, ip.len, ip.ttl, mac_addr(eth.src), mac_addr(eth.dst), eth.type ]
    #-------------------#
            
    
    userIn = input('''Enter num:
    [1] To print to txt file
    [2] To print to excel 
    [3] To exit \n''')
    
    if int(userIn) == 1:    
        print('\n writing to txt file...')
        
        # show visual display of a progress bar using the tqdm module
        for i in tqdm(range(100)):
            
            with open('ScanLog.txt', 'a+') as f:

                #using prettyprint module to print dictionary into a table
                print("{:<20} {:<20} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8} {:<15} \n".format('Source', 'Destination', 'SYN', 'RST', 'FIN', 'PSH', 'ACK', 'URG', 'ECE', 'CWR', 'SCAN_TYPE'), file=f)
                for (k,v) in flagchk.items():
                    DST, SYN, RST, FIN, PSH, ACK, URG, ECE, CWR, SCANTYPE = v
                    print("{:<20} {:<20} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8} {:<15}".format(k, DST, SYN, RST, FIN, PSH, ACK, URG, ECE, CWR, SCANTYPE), file=f)
            
            with open('IPLog.txt', 'a+') as s:
                print("{:<20} {:<20} {:<8} {:<8} {:<20} {:<20} {:<8} \n".format('Source', 'Destination', 'ipLen', 'TTL', 'MAC_src', 'MAC_dst', 'ETH_type'), file=s)
                for (k,v) in logIP.items():
                    DEST, IPLEN, TTL, MACSRC, MACDST, ETHTYPE = v
                    print("{:<20} {:<20} {:<8} {:<8} {:<20} {:<20} {:<8}".format(k, DEST, IPLEN, TTL, MACSRC, MACDST, ETHTYPE), file=s)
                    
        print('Done!')
            
                    
    if int(userIn) == 2:
        wbook = xlsxwriter.Workbook('IPflags.xlsx')
        sheet1 = wbook.add_worksheet('scanLog')
        sheet2 = wbook.add_worksheet('ipLog')
        row1 = 0
        row2 = 0
        
        # styling
        bold = wbook.add_format({'bold':True})
        sheet1.set_column('A:A', 20)
        sheet1.set_column('B:B', 20)
        sheet2.set_column('A:A', 20)
        sheet2.set_column('B:B', 20)
        sheet2.set_column('E:E', 20)
        sheet2.set_column('F:F', 20)
        
        
        tableHeader = ['Source', 'Destination' 'SYN', 'RST', 'FIN', 'PSH', 'ACK', 'URG', 'ECE', 'CWR', 'SCAN_TYPE']
        sheet1.write_row(row1, 0, tableHeader, bold)
        row1 += 1
        
        tableHeader = ['Source', 'Destination', 'ipLen', 'TTL', 'MAC_src', 'MAC_dst', 'ETH_type']
        sheet2.write_row(row2, 0, tableHeader, bold)
        row2 += 1
        
        # show visual display of a progress bar using the tqdm module
        for i in tqdm(range(100)):
            for key in flagchk.keys():
                sheet1.write(row1, 0, key)
                sheet1.write_row(row1, 1, flagchk[key])
                row1 += 1
                
            for k in logIP.keys():
                sheet2.write(row2, 0, k)
                sheet2.write_row(row2, 1, logIP[k])
                row2 += 1
            
        wbook.close()
        
        print('Done!')
        
    if int(userIn) == 3:
        sys.exit(0)
       
         
            ### print checks ###
            #-------------------#
                #print("{a} : SYN = {b}, RST = {c}, FIN = {d}, PSH = {e}, ACK = {f}, URG = {g}, ECE = {h}, CWR = {i} \n".format(a=key, b=value[0], c=value[1], d=value[2], e=value[3], f=value[4], g=value[5], h=value[6], i=value[7]), file=f)
                #print("{a} has {b} \n".format(a=key, b=value), file=f)
                #print('\nTimestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)), file=f)
                #print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type, file=f)
                #print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)' % (src, dst, ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset), file=f)
                #print (tcpFlag, file=f)
            #-------------------#



#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Argparse ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--listIP', type=argparse.FileType('rb'), metavar='<pcap file name>', help='list all src and dst IPs')
    args = parser.parse_args()


    if args.listIP:
        file_name = args.listIP
        pcap_IPlist(file_name)



    sys.exit(0)
    
        
    
 