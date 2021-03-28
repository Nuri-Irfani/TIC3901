import argparse, os, sys, socket, datetime
import dpkt, pprint, xlsxwriter
from collections import defaultdict
from dpkt.compat import compat_ord
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from tqdm import tqdm



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

    print('processing packets...')
    
    for timestamp, buf in pcap:    # iterate through packets
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


            #convert IP addresses into string format.
            src = socket.inet_ntop(socket.AF_INET, ip.src)
            dst = socket.inet_ntop(socket.AF_INET, ip.dst)

            # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
            # obtained from example code provided by dpkt
            do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
            more_fragments = bool(ip.off & dpkt.ip.IP_MF)
            fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
            
            
            # put each IP and its list of set flags in a dictionary
            # dictionary structure: 
            # KEY: IP   VALUE: SYN, RST, FIN, PSH, ACK, URG, ECE, CWR
            if src not in flagchk.keys():
                flagchk[src] = [0, 0, 0, 0, 0, 0, 0, 0]

            if 'SYN' in tcpFlag:
                flagchk[src][0] += 1
            if 'RST' in tcpFlag:
                flagchk[src][1] += 1
            if 'FIN' in tcpFlag:
                flagchk[src][2] += 1
            if 'PSH' in tcpFlag:
                flagchk[src][3] += 1
            if 'ACK' in tcpFlag:
                flagchk[src][4] += 1
            if 'URG' in tcpFlag:
                flagchk[src][5] += 1
            if 'ECE' in tcpFlag:
                flagchk[src][6] += 1
            if 'CWR' in tcpFlag:
                flagchk[src][7] += 1
                    
        ### print checks ###
        #-------------------#
            #print(flagchk[src])

        except:
            pass
     
    
### print checks ###
#-------------------#
    #print("{:<20} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8} \n".format('IP Address', 'SYN', 'RST', 'FIN', 'PSH', 'ACK', 'URG', 'ECE', 'CWR'))
    #for k,v in flagchk.items():
                    #SYN, RST, FIN, PSH, ACK, URG, ECE, CWR = v
                    #print("{:<20} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8}".format(k, SYN, RST, FIN, PSH, ACK, URG, ECE, CWR))
            
    
    userIn = input('''Enter num:
    [1] To print to txt file
    [2] To print to excel \n''')
    
    if int(userIn) == 1:    
        print('\n writing to txt file...')
        for i in tqdm(range(100)):
            with open('output.txt', 'a+') as f:

                #using prettyprint module to print dictionary into a table
                print("{:<20} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8} \n".format('IP Address', 'SYN', 'RST', 'FIN', 'PSH', 'ACK', 'URG', 'ECE', 'CWR'), file=f)
                for k,v in flagchk.items():
                    SYN, RST, FIN, PSH, ACK, URG, ECE, CWR = v
                    print("{:<20} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8} {:<8}".format(k, SYN, RST, FIN, PSH, ACK, URG, ECE, CWR), file=f)
                    
    if int(userIn) == 2:
        wbook = xlsxwriter.Workbook('IPflags.xlsx')
        wsheet = wbook.add_worksheet()
        row = 0
        
        # styling
        bold = wbook.add_format({'bold':True})
        wsheet.set_column('A:A', 20)
        
        
        tableHeader = ['IP Address', 'SYN', 'RST', 'FIN', 'PSH', 'ACK', 'URG', 'ECE', 'CWR']
        wsheet.write_row(row, 0, tableHeader, bold)
        row += 1
        
        for key in flagchk.keys():
            wsheet.write(row, 0, key)
            wsheet.write_row(row, 1, flagchk[key])
            row += 1
            
        wbook.close()
       
         
            ### print checks ###
            #-------------------#
                #print("{a} : SYN = {b}, RST = {c}, FIN = {d}, PSH = {e}, ACK = {f}, URG = {g}, ECE = {h}, CWR = {i} \n".format(a=key, b=value[0], c=value[1], d=value[2], e=value[3], f=value[4], g=value[5], h=value[6], i=value[7]), file=f)
                #print("{a} has {b} \n".format(a=key, b=value), file=f)
                #print('\nTimestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)), file=f)
                #print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type, file=f)
                #print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)' % (src, dst, ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset), file=f)
                #print (tcpFlag, file=f)



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
    
        
    
 