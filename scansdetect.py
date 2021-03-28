import argparse, os, sys, socket, datetime
import dpkt, pyshark
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


# for sorting. Return negative if ip1 < ip2, 
# 0 if they are equal, positive if ip1 > ip2.
###########################################################
def compare_IPs(ip1, ip2):
    return sum(map(int, ip1.split('.'))) - sum(map(int, ip2.split('.')))

    

# Set flags in TCP packet
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
    
    flagchk = defaultdict(list) # Dictionary of suspects. suspect's IP: {# SYNs, # SYN-ACKs}

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

            #get flags that are set in the packet
            tcpFlag = tcpFlags(tcp)


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
            for flags in tcpFlag:
                if flags == 'SYN':
                    if src not in flagchk:
                        flagchk[src] = {'SYN': 0, 'SYN-ACK': 0}
                    flagchk[src]['SYN'] += 1
                if flags == ('SYN','ACK'):
                    if dst not in flagchk:
                        flagchk[dst] = {'SYN': 0, 'SYN-ACK':0}
                    flagchk[src]['SYN-ACK'] += 1

        except:
            pass
            
    
    print('writing to txt file...')
    sorted_flagchk = flagchk.items(),key=lambda
    for i in tqdm(range(100)):
        with open('output.txt', 'a+') as f:
            for key, value in flagchk.items():
                print("{a} has {b} \n".format(a=key, b=value), file=f)
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
    
        
    
 