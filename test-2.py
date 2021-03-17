import argparse, os, sys, socket
import dpkt, pyshark
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP



#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~FUNCTIONS~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

# scapy test: list all TCP packets. scapy is confusing.
# need to find more tutorials
###########################################################
def pcap_Reader(file_name):
    count = 0
    TCP_count = 0
    
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        count += 1
        
        ether_pkt = Ether(pkt_data)

        # exclude non-IPv4 packets
        if ether_pkt.type != 0x0800:
            continue

        # exclude non-TCP packet
        ip_pkt = ether_pkt[IP]
        if ip_pkt.proto != 6:
            continue

        TCP_count += 1

    print('{} contains {} packets ({} TCP... maybe)'.
          format(file_name, count, TCP_count))
    

    
# dpkt test: list all src and dst ips.
###########################################################
def pcap_IPlist(file_name):
    
    #pass to dpkt's reader
    pcap = dpkt.pcap.Reader(file_name)

    for (ts,buff) in pcap:
        try:
            #unpack ethernet frame to read data
            eth = dpkt.ethernet.Ethernet(buff)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue 

            #get IP packet
            ip = eth.data
            if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue

            #convert IP addresses into string format.
            src = socket.inet_ntop(socket.AF_INET, ip.src)
            dst = socket.inet_ntop(socket.AF_INET, ip.dst)

            # Print the source and destination IP
            #sys.stdout = open('output.txt','wt')
            with open('output.txt', 'a+') as f:
                print('Source: ' +src+ ' Destination: '  +dst, file=f)

        except:
            pass
        


# Closed scans detection attempt (RST-ACK response)
###########################################################
def pcap_detClosed(file_name):
    
    #pass to dpkt's reader
    pcap = dpkt.pcap.Reader(file_name)
#    flagList = []
    count = 0
    
    for (ts, buff) in pcap:
        eth = dpkt.ethernet.Ethernet(buff)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue     
        
        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue
        
        tcp = ip.data           
        if (tcp.flags & dpkt.tcp.TH_RST != 0) and (tcp.flags & dpkt.tcp.TH_ACK != 0):
#            flagList.append(tcp)
#        if ((tcp.flags & dpkt.tcp.TH_SYN != 0) and (tcp.flags & dpkt.tcp.TH_ACK != 0)):
#            flagList.append(tcp)
#        if ((tcp.flags & dpkt.tcp.TH_SYN != 0) and (tcp.flags & dpkt.tcp.TH_RST != 0) and (tcp.flags & dpkt.tcp.TH_ACK != 0)):
#            flagList.append(tcp)
#        if (tcp.flags & dpkt.tcp.TH_RST != 0):
#            flagList.append(tcp)
            count += 1
        
    print('There are ' +str(count)+ ' suspicious packets.')
#    with open('suspects.txt', 'a+') as f:
#        for i in range (len (flagList)):
#            src = socket.inet_ntop(socket.AF_INET, ip.src)
#            dst = socket.inet_ntop(socket.AF_INET, ip.dst)
#            print('Source: ' +src+ ' Destination: '  +dst, flagList[i], file=f)



#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Argparse ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>', help='count num of TCP packets')
    parser.add_argument('--listIP', type=argparse.FileType('rb'), metavar='<pcap file name>', help='list all src and dst IPs')
    parser.add_argument('--scanClosed', type=argparse.FileType('rb'), metavar='<pcap file name>', help='attempts to detect RST-ACK responses')
    args = parser.parse_args()

    if args.pcap:
        file_name = args.pcap
        if not os.path.isfile(file_name):
            print('"{}" does not exist'.format(file_name), file=sys.stderr)
            sys.exit(-1)
        pcap_Reader(file_name)

    if args.listIP:
        file_name = args.listIP
        pcap_IPlist(file_name)
        
    if args.scanClosed:
        file_name = args.scanClosed
        pcap_detClosed(file_name)


    sys.exit(0)
    
        
    
 