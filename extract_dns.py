#! /usr/bin/env python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import rdpcap
from os import listdir as ls
import sys
from collections import defaultdict, Counter
from operator import itemgetter
'''
    extract_dns

    This script utilizes the scapy module to extract dns queries from a pcap
'''

def extract(p):
    '''
        extract(scapy_packet) -> tuple(str,str)

        extracts the source ip and the query that was made
    '''
    src = p['IP'].src
    query = p['DNS'].qd.qname

    return src, query.decode('utf-8').rstrip('.')


def sort_ip(ip):
    '''
        sorted_ip(str) -> int

        ensures proper sorting of an ip address based on octets
    '''
    ip = ip.split('.')
    total = 0

    for i, octet in enumerate(ip[::-1]):
        total += int(octet) << i*8

    return total


def main(argv):

    pcaps = (fname for fname in ls() if '.pcap' in fname)
    all_queries = defaultdict(list)

    for pcap in pcaps:
        p = rdpcap(pcap)
        for packet in p:
            if packet.getlayer('DNS') and packet.getlayer('DNS').opcode == 0:
                src_ip, query = extract(packet)
                all_queries[src_ip].append(query)

    for src_ip in sorted(all_queries, key=sort_ip):
        sub_queries = Counter(all_queries[src_ip])
        for i, query in enumerate(sorted(sub_queries.items(), key=itemgetter(1,0), reverse=True)):
            if i == 0:
                print('{:<15} {:>7}  {:<}'.format(src_ip, query[1], query[0]))
            else:
                print('{:15} {:>7}  {:<}'.format('', query[1], query[0]))

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
