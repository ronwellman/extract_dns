# Extract DNS

### Author
ron.wellman01@gmail.com - Feb2018

### Purpose
A simple python script to extract DNS queries from a PCAP file.  

### Motivation
I needed a quick snapshot of the DNS requests on my network and the IP addresses that were making them.

### PCAP generation performed in PfSense CLI
tcpdump -i em1 -C 10 -w test.pcap udp port 53

### Python Version
python3

### Notable Packages
scapy-python3==0.23

### Setup
python3 -m venv venv
source venv/bin/activate
pip3 install scapy-python3, flake8

### Formatting
flake8 --ignore=E402 --max-line-length=80 extract_dns.py

### Potential Future upgrades
1. argparse or click integration
    1. custom directory for pcaps
    1. custom output filenames
    1. restrict by source address
    1. ability to filter out common DNS entries or entries with a higher number of occurrences
1. Cleaner Output
    1. Current sorting methodology is incorrect/incomplete
    1. Output could be easier to read
1. Speed is less than desirable to move through a large PCAP
