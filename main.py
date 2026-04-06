from scapy.all import sniff, Ether, IP, TCP
from datetime import datetime

def handle_packet(pkt):
    data_formatada = datetime.now().strftime('%H:%M:%S')
    print(data_formatada, end=" | ")
    version_IP = {2048: "IPv4", 34525: "IPv6"}
    if IP in pkt:  
        if pkt[IP].proto == 6:
            ip_version = version_IP[pkt[Ether].type]
            source = pkt[IP].src
            dest = pkt[IP].dst
            srcport = int(pkt[TCP].sport)
            dstport = int(pkt[TCP].dport)
            seq = pkt[TCP].seq
            ack = pkt[TCP].ack
            flag = pkt[TCP].flags
            print(f"{ip_version} {source}:{srcport} > {dest}:{dstport} # TCP seq:{seq} ack:{ack} flag:{flag}")

sniff(prn=handle_packet, store=0, count=0, filter='ip')
