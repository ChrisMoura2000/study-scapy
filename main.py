from scapy.all import sniff, Ether, IP, TCP, UDP

def handle_packet(pkt):
    if IP in pkt:
        print("===============================")
        print(pkt[Ether].dst)
        print(pkt[IP].dst)
        print(pkt[IP].proto)

sniff(prn=handle_packet ,count=10, filter="ip")

