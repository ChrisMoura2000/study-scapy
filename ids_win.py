from scapy.all import sniff, Ether, IP, TCP, UDP, Raw
import os

# Função para processar e analisar os pacotes capturados
def packet_handler(packet):
    # Verificar se o pacote possui camada Ethernet
    if Ether in packet:
        eth_dest_mac = packet[Ether].dst
        eth_src_mac = packet[Ether].src
        eth_type = packet[Ether].type
        print("Cabeçalho Ethernet:")
        print(f"MAC de destino: {eth_dest_mac}")
        print(f"MAC de origem: {eth_src_mac}")
        print(f"Tipo: {hex(eth_type)}")
        print("--------------------")

    # Verificar se o pacote possui camada IP
    if IP in packet:
        ip_src = packet[IP].src
        ip_dest = packet[IP].dst
        ip_protocol = packet[IP].proto
        print("Cabeçalho IP:")
        print(f"Endereço de origem: {ip_src}")
        print(f"Endereço de destino: {ip_dest}")
        print(f"Protocolo: {ip_protocol}")
        print("--------------------")

        # Verificar se o protocolo é TCP (protocolo 6)
        if TCP in packet:
            tcp_src_port = packet[TCP].sport
            tcp_dest_port = packet[TCP].dport
            tcp_seq = packet[TCP].seq
            tcp_ack = packet[TCP].ack
            tcp_flags = packet[TCP].flags
            print("Cabeçalho TCP:")
            print(f"Porta de origem: {tcp_src_port}")
            print(f"Porta de destino: {tcp_dest_port}")
            print(f"Número de Sequência: {tcp_seq}")
            print(f"Número de Ack: {tcp_ack}")
            print(f"Flags: {tcp_flags}")
            print("--------------------")

            # Verificar se a flag SYN está ativada
            if "S" in tcp_flags:
                write_logs(f"SYN Detected - {ip_src} -> {ip_dest} (Porta {tcp_src_port} -> {tcp_dest_port})")
                print("Flag SYN detectada (início de conexão TCP)")

        # Verificar se o protocolo é UDP (protocolo 17)
        elif UDP in packet:
            udp_src_port = packet[UDP].sport
            udp_dest_port = packet[UDP].dport
            udp_length = packet[UDP].len
            print("Cabeçalho UDP:")
            print(f"Porta de origem: {udp_src_port}")
            print(f"Porta de destino: {udp_dest_port}")
            print(f"Tamanho UDP: {udp_length}")
            print("--------------------")

# Função para ler os logs armazenados
def read_logs():
    try:
        with open('logs_win.txt', "r", encoding='utf-8') as arq:
            conteudo = arq.readlines()
            print(conteudo)
            return conteudo
    except FileNotFoundError:
        print("O arquivo não existe.")

# Função para escrever nos logs
def write_logs(payload):
    with open('logs_win.txt', 'a', encoding='utf-8') as arq:
        arq.write(payload + '\n')

# Função para excluir os logs
def del_logs():
    try:
        arquivo = "logs_win.txt"
        if os.path.exists(arquivo):
            os.remove(arquivo)
            print(f"Arquivo '{arquivo}' foi excluído com sucesso!")
        else:
            print(f"Arquivo '{arquivo}' não existe.")
    except Exception as e:
        print(f"Ocorreu um erro ao tentar excluir o arquivo: {e}")

# Função principal para capturar pacotes
def main_sniffer():
    print("Aguardando pacotes Ethernet...")
    
    # Use o Scapy para capturar pacotes. Defina o filtro para capturar pacotes Ethernet/IP/TCP/UDP.
    sniff(prn=packet_handler, store=0, filter="ip", count=0)  # Ajuste conforme necessário

if __name__ == "__main__":
    main_sniffer()
