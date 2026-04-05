from datetime import datetime
from colorama import Fore, init
import socket
import struct
import os

init(autoreset=True)  # Para não precisar usar o reset manualmente

# Crie um socket raw Ethernet para capturar pacotes
raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

# Obtendo o endereço IP local
hostname = socket.gethostname()  # Nome do host
local_ip = socket.gethostbyname(hostname)  # Endereço IP associado

print("Aguardando pacotes Ethernet...")

# Função que imprime o tempo decorrido desde o início
def print_current_time():
    current_time = datetime.now()
    return (f"[{current_time.strftime('%d/%m/%Y')} {current_time.strftime('%H:%M:%S')}]")

def main_sniffer():
    while True:
        # Capture um pacote Ethernet
        packet, addr = raw_socket.recvfrom(65535)

        # Analise o cabeçalho Ethernet
        eth_header = packet[:14]
        eth_payload = packet[14:]

        eth_dest_mac, eth_src_mac, eth_type = struct.unpack("!6s6sH", eth_header)
        print(f"Time: {print_current_time()}")
        print(Fore.RED + "Cabeçalho Ethernet:")
        print(Fore.RED + f"MAC de destino: {':'.join('%02x' % b for b in eth_dest_mac)}")
        print(Fore.RED + f"MAC de origem: {':'.join('%02x' % b for b in eth_src_mac)}")
        print(Fore.RED + f"Tipo: {hex(eth_type)}")
        print(Fore.RED + "--------------------")

        # Verificar se o pacote é IPv4 (EtherType 0x0800)
        if eth_type == 0x0800:
            ip_header = eth_payload[:20]
            ip_version, ip_tos, ip_length, ip_id, ip_flags, ip_ttl, ip_protocol, ip_checksum, ip_src, ip_dest = struct.unpack("!BBHHHBBH4s4s", ip_header)

            print(Fore.YELLOW + "Cabeçalho IP:")
            print(Fore.YELLOW + f"Endereço de origem: {socket.inet_ntoa(ip_src)}")
            print(Fore.YELLOW + f"Endereço de destino: {socket.inet_ntoa(ip_dest)}")
            print(Fore.YELLOW + f"Protocolo: {ip_protocol}")
            print(Fore.YELLOW + "--------------------")

            # if socket.inet_ntoa(ip_src) == socket.inet_ntoa(ip_dest):  # Verifica se endereço de IP de destino é o mesmo que de origem
            #     print("Cabeçalho IP:")
            #     print(f"Endereço de origem: {socket.inet_ntoa(ip_src)}")
            #     print(f"Endereço de destino: {socket.inet_ntoa(ip_dest)}")
            #     print(f"Protocolo: {ip_protocol}")
            #     print("--------------------")

            # Verificar se o protocolo é TCP (protocolo 6) ou UDP (protocolo 17)
            if ip_protocol == 6:
             if len(eth_payload) >= 40:  # Certifique-se de que o cabeçalho TCP completo está disponível
                    tcp_header = eth_payload[20:40]

                    # Payload (dados): restante do pacote após o cabeçalho TCP
                    payload = packet[54:]
                    
                    # Exibe o conteúdo do payload
                    print(f"Payload: {payload.decode(errors='ignore')}")

                    try:
                        src_port, dest_port, sequence, ack_num, offset_flags = struct.unpack("!HHIIB", tcp_header[:13])
                        offset = (offset_flags >> 4) * 4
                        SYN_flag = (offset_flags >> 1) # O SYN está no segundo bit
                        
                        if SYN_flag:
                            print(local_ip, "local_ip <<<<<<<<<<<<<<<<<<<<<<<<<", hostname)
                            if "192.168.15.148" == socket.inet_ntoa(ip_dest):
                                print(f"RECEBI SYN de {socket.inet_ntoa(ip_src)}")
                                # write_logs(f"RECEBI SYN de {socket.inet_ntoa(ip_src)}")
                            # write_logs(f"IP route: {socket.inet_ntoa(ip_src)} >> {socket.inet_ntoa(ip_dest)}\n Port Route: {src_port} >> {dest_port} \nTime: {print_current_time()}\n-----------------------------")
                            # print("Flag SYN está ativada.")

                        print(Fore.GREEN + "Cabeçalho TCP:")
                        print(Fore.GREEN + f"Porta de origem: {src_port}")
                        print(Fore.GREEN + f"Porta de destino: {dest_port}")
                        print(Fore.GREEN + f"Número de Sequência: {sequence}")
                        print(Fore.GREEN + f"Número de Ack: {ack_num}")
                        print(Fore.GREEN + f"Offset: {offset}")
                        print(Fore.GREEN + "--------------------")
                    except struct.error as e:
                        print(f"Erro ao desempacotar cabeçalho TCP: {e}")

            if ip_protocol == 17:
                udp_header = eth_payload[20:28]
                src_port, dest_port, udp_length, udp_checksum = struct.unpack("!HHHH", udp_header)

                print("Cabeçalho UDP:")
                print(f"Porta de origem: {src_port}")
                print(f"Porta de destino: {dest_port}")
                print(f"Checksum UDP: {udp_checksum}")
                print(f"Tamanho: {udp_length}")
                print("--------------------")
        print("====================")

def read_logs():
    try:
        with open('logs_linux.txt', "r", encoding='utf-8') as arq:
            conteudo = arq.readlines()
            print(conteudo)
            arq.close()
            return conteudo
    except FileNotFoundError:
        print("O arquivo não existe.")

def write_logs(payload):
    with open('logs_linux.txt', 'a', encoding='utf-8') as arq:
        arq.write(payload + '\n')

def del_logs():
    try:
        # Nome do arquivo que você quer excluir
        arquivo = "logs_linux.txt"

        # Verifica se o arquivo existe
        if os.path.exists(arquivo):
            os.remove(arquivo)
            print(f"Arquivo '{arquivo}' foi excluído com sucesso!")
        else:
            print(f"Arquivo '{arquivo}' não existe.")
    except Exception as e:
        print(f"Ocorreu um erro ao tentar excluir o arquivo: {e}")

if __name__ == "__main__":
    main_sniffer()
