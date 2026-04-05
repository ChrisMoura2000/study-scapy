# Montando um IDS com scapy

A ideia aqui é aprender a usar a biblioteca scapy, para isso vou começar fazendo um sniffer de rede simples e depois desenvolver um sistema de IDS básico para compreender como os pacotes trafegam na rede.

# Caderno/Anotações
## Introdução segundo notebook LM

As fontes detalham o **Scapy**, uma biblioteca **Python** versátil projetada para a **manipulação**, **envio** e **captura** de pacotes em redes de computadores. O conteúdo explora funcionalidades essenciais, como o uso da função **sniff()** para monitoramento de tráfego e a análise de arquivos **pcap** para exames detalhados. Explicações teóricas abordam o modelo de **camadas de rede** e protocolos fundamentais, incluindo **ARP**, **ICMP**, **DNS** e **DHCP**. Além de servir como um guia técnico com exemplos de código, o material destaca o papel da ferramenta em **testes de penetração** e auditorias de segurança. Por fim, os textos enfatizam como o Scapy permite forjar pacotes personalizados para diagnosticar vulnerabilidades ou entender a comunicação entre dispositivos.

## Propriedades de cada frame

### Ethernet

```
[Ether]
.dst
.src
.type
```

.dst: Endereço de destino

.src: Endereço de origem (src)

.type: Identifica o tipo de protocolo no payload, por exemplo

- IPv4
- IPv6
- ARP

### IP

```
[IP]
.dst
.src
.proto
```

.proto = Protocolo que vem no payload do IP ou seja outro procolo, os mais comuns são:

- ICMP = 1
- IGMP = 2
- TCP = 6
- UDP = 17
- lista completa → [link](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)

### TCP

```
[TCP]
.sport
.dport
.seq
.ack
.flags
```

.sport: Porta de origem (Normalmente aleatória)

.dport: Porta de destino, mais comuns:

- 21 - FTP
- 22 - SSH
- 23 - Telnet
- 25 - SMTP
- 53 - DNS
- 80 - HTTP
- 443 - HTTPS

.seq: Número de sequência, serve para identificar o segmento TCP. O primeiro é aleatório e os seguintes são em sequência, está ligado diretamente ligado ao seu payload. Resumindo serve para ter controle dos pacotes, caso algum falhe o TCP reenvia para garantir a entrega 

.ack: Campo Acknowledgment (confirmação ou reconhecimento), é número enviado para dizer que sabe qual o próximo número de sequencia que deve receber da outra maquina, para saber o próximo número de seq é preciso que o anterior tenha sido recebido.

.flags: as flags também servem para controlar os pacotes na rede, temos:

- SYN → Pedido para sincronizar, inicio de uma conexão
- ACK → É a mais usada serve para que um dos lados confirme para o outro que sabe o número de sequência do próximo segmento
- PSH → É utilizada para sinalizar que há dados no payload do segmento TCP. Nem todo segmento TCP tem payload e os que tem vem com essa Flag ativa
- RST → É utilizada para dizer “não entendi”. Exemplos se o servidor não estivar ativo o cliente recebe essa flag reset (RST) ou se enviarmos um comando de e-mail, como LIST, em um servidor de páginas.

### UDP

```
[UDP]
.sport
.dport
.len
```

.len: Tamanho total do segmento UDP (cabeçalho e payload)
