from scapy.all import *
from collections import Counter

def capturar_pacotes(interface, contagem=100):
    pacotes = sniff(iface=interface, count=contagem)
    return pacotes

def analisar_trafego(pacotes):
    total_pacotes = len(pacotes)
    
    # Dicionário para armazenar contagem de protocolos
    protocolos = {}
    # Listas para armazenar endereços IP de origem e destino
    enderecos_origem = []
    enderecos_destino = []

    for pacote in pacotes:
        # Verifica se o pacote contém a camada IP
        if IP in pacote:
            # Capturando os campos dos pacotes
            ip_origem = pacote[IP].src
            ip_destino = pacote[IP].dst
            protocolo = pacote[IP].proto
            tamanho = len(pacote)

            # Contagem de protocolos
            if protocolo in protocolos:
                protocolos[protocolo] += 1
            else:
                protocolos[protocolo] = 1

            # Armazenando endereços IP
            enderecos_origem.append(ip_origem)
            enderecos_destino.append(ip_destino)

    # Calculando as estatísticas
    num_protocolos = len(protocolos)
    top_enderecos_origem = Counter(enderecos_origem).most_common(5)
    top_enderecos_destino = Counter(enderecos_destino).most_common(5)

    # Exibindo estatísticas
    print("Estatísticas de Tráfego:")
    print("Número total de pacotes capturados:", total_pacotes)
    print("Número de protocolos diferentes:", num_protocolos)
    print("Número de pacotes por protocolo:")
    for protocolo, contagem in protocolos.items():
        print(f"  Protocolo {protocolo}: {contagem} pacotes")
    print("Top 5 endereços IP de origem com mais tráfego:")
    for endereco, contagem in top_enderecos_origem:
        print(f"  {endereco}: {contagem} pacotes")
    print("Top 5 endereços IP de destino com mais tráfego:")
    for endereco, contagem in top_enderecos_destino:
        print(f"  {endereco}: {contagem} pacotes")

# Exemplo de uso
if __name__ == "__main__":
    interface = "en0"  # Substitua pela sua interface de rede
    pacotes = capturar_pacotes(interface)
    analisar_trafego(pacotes)
