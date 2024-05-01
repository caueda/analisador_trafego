from scapy.all import *
from collections import Counter
import argparse
import time
import datetime

# Dicionário para mapear números de protocolos para nomes
protocol_names = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

def capturar_pacotes(interface, contagem=100):
    pacotes = sniff(iface=interface, count=contagem)
    return pacotes

def generate_traffic_stats(total_pacotes, num_protocolos, protocolos, top_enderecos_origem, top_enderecos_destino, protocol_names):
    result = []
    result.append("Estatísticas de Tráfego:")
    result.append(f"Número total de pacotes capturados: {total_pacotes}")
    result.append(f"Número de protocolos diferentes: {num_protocolos}")
    result.append("Número de pacotes por protocolo:")
    for protocolo, contagem in protocolos.items():
        result.append(f"  Protocolo {protocol_names[protocolo]}: {contagem} pacotes")
    result.append("Top 5 endereços IP de origem com mais tráfego:")
    for endereco, contagem in top_enderecos_origem:
        result.append(f"  {endereco}: {contagem} pacotes")
    result.append("Top 5 endereços IP de destino com mais tráfego:")
    for endereco, contagem in top_enderecos_destino:
        result.append(f"  {endereco}: {contagem} pacotes")
    return "\n".join(result)

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
    return generate_traffic_stats(total_pacotes, num_protocolos, protocolos, top_enderecos_origem, top_enderecos_destino, protocol_names)

# Exemplo de uso
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analisador de tráfego de rede")
    parser.add_argument("interface", type=str, help="Interface de rede para captura de pacotes")
    args = parser.parse_args()
    while True:
        try:
            print(f"\nAnálise de tráfego. Interface de Rede {args.interface}: Início da coleta de pacotes {datetime.datetime.now()}")
            pacotes = capturar_pacotes(args.interface)
            print(analisar_trafego(pacotes))
            time.sleep(5)
        except KeyboardInterrupt:
            print("\nEncerrando a coleta de pacotes")
            break
        except Exception as e:
            print(f"Falha na coleta dos pacotes: {e}. Tentando novamente...")
