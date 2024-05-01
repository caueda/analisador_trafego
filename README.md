# Análise de tráfego

Desenvolver uma aplicação para a análise de tráfego com a responsabilidade de capturar pacotes de
uma interface de rede e exibir estatísticas básicas.

## Requisitos

### Captura de Pacotes
- Desenvolva um script ou aplicação que capture pacotes de uma interface de rede
especificada.
- Utilize uma biblioteca ou ferramenta adequada para realizar a captura de pacotes (por
exemplo Scapy em Python).
- Capture os seguintes campos dos pacotes: endereço IP de origem, endereço IP de destino,
protocolo, tamanho do pacote.

### Análise de Tráfego
#### Calcule e exiba estatísticas básicas sobre o tráfego capturado, incluindo:
- Número total de pacotes capturados.
-  Número de pacotes por protocolo (por exemplo, TCP, UDP).
- Top 5 endereços IP de origem com mais tráfego.
- Top 5 endereços IP de destino com mais tráfego.

### Tecnologias Utilizadas
- Utilize a linguagem de programação de sua preferência, preferencialmente Python.
- A utilização de docker

## Como executar

### Windows
#### Requisitos
Instalar o Ncap.
```bash
python analisador_trafego.py <Interface de Rede>
```
Exemplo: 
```bash
python analisador_trafego.py "Wi-Fi"
```

### Linux
```bash
sudo python3 analisador_trafego.py <Interface de Rede>
```
Exemplo: 
```bash
sudo python3 analisador_trafego.py eth0
```

## Criando a imagem para Docker
docker build --pull --rm -f "Dockerfile" -t analisetrafegorede:latest "." 
## Rodando o container Docker
```bash
docker run --network=host -t -a stdout -a stderr <image_id>
```