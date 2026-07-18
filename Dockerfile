# Usando uma imagem base leve, mas completa
FROM python:3.9-slim

# Instala dependências de rede e sistema necessárias (+ libpcap pro scapy capturar pacotes)
RUN apt-get update && apt-get install -y \
    iproute2 \
    net-tools \
    curl \
    tcpdump \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Configura o diretório de trabalho
WORKDIR /app

# Instala as bibliotecas Python necessárias (scapy estava faltando!)
RUN pip install requests scapy

# Copia os DOIS scripts + o entrypoint
COPY sentinela.py .
COPY auditoria7.py .
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# Sobe sentinela.py e auditoria7.py juntos
CMD ["./entrypoint.sh"]
