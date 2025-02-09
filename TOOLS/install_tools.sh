#!/bin/bash

# Script para instalação das ferramentas necessárias para o script de PenTest
# Desenvolvido para Debian 12

set -e  # Encerra o script em caso de erro

# Atualiza a lista de pacotes e instala dependências básicas
echo "[+] Atualizando pacotes e instalando dependências básicas..."
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip git curl \
    nmap nikto amass dnsrecon masscan \
    unzip build-essential libffi-dev libssl-dev \
    libcurl4-openssl-dev libldns-dev

# Instala bibliotecas Python necessárias
echo "[+] Instalando bibliotecas Python..."
pip3 install --upgrade pip
pip3 install requests rich

# Instalação do theHarvester
echo "[+] Instalando theHarvester..."
if [ ! -d "/opt/theHarvester" ]; then
    sudo git clone https://github.com/laramies/theHarvester.git /opt/theHarvester
    cd /opt/theHarvester && sudo pip3 install -r requirements.txt
else
    echo "[!] theHarvester já instalado."
fi

# Instalação do Sublist3r
echo "[+] Instalando Sublist3r..."
if [ ! -d "/opt/Sublist3r" ]; then
    sudo git clone https://github.com/aboul3la/Sublist3r.git /opt/Sublist3r
    cd /opt/Sublist3r && sudo pip3 install -r requirements.txt
else
    echo "[!] Sublist3r já instalado."
fi

# Instalação e configuração da API DeepSeek via Ollama
echo "[+] Instalando Ollama e API DeepSeek..."
curl -fsSL https://ollama.com/install.sh | sh

# Finalizando instalação
echo "[+] Instalação concluída. Execute o script de PenTest normalmente."
echo "Para rodar o script de PenTest, utilize: python3 script_pentest.py"