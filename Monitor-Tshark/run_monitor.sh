#!/usr/bin/env bash
#
# run_monitor.sh — Cria venv, instala dependências, habilita raw sockets e roda o monitor
#
# Uso: ./run_monitor.sh [INTERFACE] [LOG_DIR] [MAX_ROWS] [TOP_VICTIMS]
# Ex:  ./run_monitor.sh enp6s18 logs 60 10
#
# Parâmetros:
#
# enp6s18 → interface (verifique com ip addr show)
# logs → diretório para armazenar logs
# 60 → número de linhas antes de resetar a tabela
# 10 → número de IPs vítimas exibidos no resumo
# set -e  # sai em caso de erro :contentReference[oaicite:0]{index=0}

# Parâmetros com defaults
IFACE="${1:-enp6s18}"
LOGDIR="${2:-logs}"
MAX_ROWS="${3:-60}"
TOP_VICTIMS="${4:-10}"

# 1) Criar e ativar virtualenv
echo "[*] Criando ambiente virtual..."
python3 -m venv .venv                                         # venv nativo do Python 3 :contentReference[oaicite:1]{index=1}
source .venv/bin/activate                                     # ativa venv no script 

# 2) Instalar/atualizar dependências
echo "[*] Instalando dependências (scapy, rich)..."
pip3 install --upgrade pip --break-system-packages            # atualiza pip
pip3 install scapy rich  --break-system-packages              # instala bibliotecas :contentReference[oaicite:2]{index=2} :contentReference[oaicite:3]{index=3}


# 2) Instalar/atualizar dependências
echo "[*] Instalando dependências (scapy, rich)..."
pip3 install --upgrade pip --break-system-packages            # atualiza pip


# 3) Conceder capacidades de raw-socket ao Python do venv
echo "[*] Configurando CAP_NET_RAW no Python do venv..."
PYTHON_VENV_BIN="$(readlink -f .venv/bin/python3)"
sudo setcap cap_net_raw,cap_net_admin=eip "$PYTHON_VENV_BIN"  # limita raw-socket ao venv :contentReference[oaicite:4]{index=4}

# 4) Garantir diretório de logs
echo "[*] Preparando diretório de logs em '$LOGDIR'..."
mkdir -p "$LOGDIR"

# 5) Executar monitor de rede
echo "[*] Iniciando monitor em '$IFACE'..."
exec python3 mon_ataque.py \
    --interface "$IFACE" \
    --log-dir "$LOGDIR" \
    --max-rows "$MAX_ROWS" \
    --top-victims "$TOP_VICTIMS"
