#!/bin/bash

LOG_FILE="/var/log/ids-setup.log"
IFACE="br0"
DOWNLOAD="700mbit"
UPLOAD="800mbit"

echo "========== INÍCIO DA CONFIGURAÇÃO ==========" | tee -a "$LOG_FILE"

install_dependencies() {
    echo "[+] Instalando pacotes necessários..." | tee -a "$LOG_FILE"
    apt update && apt install -y bridge-utils suricata fail2ban ipset iftop curl gnupg2 software-properties-common squid iptables-persistent
}

setup_bridge() {
    echo "[+] Configurando bridge entre enp6s18 (entrada) e enp6s19 (saída)..." | tee -a "$LOG_FILE"
    ip addr flush dev enp6s18
    ip addr flush dev enp6s19

    ip link set br0 down 2>/dev/null
    ip link delete br0 type bridge 2>/dev/null

    ip link add name br0 type bridge
    ip link set dev enp6s18 master br0
    ip link set dev enp6s19 master br0

    ip link set dev br0 up
    ip link set dev enp6s18 up
    ip link set dev enp6s19 up

    ip addr add 192.168.3.10/24 dev br0
    ip route add default via 192.168.3.1

    echo "[+] Bridge br0 ativa com IP 192.168.3.10" | tee -a "$LOG_FILE"
}

setup_suricata() {
    echo "[+] Instalando e configurando Suricata..." | tee -a "$LOG_FILE"
    systemctl stop suricata
    suricata-update
    sed -i 's/interface: .*/interface: br0/' /etc/suricata/suricata.yaml
    systemctl enable suricata
    systemctl start suricata
}

setup_crowdsec() {
    echo "[+] Instalando CrowdSec..." | tee -a "$LOG_FILE"
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
    apt install -y crowdsec
    systemctl enable crowdsec
    systemctl start crowdsec
}

setup_fail2ban() {
    echo "[+] Ativando Fail2Ban..." | tee -a "$LOG_FILE"
    systemctl enable fail2ban
    systemctl start fail2ban
}

setup_ipset_blocklist() {
    echo "[+] Configurando IPSet para bloqueio de IPs maliciosos..." | tee -a "$LOG_FILE"
    ipset destroy blacklist 2>/dev/null
    ipset create blacklist hash:ip
    curl -s https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset | while read ip; do
        [[ "$ip" =~ ^#.*$ ]] && continue
        ipset add blacklist $ip 2>/dev/null
    done
    iptables -D INPUT -m set --match-set blacklist src -j DROP 2>/dev/null
    iptables -I INPUT -m set --match-set blacklist src -j DROP
    echo "[+] IPs bloqueados com sucesso." | tee -a "$LOG_FILE"
}

setup_qos() {
    echo "[+] Configurando QoS..." | tee -a "$LOG_FILE"

    # Limpa regras anteriores
    iptables -t mangle -F

    # Marca pacotes conforme protocolos
    iptables -t mangle -A PREROUTING -p udp -j MARK --set-mark 10  # Jogos
    iptables -t mangle -A PREROUTING -p tcp -j MARK --set-mark 20  # Streaming
    iptables -t mangle -A PREROUTING -p tcp --dport 21 -j MARK --set-mark 30     # Downloads FTP
    iptables -t mangle -A PREROUTING -p tcp --dport 51413 -j MARK --set-mark 40  # Torrent TCP
    iptables -t mangle -A PREROUTING -p udp --dport 51413 -j MARK --set-mark 40  # Torrent UDP

    # Limpa regras anteriores do tc
    tc qdisc del dev $IFACE root 2>/dev/null

    # Cria raiz HTB
    tc qdisc add dev $IFACE root handle 1: htb default 30
    tc class add dev $IFACE parent 1: classid 1:1 htb rate $UPLOAD

    # Classes por prioridade
    tc class add dev $IFACE parent 1:1 classid 1:10 htb rate 5mbit ceil $UPLOAD prio 1
    tc class add dev $IFACE parent 1:1 classid 1:20 htb rate 4mbit ceil $UPLOAD prio 2
    tc class add dev $IFACE parent 1:1 classid 1:30 htb rate 3mbit ceil $UPLOAD prio 3
    tc class add dev $IFACE parent 1:1 classid 1:40 htb rate 2mbit ceil $UPLOAD prio 4

    # Aplica filtros
    tc filter add dev $IFACE parent 1: protocol ip handle 10 fw flowid 1:10
    tc filter add dev $IFACE parent 1: protocol ip handle 20 fw flowid 1:20
    tc filter add dev $IFACE parent 1: protocol ip handle 30 fw flowid 1:30
    tc filter add dev $IFACE parent 1: protocol ip handle 40 fw flowid 1:40

    echo "[+] QoS aplicado com sucesso." | tee -a "$LOG_FILE"
}

setup_cache() {
    echo "[+] Configurando cache Squid (básico)..." | tee -a "$LOG_FILE"
    systemctl enable squid
    systemctl restart squid
    echo "[+] Squid ativo. Edite /etc/squid/squid.conf para ajustes personalizados." | tee -a "$LOG_FILE"
}

save_iptables_rules() {
    echo "[+] Salvando regras do iptables..." | tee -a "$LOG_FILE"
    iptables-save > /etc/iptables/rules.v4
    iptables-save > /etc/iptables/rules.v6
    echo "[+] Regras salvas com sucesso." | tee -a "$LOG_FILE"
}

restart_iptables_service() {
    echo "[+] Reiniciando serviço do iptables..." | tee -a "$LOG_FILE"
    systemctl restart netfilter-persistent
    echo "[+] Serviço do iptables reiniciado com sucesso." | tee -a "$LOG_FILE"
}

# Execução das funções
install_dependencies
setup_bridge
setup_suricata
setup_crowdsec
setup_fail2ban
setup_qos
setup_ipset_blocklist
setup_cache
save_iptables_rules
restart_iptables_service

echo "========== CONFIGURAÇÃO FINALIZADA ==========" | tee -a "$LOG_FILE"