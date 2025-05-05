import os
import time
import psutil
from datetime import datetime
from scapy.all import sniff, IP, Ether
from rich.live import Live
from rich.table import Table
from rich.console import Console
from rich.panel import Panel
from rich.layout import Layout

# Diretório para armazenar os logs
LOG_DIR = "/home/monitor-srv/script/pacote_rede"
os.makedirs(LOG_DIR, exist_ok=True)

# Inicializa o console do Rich
console = Console()

# Intervalo de atualização em segundos
UPDATE_INTERVAL = 1

# Obtém as interfaces de rede disponíveis
interfaces = psutil.net_if_stats().keys()

# Função para obter o endereço MAC da interface
def get_mac_address(interface):
    addrs = psutil.net_if_addrs().get(interface, [])
    for addr in addrs:
        if addr.family == psutil.AF_LINK:
            return addr.address
    return "N/A"

# Função para formatar bytes em uma representação legível
def format_bytes(size):
    power = 1024
    n = 0
    power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size > power and n < 4:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}B"

# Função para criar a tabela de exibição
def create_table():
    table = Table(title="Monitoramento de Tráfego de Rede", expand=True)
    table.add_column("Interface", justify="left")
    table.add_column("MAC Address", justify="left")
    table.add_column("Bytes Enviados", justify="right")
    table.add_column("Bytes Recebidos", justify="right")
    table.add_column("Pacotes Enviados", justify="right")
    table.add_column("Pacotes Recebidos", justify="right")
    table.add_column("Velocidade Envio/s", justify="right")
    table.add_column("Velocidade Recebimento/s", justify="right")
    return table

# Função para criar o painel de dispositivos conectados
def create_connected_devices_panel():
    connections = psutil.net_connections(kind='inet')
    remote_ips = set()
    for conn in connections:
        if conn.raddr:
            remote_ips.add(conn.raddr.ip)
    ip_list = "\n".join(f"- {ip}" for ip in remote_ips)
    panel = Panel(f"Total de dispositivos conectados: {len(remote_ips)}\nEndereços IP conectados:\n{ip_list}", title="Dispositivos Conectados", expand=True)
    return panel

# Função para criar o layout completo
def create_layout(table, panel):
    layout = Layout()
    layout.split_column(
        Layout(name="upper"),
        Layout(name="lower")
    )
    layout["upper"].update(table)
    layout["lower"].update(panel)
    return layout

# Função principal de monitoramento
def start_monitoring():
    prev_counters = psutil.net_io_counters(pernic=True)
    with Live(console=console, refresh_per_second=1) as live:
        while True:
            time.sleep(UPDATE_INTERVAL)
            table = create_table()
            current_counters = psutil.net_io_counters(pernic=True)
            timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
            log_filename = os.path.join(LOG_DIR, f"{datetime.now().strftime('%d-%m-%Y')}.log")
            with open(log_filename, "a") as log_file:
                for iface in interfaces:
                    mac = get_mac_address(iface)
                    prev = prev_counters.get(iface)
                    curr = current_counters.get(iface)
                    if prev and curr:
                        sent_diff = curr.bytes_sent - prev.bytes_sent
                        recv_diff = curr.bytes_recv - prev.bytes_recv
                        table.add_row(
                            iface,
                            mac,
                            format_bytes(curr.bytes_sent),
                            format_bytes(curr.bytes_recv),
                            str(curr.packets_sent),
                            str(curr.packets_recv),
                            format_bytes(sent_diff / UPDATE_INTERVAL),
                            format_bytes(recv_diff / UPDATE_INTERVAL)
                        )
                        log_file.write(f"{timestamp} | Interface: {iface} | MAC: {mac} | Enviados: {curr.bytes_sent} bytes | Recebidos: {curr.bytes_recv} bytes | Pacotes Enviados: {curr.packets_sent} | Pacotes Recebidos: {curr.packets_recv}\n")
                prev_counters = current_counters
            panel = create_connected_devices_panel()
            layout = create_layout(table, panel)
            live.update(layout)

# Inicia o monitoramento
if __name__ == "__main__":
    start_monitoring()