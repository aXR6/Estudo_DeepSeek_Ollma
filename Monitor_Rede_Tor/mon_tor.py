import psutil
import time
import os
import logging
from logging.handlers import TimedRotatingFileHandler
from rich.console import Console
from rich.table import Table
from datetime import datetime

# Configuração do logger
log_dir = "/var/log/tor_monitor"
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "tor_connections.log")

logger = logging.getLogger("TorMonitor")
logger.setLevel(logging.INFO)

handler = TimedRotatingFileHandler(log_file, when="midnight", backupCount=7)
handler.suffix = "%d-%m-%Y"
formatter = logging.Formatter('%(asctime)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

console = Console()

def get_mac_address(interface_name):
    addrs = psutil.net_if_addrs()
    if interface_name in addrs:
        for snic in addrs[interface_name]:
            if snic.family == psutil.AF_LINK:
                return snic.address
    return "N/A"

def monitor_tor_connections():
    while True:
        connections = psutil.net_connections(kind='inet')
        tor_connections = [conn for conn in connections if conn.laddr.port == 9050 and conn.status == 'ESTABLISHED']

        table = Table(title="Conexões Ativas na Porta 9050 (Tor)")

        table.add_column("Endereço Remoto", justify="left", style="cyan")
        table.add_column("Porta Remota", justify="right", style="magenta")
        table.add_column("PID", justify="right", style="green")
        table.add_column("Interface", justify="left", style="yellow")
        table.add_column("MAC", justify="left", style="red")
        table.add_column("Bytes Enviados", justify="right", style="blue")
        table.add_column("Bytes Recebidos", justify="right", style="blue")

        io_counters = psutil.net_io_counters(pernic=True)

        for conn in tor_connections:
            raddr = f"{conn.raddr.ip}" if conn.raddr else "N/A"
            rport = f"{conn.raddr.port}" if conn.raddr else "N/A"
            pid = str(conn.pid) if conn.pid else "N/A"
            interface = "N/A"
            mac = "N/A"
            bytes_sent = "N/A"
            bytes_recv = "N/A"

            # Determinar a interface de rede associada à conexão
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.address == conn.laddr.ip:
                        interface = iface
                        mac = get_mac_address(iface)
                        if iface in io_counters:
                            bytes_sent = str(io_counters[iface].bytes_sent)
                            bytes_recv = str(io_counters[iface].bytes_recv)
                        break

            table.add_row(raddr, rport, pid, interface, mac, bytes_sent, bytes_recv)
            logger.info(f"Conexão estabelecida - IP: {raddr}, Porta: {rport}, PID: {pid}, Interface: {interface}, MAC: {mac}, Bytes Enviados: {bytes_sent}, Bytes Recebidos: {bytes_recv}")

        console.clear()
        console.print(table)
        time.sleep(5)

if __name__ == "__main__":
    monitor_tor_connections()
