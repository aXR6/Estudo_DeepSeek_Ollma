#!/usr/bin/env python3
import argparse
import logging
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from datetime import datetime
from collections import Counter
from scapy.all import sniff, IP, TCP, Ether
from rich.console import Console, Group
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich import box

console = Console()


def parse_args():
    parser = argparse.ArgumentParser(description="Network Monitor with Scapy & Rich")
    parser.add_argument(
        "-i", "--interface",
        default="enp6s18",
        help="Interface para monitorar"
    )
    parser.add_argument(
        "-l", "--log-dir",
        default="logs",
        help="Diretório de logs"
    )
    parser.add_argument(
        "-n", "--max-rows",
        type=int,
        default=60,
        help="Linhas antes de resetar tabela"
    )
    parser.add_argument(
        "-t", "--top-victims",
        type=int,
        default=10,
        help="Número de IPs vítimas para exibir"
    )
    return parser.parse_args()


def setup_logger(log_dir):
    log_path = Path(log_dir)
    log_path.mkdir(exist_ok=True)
    logger = logging.getLogger("netmon")
    logger.setLevel(logging.INFO)
    handler = TimedRotatingFileHandler(
        log_path / "netmon.log",
        when="midnight",
        interval=1,
        backupCount=7,
        encoding="utf-8"
    )
    handler.setFormatter(
        logging.Formatter(
            "[%(asctime)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
    )
    logger.addHandler(handler)
    return logger


def detect_scan_type(flags):
    f = int(flags)
    scans = []
    if f == 0:
        scans.append("NULL")
    if f & 0x02 and not (f & 0xFD):
        scans.append("SYN")
    if (f & 0x01) and (f & 0x08) and (f & 0x20):
        scans.append("XMAS")
    return scans


def create_table():
    tbl = Table(title="📡 Network Monitor – Potenciais Ameaças", box=box.SIMPLE_HEAD)
    tbl.add_column("Time", style="magenta")
    tbl.add_column("SRC MAC", style="cyan", no_wrap=True)
    tbl.add_column("DST MAC", style="cyan", no_wrap=True)
    tbl.add_column("Proto", style="yellow", justify="center")
    tbl.add_column("SRC IP:Port", style="red")
    tbl.add_column("DST IP:Port", style="green")
    tbl.add_column("Alert", style="bold red")
    return tbl


def create_summary_table(victim_counter, top_n):
    tbl = Table(title=f"🏆 Top {top_n} IPs Vítimas", box=box.SIMPLE_HEAD)
    tbl.add_column("IP Vítima", style="red")
    tbl.add_column("Quantidade", justify="center")
    for ip, count in victim_counter.most_common(top_n):
        tbl.add_row(ip, str(count))
    return tbl


def main():
    args = parse_args()
    logger = setup_logger(args.log_dir)

    victim_counter = Counter()
    table_ref = [create_table()]
    row_counter = [0]

    console.print(f"[bold green]Iniciando monitor em {args.interface}[/bold green]")

    with Live(Group(table_ref[0], Panel(create_summary_table(victim_counter, args.top_victims))),
               refresh_per_second=4, screen=True) as live:
        def packet_callback(pkt):
            try:
                if not (pkt.haslayer(Ether) and pkt.haslayer(IP) and pkt.haslayer(TCP)):
                    return

                eth, ip, tcp = pkt[Ether], pkt[IP], pkt[TCP]
                scans = detect_scan_type(tcp.flags)
                if not scans:
                    return

                ts = datetime.now().strftime("%H:%M:%S")
                src = f"{ip.src}:{tcp.sport}"
                dst = f"{ip.dst}:{tcp.dport}"
                alert = ", ".join(scans)

                # Atualiza tabelas e contadores
                victim_counter[dst] += 1
                table_ref[0].add_row(ts, eth.src, eth.dst, "TCP", src, dst, alert)
                logger.info(f"{ts} | {eth.src} -> {eth.dst} | {src} -> {dst} | {alert}")

                row_counter[0] += 1
                # Reset tabela de ataques
                if row_counter[0] >= args.max_rows:
                    table_ref[0] = create_table()
                    row_counter[0] = 0

                # Recria sumário de vítimas
                summary_tbl = create_summary_table(victim_counter, args.top_victims)

                # Atualiza display mantendo o contexto Live
                live.update(Group(table_ref[0], Panel(summary_tbl, title="🏆 Top Vítimas")))

            except Exception as e:
                logger.exception(f"Erro no callback de pacote: {e}")

        sniff(iface=args.interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("[bold red]Monitoramento interrompido pelo usuário[/bold red]")