#!/usr/bin/env python3

"""
Sistema Avançado de Detecção e Resposta a Ameaças em Tempo Real (ART-System)

Funcionalidades:
1. Monitoramento contínuo do tráfego de rede
2. Detecção de padrões suspeitos (DDoS, port scanning, brute force)
3. Análise preditiva via IA integrada
4. Resposta automatizada a ameaças
5. Sistema de aprendizado contínuo de padrões

Requisitos:
- Scapy 2.5.0+
- Requests 2.31.0+
- Python 3.10+
- Executar como root/sudo

Modo de uso:
sudo python3 art_system.py --config config.yaml

Autor: IA Specialist
Revisão: 1.8.2
"""

import os
import sys
import time
import signal
import logging
import argparse
import subprocess
import json
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Optional

import yaml
import requests
from scapy.sendrecv import AsyncSniffer
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Packet

# Configuração padrão
DEFAULT_CONFIG = {
    'network': {
        'interface': 'enp8s0',
        'whitelist': ['192.168.3.100'],
        'max_pps': 5000,        # Packets por segundo
        'max_syn_ratio': 0.8,   # % de pacotes SYN
        'burst_window': 5,      # Janela de detecção em segundos
    },
    'api': {
        'endpoint': 'http://localhost:5000/analyze',
        'key': 'sk_prod_1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        'timeout': 30,
        'threshold': 0.85       # Confiança mínima para ação
    },
    'logging': {
        'level': 'INFO',
        'file': '/var/log/art_system.log'
    }
}

class TrafficAnalyzer:
    """Analisador de padrões de tráfego em tempo real"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.reset_counters()
        
        # Estatísticas dinâmicas
        self.pps_history = deque(maxlen=60)
        self.ip_stats = defaultdict(lambda: {
            'count': 0,
            'ports': set(),
            'flags': defaultdict(int),
            'last_seen': 0
        })
        
        # Modelo de baseline
        self.baseline = {
            'avg_pps': 0,
            'syn_ratio': 0.3
        }
        
        self.learn_mode = True  # Modo de aprendizado inicial
        self.learning_start = time.time()
        
    def reset_counters(self):
        """Reinicia contadores temporais"""
        self.current_counts = {
            'total': 0,
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'syn': 0,
            'ports': defaultdict(int),
            'ips': defaultdict(int)
        }
        
    def update_baseline(self):
        """Atualiza a baseline de tráfego normal"""
        if self.pps_history:
            self.baseline['avg_pps'] = sum(self.pps_history)/len(self.pps_history)
            syn_ratio = sum(
                1 for pkt in self.pps_history if pkt['syn_ratio'] > 0.5
            ) / len(self.pps_history)
            self.baseline['syn_ratio'] = syn_ratio
        
    def analyze_packet(self, packet: Packet):
        """Processa cada pacote individual"""
        if not packet.haslayer(IP):
            return

        ip = packet[IP]
        now = time.time()
        
        # Atualiza contadores
        self.current_counts['total'] += 1
        self.ip_stats[ip.src]['count'] += 1
        self.ip_stats[ip.src]['last_seen'] = now
        
        if packet.haslayer(TCP):
            self.current_counts['tcp'] += 1
            tcp = packet[TCP]
            self.ip_stats[ip.src]['ports'].add(tcp.dport)
            
            if tcp.flags == 'S':
                self.current_counts['syn'] += 1
                self.ip_stats[ip.src]['flags']['syn'] += 1
                
        elif packet.haslayer(UDP):
            self.current_counts['udp'] += 1
        elif packet.haslayer(ICMP):
            self.current_counts['icmp'] += 1
            
    def detect_anomalies(self) -> List[Dict]:
        """Executa verificação de anomalias periódica"""
        anomalies = []
        now = time.time()
        
        # 1. Verifica taxa de pacotes
        current_pps = self.current_counts['total']
        self.pps_history.append(current_pps)
        
        if not self.learn_mode and current_pps > self.config['network']['max_pps']:
            anomalies.append({
                'type': 'high_traffic',
                'pps': current_pps,
                'avg_pps': self.baseline['avg_pps']
            })
            
        # 2. Verifica proporção SYN
        syn_ratio = self.current_counts['syn'] / max(1, self.current_counts['tcp'])
        if syn_ratio > self.config['network']['max_syn_ratio']:
            anomalies.append({
                'type': 'syn_flood',
                'ratio': syn_ratio
            })
            
        # 3. Detecção de port scanning
        for ip, data in self.ip_stats.items():
            if now - data['last_seen'] < 5 and len(data['ports']) > 10:
                anomalies.append({
                    'type': 'port_scan',
                    'ip': ip,
                    'ports': len(data['ports'])
                })
                
        # Atualiza baseline após período de aprendizado
        if self.learn_mode and (now - self.learning_start) > 300:
            self.learn_mode = False
            self.update_baseline()
            
        self.reset_counters()
        return anomalies

class ThreatResponder:
    """Gerencia respostas a ameaças detectadas"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.blocked_ips = set()
        
    def execute_response(self, action: str, target: str):
        """Executa ações de resposta"""
        if target in self.config['network']['whitelist']:
            logging.warning(f"Tentativa de bloquear IP em whitelist: {target}")
            return False
            
        try:
            if action == 'block':
                self._block_ip(target)
            elif action == 'throttle':
                self._throttle_connection(target)
            return True
        except Exception as e:
            logging.error(f"Falha na resposta: {str(e)}")
            return False
            
    def _block_ip(self, ip: str):
        """Bloqueia IP usando iptables"""
        if ip not in self.blocked_ips:
            subprocess.run(
                ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                check=True
            )
            self.blocked_ips.add(ip)
            logging.info(f"IP bloqueado: {ip}")

    def _throttle_connection(self, ip: str):
        """Limita taxas de conexão"""
        subprocess.run([
            'iptables', '-A', 'INPUT', '-s', ip, '-m', 'limit',
            '--limit', '10/min', '-j', 'ACCEPT'
        ], check=True)
        logging.info(f"Conexões limitadas para: {ip}")

class APIClient:
    """Cliente para integração com API de análise"""
    
    def __init__(self, config: Dict):
        self.endpoint = config['api']['endpoint']
        self.headers = {
            'X-API-Key': config['api']['key'],
            'Content-Type': 'application/json'
        }
        
    def send_for_analysis(self, packet_data: str, context: str) -> Optional[Dict]:
        """Envia dados para análise via API"""
        payload = {
            'scan_data': packet_data,
            'context': context,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        try:
            response = requests.post(
                self.endpoint,
                headers=self.headers,
                json=payload,
                timeout=self.config['api']['timeout']
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"Erro na API: {str(e)}")
            return None

class ARTSystem:
    """Sistema principal de monitoramento"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.sniffer = AsyncSniffer()
        self.analyzer = TrafficAnalyzer(config['network'])
        self.responder = ThreatResponder(config['network'])
        self.api_client = APIClient(config['api'])
        
        # Sinalização para parada
        self.running = False
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)
        
    def start(self):
        """Inicia o monitoramento"""
        logging.info("Iniciando ART-System...")
        self.running = True
        self.sniffer.start()
        
        try:
            while self.running:
                time.sleep(self.config['network']['burst_window'])
                self._process_packets()
        except Exception as e:
            logging.critical(f"Erro crítico: {str(e)}")
            self.stop()
            
    def _process_packets(self):
        """Processa pacotes e verifica anomalias"""
        packets = self.sniffer.stop()
        for packet in packets:
            self.analyzer.analyze_packet(packet)
            
        anomalies = self.analyzer.detect_anomalies()
        if anomalies:
            self._handle_anomalies(anomalies)
            
        self.sniffer.start()  # Reinicia o sniffer
            
    def _handle_anomalies(self, anomalies: List[Dict]):
        """Trata anomalias detectadas"""
        logging.warning(f"Anomalias detectadas: {len(anomalies)}")
        
        packet_data = self._capture_traffic()
        context = {
            'timestamp': datetime.now().isoformat(),
            'anomalies': anomalies,
            'baseline': self.analyzer.baseline
        }
        
        response = self.api_client.send_for_analysis(
            packet_data,
            json.dumps(context)
        )
        
        if response and response.get('confidence', 0) > self.config['api']['threshold']:
            for action in response.get('actions', []):
                self.responder.execute_response(
                    action['type'],
                    action['target']
                )
                
    def _capture_traffic(self) -> str:
        """Captura tráfego para análise"""
        # Implementar captura de pacotes recentes
        # Retornar resumo formatado
        return "Dados de tráfego capturados..."
        
    def stop(self, signum=None, frame=None):
        """Para o sistema de monitoramento"""
        logging.info("Parando ART-System...")
        self.running = False
        self.sniffer.stop()
        sys.exit(0)

def load_config(file_path: str) -> Dict:
    """Carrega configuração com verificação de estrutura"""
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Arquivo não encontrado: {file_path}")

        with open(file_path, 'r') as f:
            user_config = yaml.safe_load(f) or {}

            # Verificação de tipo primário
            if not isinstance(user_config, dict):
                raise ValueError("Configuração deve ser um dicionário")

            # Merge hierárquico
            config = deepmerge(DEFAULT_CONFIG, user_config)

            # Validação de estrutura
            required_sections = {
                'network': dict,
                'api': dict,
                'logging': dict
            }
            
            for section, stype in required_sections.items():
                if section not in config:
                    raise ValueError(f"Seção obrigatória ausente: {section}")
                if not isinstance(config[section], stype):
                    raise ValueError(f"Tipo inválido para {section}. Esperado: {stype}")

            return config

    except Exception as e:
        logging.critical(f"Erro na configuração: {str(e)}")
        sys.exit(1)

def deepmerge(default, custom):
    """Faz merge seguro de dicionários aninhados"""
    merged = default.copy()
    for key, value in custom.items():
        if isinstance(value, dict) and key in default:
            merged[key] = deepmerge(default[key], value)
        else:
            merged[key] = value
    return merged

def setup_logging(config: Dict):
    """Configura sistema de logging"""
    logging.basicConfig(
        level=config['logging']['level'],
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(config['logging']['file']),
            logging.StreamHandler()
        ]
    )

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='config.yaml',
                        help='Caminho para o arquivo de configuração')
    args = parser.parse_args()
    
    config = load_config(args.config)

# Verificação final de integridade (adicionar estas linhas)
if 'logging' not in config:
    print("ERRO CRÍTICO: Seção 'logging' ausente na configuração!")
    print("Configuração carregada:", json.dumps(config, indent=2))
    sys.exit(1)

if not isinstance(config['logging'], dict):
    print("ERRO CRÍTICO: Seção 'logging' mal formatada!")
    print("Tipo encontrado:", type(config['logging']))
    sys.exit(1)

    setup_logging(config['logging'])
    
    if os.geteuid() != 0:
        logging.error("Requer privilégios de root/sudo")
        sys.exit(1)
        
    art_system = ARTSystem(config)
    art_system.start()