#!/usr/bin/env python3
"""
Script de PenTest que consome a API do DeepSeek via Ollama.

Funcionalidades:
    - Escaneamento de um único IP/Domínio utilizando Nmap, Nikto, Amass, theHarvester, sublist3r, dnsrecon e SSLyze.
    - Todos os scanners (exceto masscan) utilizam a mesma entrada (alvo) e são executados sequencialmente.
    - Cada ferramenta é executada e seu resultado é enviado individualmente para a API do DeepSeek;
      a próxima ferramenta só é acionada após o recebimento pela API da análise anterior.
    - Menu separado para executar o masscan, que solicita os parâmetros necessários.
    - Integração dos resultados de todas as ferramentas em uma única saída, enviada para a API do DeepSeek.
    - Visualização e exportação dos resultados (JSON e HTML).
    - Salvamento automático dos IPs encontrados em network_devices.txt.
    - Gravação dos resultados no banco de dados SQLite (scan_results.db).

Requisitos:
    - Python 3.7+
    - Ferramentas instaladas e acessíveis via linha de comando: Nmap, Nikto, Amass, theHarvester, sublist3r, dnsrecon, masscan e SSLyze.
    - API do DeepSeek (via Ollama) rodando localmente.
    - Bibliotecas: requests (pip install requests) e rich (pip install rich).
    - Biblioteca para banco de dados SQLite (nativa no Python) ou outro DB à sua escolha.

Autor: Thalles Canela
Data: 2025-02-02 (Atualizado: 2025-02-08)
"""

import os
import subprocess
import json
import re
import socket
import sqlite3  # Biblioteca nativa para SQLite
from datetime import datetime
import requests
from rich.console import Console

# ==================== CONFIGURAÇÕES GLOBAIS ====================

API_ENDPOINT = "http://localhost:5000/analyze"
API_KEY = "sk_prod_1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

### Você pode escolher qual será contexto da análise: Proteção ou Exploração ###

### Feito com DeepSeek-R1
#CONTEXT_MESSAGE_Misto="Objetivo: Fornecer uma análise técnica aprofundada e correlacionada dos resultados de PenTest, combinando identificação de vulnerabilidades, avaliação de riscos, sugestões de exploração e recomendações de mitigação. A análise deve considerar dados de uma única ferramenta por relatório, garantindo precisão e contextualização adequada.\n\nPonto importante de atenção:\n- Você só receberá relatórios de 1 ferramenta por vez.\n- Identifique qual ferramenta gerou o relatório (ex: Nmap, Nikto, Amass, etc.).\n- Processe apenas as informações da ferramenta que enviou o relatório.\n- Formato de resposta: PT-BR (Português do Brasil).\n- Estrutura da resposta organizada em seções (por ferramenta ou categoria de risco).\n- Destaque riscos críticos e CVEs.\n- Use listas para PoCs (Proofs of Concept) e recomendações.\n- Conclusão com resumo executivo (impacto geral e ações prioritárias).\n\nInstruções detalhadas:\n1. Análise por ferramenta:\n   - Descreva os resultados do relatório, identificando a ferramenta utilizada (ex: Nmap para portas abertas, Nikto para vulnerabilidades web).\n   - Contextualize o papel da ferramenta no escopo do PenTest (ex: SSLyze para avaliação SSL/TLS).\n2. Classificação de riscos:\n   - Classifique vulnerabilidades por gravidade (baixa, média, alta), usando matriz de risco (impacto x probabilidade).\n   - Priorize CVEs conhecidos e vulnerabilidades com exploração pública.\n3. Vetores de exploração e PoCs:\n   - Para cada vulnerabilidade, sugira vetores de exploração (ex: uso de Metasploit para serviços desatualizados).\n   - Inclua ideias de PoCs práticos (ex: comandos curl para testar XSS, scripts para verificar SQLi).\n4. Recomendações técnicas:\n   - Liste ações específicas para mitigação (ex: atualizar serviços, corrigir configurações).\n   - Explique como cada medida neutraliza o vetor de ataque associado.\n5. Validação de falsos positivos:\n   - Indique métodos para confirmar resultados (ex: testes manuais, uso de Nessus ou Burp Suite).\n6. Avaliação de impacto:\n   - Descreva cenários de exploração realistas (ex: acesso não autorizado via subdomínio esquecido).\n   - Relacione vulnerabilidades a impactos operacionais (ex: vazamento de dados, interrupção de serviços).\n7. Terminologia técnica:\n   - Use termos como exploit, payload, hardening e CVE para manter precisão.\n\nExemplo de estrutura esperada na resposta:\n- Ferramenta analisada: [Nome da ferramenta]\n- Riscos identificados:\n  - [Alta gravidade] Vulnerabilidade X (CVE-XXXX-XXXX): Descrição técnica.\n  - Vetor de exploração: Descrição de como um atacante poderia explorar a falha.\n  - PoC sugerido: Comando ou script para validação.\n- Recomendações:\n  - Aplicar patch Y na versão do serviço Z.\n  - Configurar firewall para bloquear porta exposta.\n- Falsos positivos:\n  - Vulnerabilidade A requer validação manual via [método].\n\nConclusão (Resumo executivo):\n- Impacto geral: Resumo dos riscos críticos e seu potencial impacto no ambiente.\n- Ações prioritárias: Lista concisa das correções mais urgentes (ex: corrigir CVE crítico, remover subdomínio mal configurado).\n\nObservação final:\n- Mantenha a resposta em PT-BR, com clareza técnica e organização lógica.\n- Priorize a acionabilidade: cada item deve permitir que a equipe de segurança execute correções ou validações."

##@ Feito com ChatGTP o1
CONTEXT_MESSAGE_Misto=( "Prompt para Análise Técnica Aprofundada:" "" "Objetivo:" "Fornecer uma análise técnica, aprofundada e correlacionada dos resultados dos scans de PenTest, identificando, classificando e interpretando os riscos e vulnerabilidades detectados no alvo, bem como explorando possíveis vetores de ataque e proofs-of-concept (PoCs) quando aplicável. Os dados foram coletados pelas ferramentas Nmap, Nikto, Amass, theHarvester, sublist3r, dnsrecon e SSLyze, podendo incluir informações sobre portas abertas, detecção de serviços, enumeração de subdomínios, vulnerabilidades conhecidas, configurações de SSL/TLS, banners e informações DNS." "" "Ponto importante de atenção:" "- Você só irá receber relatórios de 1 ferramenta por vez." "- Identifique a ferramenta que esteja enviando o relatório para ser analisado." "- Processe apenas informações da ferramenta da qual você recebeu o relatório." "- Formato de linguagem da Resposta Esperado: PT-BR (Portugues do Brasil)." "- Estruturado em seções (por ferramenta ou categoria de risco)." "- Destaque em negrito riscos críticos e CVEs." "- Use listas para PoCs e recomendações." "- Conclusão com resumo executivo (impacto geral e ações prioritárias)." "" "Instruções de Análise (combinando aspectos de detecção, mitigação e exploração):" "1) Organização e Detalhamento:" " a) Analise detidamente o conteúdo do relatório recebido, classificando as informações por ferramenta (Nmap, Nikto, Amass, theHarvester, sublist3r, dnsrecon, SSLyze) ou por categoria de risco (baixa, média, alta)." " b) Destaque informações críticas e referências a vulnerabilidades conhecidas (CVE) ou boas práticas de segurança." "" "2) Identificação e Classificação de Riscos:" " a) Classifique cada vulnerabilidade ou achado em termos de gravidade (baixa, média, alta) com base em impacto e probabilidade." " b) Sempre que possível, inclua referências a CVEs e evidências técnicas para embasar a análise." "" "3) Exploração e Vetores de Ataque:" " a) Para cada vulnerabilidade, descreva possíveis vetores de exploração, incluindo exemplos de uso de ferramentas como Metasploit ou scripts personalizados." " b) Forneça ideias de proof-of-concept (PoC) demonstrando como validar ou explorar a falha (por exemplo, scripts em Python, uso de Burp Suite para interceptar e manipular requisições HTTP, técnicas de brute force, fuzzing etc.)." "" "4) Recomendações de Mitigação:" " a) Para cada falha, apresente recomendações técnicas específicas de correção ou mitigação (aplicar patches, hardening de sistemas, substituir protocolos obsoletos, renovar certificados etc.)." " b) Explique de que forma cada medida recomendada bloqueia ou dificulta o vetor de ataque apontado." "" "5) Falsos Positivos e Validação:" " a) Considere possíveis falsos positivos, indicando métodos de validação (verificações manuais, uso de múltiplas ferramentas, testes adicionais em ambiente controlado)." "" "6) Avaliação de Impacto:" " a) Descreva cenários de como as vulnerabilidades podem ser exploradas e o impacto resultante no ambiente." " b) Inclua exemplos de ataques reais ou hipotéticos (subdomínios esquecidos que podem permitir phishing, portas abertas que possibilitam movimentação lateral etc.)." "" "7) Terminologia e Linguagem:" " a) Utilize terminologia técnica de segurança da informação e de PenTest (enumerar, hardening, payload, exploit, post-exploitation etc.)." " b) Apresente toda a análise em Português do Brasil." "" "8) Conclusão e Resumo Executivo:" " a) Forneça um breve resumo dos principais riscos e vulnerabilidades encontradas." " b) Destaque as ações prioritárias a serem tomadas, considerando o impacto geral no ambiente." "" "Observação final:" "Você está recebendo dados levantados pelas ferramentas Nmap, Nikto, Amass, theHarvester, sublist3r, dnsrecon e SSLyze. Toda a análise gerada deve ser apresentada em Português do Brasil, estruturando as seções de forma clara e enfatizando riscos críticos e referências a CVEs em negrito, além de recomendar medidas de correção ou mitigação para cada item identificado." )

CONTEXT_MESSAGE_Protecao = (
    "Objetivo: Fornecer uma análise técnica, aprofundada e correlacionada dos resultados dos scans de PenTest, "
    "identificando, classificando e interpretando os riscos e vulnerabilidades detectados no alvo. "
    "Os resultados foram coletados por diversas ferramentas (Nmap, Nikto, Amass, theHarvester, sublist3r, dnsrecon e SSLyze) e podem conter dados sobre "
    "port scanning, detecção de serviços, enumeração de subdomínios, vulnerabilidades conhecidas e informações DNS. \n\n"
    
    "Instruções:\n"
    "1. Analise detalhadamente os resultados apresentados, organizando-os por ferramenta e destacando informações críticas. Considere o papel de cada ferramenta:\n"
    "   - Nmap: Identificação de portas abertas, serviços expostos e sistemas operacionais.\n"
    "   - Nikto: Detecção de vulnerabilidades em servidores web, como configurações inseguras e arquivos sensíveis expostos.\n"
    "   - Amass/theHarvester: Enumeração de subdomínios e coleta de informações públicas (OSINT).\n"
    "   - Sublist3r/dnsrecon: Descoberta de registros DNS e subdomínios esquecidos ou mal configurados.\n"
    "   - SSLyze: Análise de configurações de SSL/TLS, identificando problemas como certificados expirados ou protocolos inseguros.\n"
    "2. Identifique e classifique as vulnerabilidades e riscos encontrados, determinando a gravidade de cada item (baixa, média, alta) com base em uma matriz de risco (impacto x probabilidade). Sempre que possível, referencie CVEs ou boas práticas de segurança.\n"
    "3. Forneça recomendações técnicas específicas para a mitigação ou correção de cada vulnerabilidade, incluindo sugestões de controles e medidas corretivas. Exemplos:\n"
    "   - Serviços desatualizados: Aplicar patches ou substituir por alternativas seguras.\n"
    "   - Configurações inseguras: Implementar hardening de sistemas e servidores.\n"
    "   - Certificados SSL/TLS: Renovar certificados expirados e desativar protocolos obsoletos (ex.: TLS 1.0).\n"
    "4. Considere possíveis falsos positivos e indique métodos para sua validação, como verificações manuais, uso de múltiplas ferramentas ou testes adicionais em ambiente controlado.\n"
    "5. A análise deve conter uma avaliação de impacto, detalhando como as vulnerabilidades podem ser exploradas e afetar o ambiente. Inclua cenários hipotéticos ou exemplos reais de ataques relacionados. Exemplo:\n"
    "   - Portas abertas em firewalls podem permitir acesso não autorizado a serviços internos.\n"
    "   - Subdomínios esquecidos podem ser usados para phishing ou ataques de força bruta.\n"
    "6. Utilize terminologia técnica de PenTest e de segurança da informação, como 'CVE', 'hardening', 'enumeração' e 'falsos positivos'.\n\n"
    
    "Você está recebendo dados levantados pelos softwares: Nmap, Nikto, Amass, theHarvester, sublist3r, dnsrecon e SSLyze. "
    "Observação importante: Apresente toda a sua análise em Português do Brasil (PT-BR). "
    "Observação importante: Resultados sempre em Português do Brasil (PT-BR)."
)

CONTEXT_MESSAGE_Exploracao = (
    "Objetivo: Fornecer uma análise técnica, aprofundada e orientada para a exploração das vulnerabilidades detectadas pelo SCAN, "
    "identificando, classificando e interpretando os riscos e falhas de segurança encontrados no alvo, e sugerindo vetores de exploração e proof-of-concept quando aplicável. "
    "Os dados foram coletados por diversas ferramentas (Nmap, Nikto, Amass, theHarvester, sublist3r, dnsrecon e SSLyze) e podem incluir informações sobre "
    "port scanning, detecção de serviços, enumeração de subdomínios, vulnerabilidades conhecidas, banners e informações DNS.\n\n"
    
    "Instruções:\n"
    "1. Analise detalhadamente os resultados apresentados, organizando-os por ferramenta e destacando as informações críticas para a exploração das falhas. Considere o papel de cada ferramenta:\n"
    "   - Nmap: Identificação de portas abertas e serviços expostos.\n"
    "   - Nikto: Detecção de vulnerabilidades em servidores web.\n"
    "   - Amass/theHarvester: Enumeração de subdomínios e informações públicas.\n"
    "   - SSLyze: Análise de configurações de SSL/TLS.\n"
    "2. Identifique e classifique as vulnerabilidades e riscos encontrados, determinando a gravidade de cada item (baixa, média, alta) com base em uma matriz de risco (impacto x probabilidade). Sempre que possível, referencie CVEs e evidências técnicas.\n"
    "3. Para cada vulnerabilidade, forneça sugestões de vetores de exploração, descrevendo como um atacante poderia utilizar a falha para comprometer o alvo. Exemplos:\n"
    "   - Serviços desatualizados: Uso de exploits públicos via Metasploit.\n"
    "   - Subdomínios esquecidos: Brute force ou fuzzing para encontrar endpoints vulneráveis.\n"
    "4. Inclua ideias de proof-of-concept, como scripts ou comandos simples para validar a vulnerabilidade. Exemplo:\n"
    "   - Script Python para testar injeção SQL.\n"
    "   - Uso do Burp Suite para interceptar e manipular requisições HTTP.\n"
    "5. Apresente recomendações técnicas específicas para a mitigação ou correção das vulnerabilidades, sugerindo controles e medidas corretivas adequadas. Explique como cada controle bloquearia o vetor de ataque sugerido.\n"
    "6. Considere a possibilidade de falsos positivos, indicando métodos para sua validação, como verificações manuais ou uso de múltiplas ferramentas.\n"
    "7. A análise deve incluir uma avaliação do impacto, detalhando as consequências de uma exploração bem-sucedida para o ambiente. Inclua cenários hipotéticos ou exemplos reais de ataques relacionados.\n"
    "8. Utilize terminologia técnica avançada de PenTest e de segurança da informação, como 'payload', 'exploit' e 'post-exploitation'.\n\n"
    
    "Você está recebendo dados levantados pelos softwares: Nmap, Nikto, Amass, theHarvester, sublist3r, dnsrecon e SSLyze. "
    "Observação importante: Apresente toda a sua análise em Português do Brasil (PT-BR). "
    "Observação importante: Resultados sempre em Português do Brasil (PT-BR)."
)

RESULTS_FILE = "results.json"
NETWORK_DEVICES_FILE = "network_devices.txt"

DB_FILE = "scan_results.db"  # Nome do arquivo local do banco SQLite

console = Console()

# ==================== FUNÇÕES DE BANCO DE DADOS ====================

def init_db():
    """
    Cria o arquivo de banco de dados (scan_results.db) e a tabela scan_results (caso não existam).
    """
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(
        """CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            target TEXT,
            combined_output TEXT,
            analysis TEXT
        )"""
    )
    conn.commit()
    conn.close()

def save_to_database(timestamp, target, combined_output, analyses):
    """
    Insere um novo registro na tabela scan_results com todas as análises.
    - analyses: dicionário com todas as análises das ferramentas
    """
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO scan_results (timestamp, target, combined_output, analysis)
           VALUES (?, ?, ?, ?)""",
        (timestamp, target, combined_output, json.dumps(analyses, ensure_ascii=False))
    )  # <-- Este parêntese estava faltando
    conn.commit()
    conn.close()

# ==================== FUNÇÕES AUXILIARES ====================

def normalize_target(target):
    """
    Normaliza o alvo removendo prefixos como http://, https://, www., etc.,
    garantindo que o formato seja adequado para as diferentes ferramentas.
    - Para IPs: retorna o IP sem modificações.
    - Para domínios: remove protocolos e subdomínios www.
    - Mantém porta se especificada (ex: google.com:443 → google.com:443).
    - Preserva caminhos após o domínio (ex: http://site.com/path → site.com/path).
    """
    target = target.strip().lower()
    for proto in ["http://", "https://", "www.", "http", "https", "ftp://", "sftp://"]:
        if target.startswith(proto):
            target = target[len(proto):]
            break
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$', target):
        target = target.lstrip("www.")
    return target

def log_message(msg):
    """Exibe uma mensagem no terminal com data/hora."""
    console.print(f"[bold][{datetime.now().isoformat()}][/bold] {msg}")

def is_ip(target):
    """Retorna True se o target for um endereço IP no formato xxx.xxx.xxx.xxx."""
    return re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target) is not None

def run_nmap_scan(target):
    """
    Executa diversos scans agressivos com Nmap para o alvo especificado,
    utilizando um target normalizado (sem os prefixos).
    Retorna uma string com os resultados.
    """
    normalized_target = normalize_target(target)
    log_message(f"Iniciando scans Nmap para o alvo: {normalized_target}")
    results = {}
    commands = [
    (
        "Intensive_Scan",
        [
            "nmap",
            "-T4",
            "-A",
            "-v",
            "-Pn",
            "--reason",
            "--traceroute",
            "--version-intensity", "9",
            "--script", "vuln,exploit,default,safe,vulners,vulscan/vulscan.nse",
            "--script-args", "vulscanshowall=1,vulscanoutput=details",
            normalized_target
        ]
    ),
    (
        "Comprehensive_Scan",
        [
            "nmap",
            "-sS",
            "-sU",
            "-T4",
            "-A",
            "-v",
            "-PE",
            "-PP",
            "-PA3389",
            "-PU40125",
            "-PY",
            "-g", "53",
            "--reason",
            "--version-intensity", "9",
            "--min-rate", "500",
            "--max-retries", "2",
            "--script", "default,discovery,safe,vulners,vulscan/vulscan.nse",
            "--script-args", "vulscanshowall=1,vulscanoutput=details",
            normalized_target
        ]
    ),
    (
        "Additional_Info",
        [
            "nmap",
            "-sV",
            "--version-intensity", "9",
            "--script", "asn-query,whois-ip,ip-geolocation-maxmind,default",
            normalized_target
        ]
    ),
    (
        "DDoS_Simulation",
        [
            "nmap",
            "-sU",
            "--script", "ntp-monlist,dns-recursion,snmp-sysdescr",
            "-p", "U:19,53,123,161",
            normalized_target
        ]
    ),
    (
        "Firewall_Check",
        [
            "nmap",
            "-sA",
            "-Pn",
            "--script", "firewall-bypass",
            normalized_target
        ]
    ),
    (
        "Full_Scan",
        [
            "nmap",
            "-p-",
            "-A",
            "-T4",
            "--reason",
            "--version-intensity", "9",
            "--min-rate", "500",
            "--max-retries", "2",
            "--script", "default,vulners,vulscan/vulscan.nse",
            "--script-args", "vulscanshowall=1,vulscanoutput=details",
            normalized_target
        ]
    )
]
    
    for scan_type, cmd in commands:
        log_message(f"Executando {scan_type.replace('_', ' ').lower()}...")
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            results[scan_type] = proc.stdout
        except subprocess.CalledProcessError as e:
            error = f"Erro no {scan_type.replace('_', ' ').lower()}: {e.stderr}"
            log_message(error)
            results[scan_type] = error

    log_message(f"Scans Nmap concluídos para: {normalized_target}\n")
    combined = f"=== RESULTADOS NMAP para {normalized_target} ===\n\n"
    for key, output in results.items():
        combined += f"==== {key} ====\n{output}\n\n"
    return combined

def get_server_ip(target):
    """
    Tenta resolver o endereço IP para o domínio/host fornecido.
    Se o target já for um IP, apenas o retorna.
    """
    if is_ip(target):
        return target
    try:
        ip_address = socket.gethostbyname(target)
        log_message(f"Endereço IP resolvido para {target}: {ip_address}")
        return ip_address
    except Exception as e:
        console.print(f"[-] Erro ao resolver IP para {target}: {e}", style="bold red")
        return None

def run_nikto_scan(target):
    """Executa Nikto (host + tuning 9) e retorna a saída."""
    log_message(f"Iniciando Nikto para {target}")
    try:
        cmd = ["nikto", "-host", f"{target}", "-Tuning", "9"]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return proc.stdout
    except subprocess.CalledProcessError as e:
        error = f"Erro no Nikto: {e.stderr}"
        log_message(error)
        return error

def run_amass_enum(target):
    """Executa o Amass no modo ativo e retorna a saída."""
    normalized_target = normalize_target(target)
    log_message(f"Iniciando Amass para {normalized_target}")
    try:
        cmd = ["amass", "enum", "-active", "-d", normalized_target, "-src", "-ip"]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return proc.stdout
    except subprocess.CalledProcessError as e:
        error = f"Erro no Amass: {e.stderr}"
        log_message(error)
        return error

def run_theharvester(target):
    """Executa theHarvester e retorna a saída."""
    normalized_target = normalize_target(target)
    log_message(f"Iniciando theHarvester para {normalized_target}")
    output_file = f"output_{normalized_target.replace('.', '_')}.html"  # gera nome de arquivo dinâmico
    try:
        cmd = [
            "python3", "/opt/theHarvester/theHarvester.py",
            "-d", normalized_target,
            "-l", "500",
            "-S", "0",
            "-p",       # utilizar proxies se configurados
            "-v",       # verbose
            "-e", "8.8.8.8",  # servidor DNS
            "-n",       # DNS lookup
            "-c",       # DNS brute force
            "-f", output_file,
            "-b", "duckduckgo"
        ]
        log_message(f"Executando theHarvester com o comando: {' '.join(cmd)}")
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        log_message(f"theHarvester finalizado. Resultados salvos em {output_file}")
        return proc.stdout
    except subprocess.CalledProcessError as e:
        error = f"Erro no theHarvester: {e.stderr}"
        log_message(error)
        return error

def run_sublist3r(target):
    """Executa o Sublist3r e retorna a saída."""
    normalized_target = normalize_target(target)
    console.print(f"[bold green]Iniciando Sublist3r para {normalized_target}[/bold green]")
    try:
        cmd = [
            "python3", "/opt/Sublist3r/sublist3r.py",
            "-d", normalized_target,
            "-t", "100",
            "-o", "sublist3r_output.txt",
            "-n"
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return proc.stdout
    except subprocess.CalledProcessError as e:
        error = f"Erro no Sublist3r: {e.stderr}"
        console.print(f"[bold red]{error}[/bold red]")
        return error

def run_dnsrecon(target):
    """Executa dnsrecon (modo -a) e retorna a saída."""
    log_message(f"Iniciando dnsrecon para {target}")
    try:
        cmd = ["dnsrecon", "-d", target, "-a"]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return proc.stdout
    except subprocess.CalledProcessError as e:
        error = f"Erro no dnsrecon: {e.stderr}"
        log_message(error)
        return error

def run_masscan():
    """
    Menu exclusivo para execução do masscan.
    Solicita do usuário:
      - Range de rede
      - Faixa de portas
      - Taxa de envio
    Retorna a saída.
    """
    console.print("\n==== Masscan Scan ====", style="bold blue")
    network_range = input("Digite o range de rede (ex.: 192.168.1.0/24): ").strip()
    port_range = input("Digite a faixa de portas (ex.: 0-65535): ").strip()
    rate = input("Digite a taxa de envio (ex.: 10000): ").strip()
    cmd = ["masscan", network_range, "-p" + port_range, "--rate=" + rate]
    log_message(f"Executando masscan: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        output = proc.stdout
        console.print("\n=== Resultado do Masscan ===", style="bold blue")
        console.print(output)
        return output
    except subprocess.CalledProcessError as e:
        error = f"Erro no Masscan: {e.stderr}"
        log_message(error)
        return error

def ping_scan(network_range):
    """Executa um scan de ping (nmap -sn) para descobrir dispositivos na rede."""
    console.print(f"\n[+] Realizando ping scan na rede: {network_range}", style="bold green")
    try:
        cmd = ["nmap", "-sn", network_range]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        output = proc.stdout
        ips = re.findall(r'Nmap scan report for ([\d\.]+)', output)
        if ips:
            with open(NETWORK_DEVICES_FILE, "w", encoding="utf-8") as f:
                for ip in ips:
                    f.write(ip + "\n")
            console.print(f"[+] IPs encontrados: {', '.join(ips)}", style="bold green")
        else:
            console.print("[-] Nenhum dispositivo encontrado.", style="bold red")
        return ips
    except subprocess.CalledProcessError as e:
        console.print(f"[-] Erro no ping scan: {e.stderr}", style="bold red")
        return []

def run_sslyze_scan(target):
    """
    Executa uma varredura agressiva com SSLyze para o alvo especificado.
    - Normaliza o target e, se não houver porta, adiciona ":443" como padrão.
    - Utiliza diversas flags para testar vulnerabilidades e configurações TLS de forma agressiva.
    Retorna a saída do comando (stdout) e, se houver apenas warnings conhecidos, os anexa ao output.
    
    Correções aplicadas:
      * Não se considera o aviso "CryptographyDeprecationWarning: Parsed a negative serial number..."
        como erro fatal, conforme sugerido em discussões na issue #6609 [&#8203;:contentReference[oaicite:2]{index=2}] e
        pela documentação e suporte (ex.: [&#8203;:contentReference[oaicite:3]{index=3}]).
    """
    normalized_target = normalize_target(target)
    # Se o target não incluir a porta, adiciona ":443"
    if ":" not in normalized_target:
        normalized_target = f"{normalized_target}:443"
    
    log_message(f"Iniciando scan SSLyze para {normalized_target}")
    
    cmd = [
        "sslyze",
        "--heartbleed",
        "--fallback",
        "--certinfo",
        "--tlsv1",
        "--tlsv1_1",
        "--tlsv1_2",
        "--tlsv1_3",
        "--sslv3",
        "--sslv2",
        "--openssl_ccs",
        "--reneg",
        "--elliptic_curves",
        "--compression",
        "--early_data",
        "--resum",
        "--resum_attempts", "100",
        "--robot",
        "--mozilla_config", "modern",
        normalized_target
    ]
    
    log_message(f"Executando SSLyze com o comando: {' '.join(cmd)}")
    
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Se o código de retorno for diferente de zero, verificamos se o stderr contém apenas o aviso conhecido.
        if proc.returncode != 0:
            # Caso o stderr contenha o aviso de serial negativo (conhecido) e não haja outros erros significativos,
            # consideramos o scan como bem-sucedido, apenas com avisos.
            if "CryptographyDeprecationWarning" in proc.stderr and "negative serial number" in proc.stderr:
                combined_output = proc.stdout + "\n[AVISOS do SSLyze]\n" + proc.stderr.strip()
                log_message("Scan SSLyze concluído com avisos.")
                return combined_output
            else:
                error_msg = f"Erro no SSLyze (codigo: {proc.returncode}):\n{proc.stderr}"
                log_message(error_msg)
                return error_msg
        
        # Se não houver erro, anexa eventuais avisos (se houver) ao output.
        output = proc.stdout
        if proc.stderr.strip():
            output += "\n[AVISOS do SSLyze]\n" + proc.stderr.strip()
        log_message("Scan SSLyze concluído com sucesso.")
        return output
    
    except Exception as e:
        error_msg = f"Erro ao executar o SSLyze: {str(e)}"
        log_message(error_msg)
        return error_msg

# ==================== FUNÇÃO DE ENVIO PARA A API ====================
def send_to_deepseek(scan_data):
    """
    Envia os dados para a API do DeepSeek com o contexto de Proteção.
    Retorna a resposta da API como dicionário.
    
    Exibe o conteúdo que foi de fato enviado para a API.
    """
    payload = {
        "scan_data": scan_data,
        "context": CONTEXT_MESSAGE_Misto
    }
    headers = {"X-API-Key": API_KEY}
    try:
        console.print("\n[+] Enviando dados para a API do DeepSeek...", style="bold green")
        response = requests.post(API_ENDPOINT, json=payload, headers=headers, timeout=200000)
        if response.status_code == 200:
            console.print("[+] Dados enviados com sucesso.", style="bold green")
            
            # Exibe na tela o conteúdo enviado para a API
            console.print("\n=== Conteúdo Enviado para a API ===", style="bold cyan")
            console.print(scan_data)
            
            analysis = response.json()
            display_analysis(analysis)
            return analysis
        else:
            console.print(f"[-] Erro na API. Código: {response.status_code}", style="bold red")
            return None
    except Exception as e:
        console.print(f"[-] Exceção ao enviar dados: {e}", style="bold red")
        return None

def display_analysis(analysis):
    """Exibe a análise do DeepSeek de forma formatada."""
    console.print("\n=== Análise do DeepSeek ===", style="bold blue")
    analysis_text = analysis.get("analysis", "Nenhuma análise disponível.")
    processing_time = analysis.get("processing_time", 0)
    console.print("\n[bold]Resultado da Análise:[/bold]", style="bold green")
    console.print(analysis_text, style="white")
    console.print(f"\n[bold]Tempo de Processamento:[/bold] {processing_time:.2f} segundos", style="bold green")

# ==================== FUNÇÃO NOVA: SCANS SEQUENCIAIS ====================
def run_scans_sequential(target):
    """
    Executa os scans de cada ferramenta de forma sequencial.
    Para cada ferramenta:
      - Executa o scan.
      - Envia o resultado individual para a API do DeepSeek.
      - Aguarda a resposta da API antes de prosseguir para a próxima ferramenta.
    
    Retorna um dicionário com os outputs e as análises individuais.
    """
    tool_results = {"target": target}
    
    # 1) Nmap
    console.print("\n=== Iniciando scan Nmap ===", style="bold blue")
    nmap_output = run_nmap_scan(target)
    tool_results["nmap_output"] = nmap_output
    tool_results["nmap_analysis"] = send_to_deepseek(nmap_output)
    
    # 2) Nmap adicional para IP (se aplicável)
    ip_address = get_server_ip(target)
    if ip_address and ip_address != target:
        console.print("\n=== Iniciando scan Nmap para IP resolvido ===", style="bold blue")
        nmap_ip_output = run_nmap_scan(ip_address)
        tool_results["nmap_ip_output"] = nmap_ip_output
        tool_results["nmap_ip_analysis"] = send_to_deepseek(nmap_ip_output)
    else:
        tool_results["nmap_ip_output"] = "Scan adicional não realizado (alvo já é IP ou resolução falhou)."
        tool_results["nmap_ip_analysis"] = None
    
    # 3) Nikto
    console.print("\n=== Iniciando scan Nikto ===", style="bold blue")
    nikto_output = run_nikto_scan(target)
    tool_results["nikto_output"] = nikto_output
    tool_results["nikto_analysis"] = send_to_deepseek(nikto_output)
    
    # 4) Amass (apenas se o alvo não for IP)
    if not is_ip(target):
        console.print("\n=== Iniciando scan Amass ===", style="bold blue")
        amass_output = run_amass_enum(target)
        tool_results["amass_output"] = amass_output
        tool_results["amass_analysis"] = send_to_deepseek(amass_output)
    else:
        tool_results["amass_output"] = "Amass não executado para IP."
        tool_results["amass_analysis"] = None
    
    # 5) theHarvester
    console.print("\n=== Iniciando scan theHarvester ===", style="bold blue")
    theharvester_output = run_theharvester(target)
    tool_results["theharvester_output"] = theharvester_output
    tool_results["theharvester_analysis"] = send_to_deepseek(theharvester_output)
    
    # 6) Sublist3r
    console.print("\n=== Iniciando scan Sublist3r ===", style="bold blue")
    sublist3r_output = run_sublist3r(target)
    tool_results["sublist3r_output"] = sublist3r_output
    tool_results["sublist3r_analysis"] = send_to_deepseek(sublist3r_output)
    
    # 7) dnsrecon
    console.print("\n=== Iniciando scan dnsrecon ===", style="bold blue")
    dnsrecon_output = run_dnsrecon(target)
    tool_results["dnsrecon_output"] = dnsrecon_output
    tool_results["dnsrecon_analysis"] = send_to_deepseek(dnsrecon_output)
    
    # 8) SSLyze
    console.print("\n=== Iniciando scan SSLyze ===", style="bold blue")
    sslyze_output = run_sslyze_scan(target)
    tool_results["sslyze_output"] = sslyze_output
    tool_results["sslyze_analysis"] = send_to_deepseek(sslyze_output)
    
    # Monta a saída combinada (apenas para referência ou salvamento posterior)
    combined_output = (
        f"=== RESULTADOS NMAP ===\n{tool_results.get('nmap_output', '')}\n\n"
        f"=== RESULTADOS NMAP (IP resolvido) ===\n{tool_results.get('nmap_ip_output', '')}\n\n"
        f"=== RESULTADOS NIKTO ===\n{tool_results.get('nikto_output', '')}\n\n"
        f"=== RESULTADOS AMASS ===\n{tool_results.get('amass_output', '')}\n\n"
        f"=== RESULTADOS theHarvester ===\n{tool_results.get('theharvester_output', '')}\n\n"
        f"=== RESULTADOS Sublist3r ===\n{tool_results.get('sublist3r_output', '')}\n\n"
        f"=== RESULTADOS dnsrecon ===\n{tool_results.get('dnsrecon_output', '')}\n\n"
        f"=== RESULTADOS SSLyze ===\n{tool_results.get('sslyze_output', '')}\n"
    )
    tool_results["combined_output"] = combined_output
    
    return tool_results

# ==================== FUNÇÃO PARA EXIBIR RESULTADOS DE CADA FERRAMENTA ====================
def display_sequential_results(tool_results):
    """
    Exibe no console os resultados de cada ferramenta e suas análises individuais.
    """
    console.print("\n=== RESULTADOS DOS SCANS SEQUENCIAIS ===", style="bold magenta")
    for tool in ["nmap", "nmap_ip", "nikto", "amass", "theharvester", "sublist3r", "dnsrecon", "sslyze"]:
        output = tool_results.get(f"{tool}_output", "")
        analysis = tool_results.get(f"{tool}_analysis", {})
        console.print(f"\n----- {tool.upper()} -----", style="bold blue")
        console.print("[bold]Output:[/bold]")
        console.print(output)
        console.print("[bold]Análise:[/bold]")
        if analysis:
            console.print(analysis)
        else:
            console.print("Nenhuma análise disponível.", style="bold red")

# ==================== FUNÇÃO PARA SALVAR RESULTADOS ====================
def save_result(result_data):
    """
    Salva os resultados:
      1) Em um arquivo JSON (results.json).
      2) No banco de dados SQLite (scan_results.db).
      3) Em um arquivo HTML com o nome do alvo.
    """
    # [Restante do código anterior mantido...]
    
    # Salva no banco de dados
    try:
        timestamp = datetime.now().isoformat()
        target = result_data.get("target", "N/A")
        combined_output = result_data.get("combined_output", "N/A")
        
        # Coleta todas as análises das ferramentas
        analyses = {
            tool: result_data.get(f"{tool}_analysis")
            for tool in ["nmap", "nmap_ip", "nikto", "amass", 
                        "theharvester", "sublist3r", "dnsrecon", "sslyze"]
        }
        
        save_to_database(timestamp, target, combined_output, analyses)
        console.print("[+] Resultados gravados no banco de dados.", style="bold green")
    except Exception as e:
        console.print(f"[-] Erro ao salvar no banco de dados: {e}", style="bold red")

    # Salva relatório HTML
    try:
        target = result_data.get("target", "unknown_target")
        sanitized_target = re.sub(r'[^a-zA-Z0-9\-_]', '_', target)
        html_filename = f"{sanitized_target}.html"
        
        # Constrói conteúdo HTML com análises detalhadas
        html_content = f"""<html>
            <head>
                <meta charset='utf-8'>
                <title>Relatório de Scan - {target}</title>
                <style>
                    .analysis {{ margin-bottom: 2em; border: 1px solid #ddd; padding: 1em; }}
                    .tool-name {{ color: #2c3e50; font-weight: bold; }}
                    pre {{ white-space: pre-wrap; word-wrap: break-word; }}
                </style>
            </head>
            <body>
                <h1>Relatório de Scan para {target}</h1>
                <h2>Resultados Combinados</h2>
                <pre>{combined_output}</pre>
                
                <h2>Análises da API</h2>"""
        
        # Adiciona cada análise ao HTML
        for tool, analysis in analyses.items():
            if analysis:
                html_content += f"""
                <div class="analysis">
                    <div class="tool-name">{tool.upper()}</div>
                    <pre>{json.dumps(analysis, indent=4, ensure_ascii=False)}</pre>
                </div>"""
        
        html_content += "</body></html>"
        
        with open(html_filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        console.print(f"[+] Relatório HTML salvo como '{html_filename}'", style="bold green")
    except Exception as e:
        console.print(f"[-] Erro ao gerar relatório HTML: {e}", style="bold red")

def view_results():
    """Exibe os resultados salvos no arquivo JSON."""
    if not os.path.exists(RESULTS_FILE):
        console.print("[-] Nenhum resultado salvo encontrado.", style="bold red")
        return
    try:
        with open(RESULTS_FILE, "r", encoding="utf-8") as f:
            results = json.load(f)
        console.print("\n=== Resultados Salvos ===", style="bold blue")
        console.print(json.dumps(results, indent=4, ensure_ascii=False))
    except Exception as e:
        console.print(f"[-] Erro ao ler resultados: {e}", style="bold red")

### REMOVER ###
def export_results_to_html():
    """Exporta os resultados salvos para um arquivo HTML (results.html)."""
    if not os.path.exists(RESULTS_FILE):
        console.print("[-] Nenhum resultado salvo encontrado para exportação.", style="bold red")
        return
    try:
        with open(RESULTS_FILE, "r", encoding="utf-8") as f:
            results = json.load(f)
        html_content = (
            "<html><head><meta charset='utf-8'><title>Resultados do PenTest</title></head>"
            "<body><h1>Resultados do PenTest</h1><pre>"
            + json.dumps(results, indent=4, ensure_ascii=False) +
            "</pre></body></html>"
        )
        html_file = "results.html"
        with open(html_file, "w", encoding="utf-8") as f:
            f.write(html_content)
        console.print(f"[+] Resultados exportados para '{html_file}'", style="bold green")
    except Exception as e:
        console.print(f"[-] Erro ao exportar resultados para HTML: {e}", style="bold red")
### REMOVER ###

# ==================== MENU PRINCIPAL ====================

def main_menu():
    init_db()

    while True:
        console.print("\n==== Menu de PenTest ====", style="bold blue")
        console.print("1. Escanear um único IP/Domínio")
        console.print("2. Escanear uma lista de IPs/Domínios")
        console.print("3. Descoberta de dispositivos na rede")
        console.print("4. Visualizar resultados salvos")
        console.print("5. Sair")
        console.print("6. Executar Masscan")
        choice = input("Escolha uma opção: ").strip()
        
        if choice == "1":
            target = input("Digite o IP ou domínio para escanear: ").strip()
            scan_results = run_scans_sequential(target)
            display_sequential_results(scan_results)
            save_result(scan_results)
        
        elif choice == "2":
            file_path = input("Digite o caminho do arquivo com a lista: ").strip()
            if not os.path.exists(file_path):
                console.print(f"[-] Arquivo '{file_path}' não encontrado.", style="bold red")
                continue
            
            with open(file_path, "r", encoding="utf-8") as f:
                targets = [line.strip() for line in f if line.strip()]
            
            for t in targets:
                console.print(f"\n=== Iniciando scans para: {t} ===", style="bold blue")
                scan_results = run_scans_sequential(t)
                console.print(scan_results["combined_output"][:500] + "...", style="bold yellow")
                
                if input(f"Salvar resultados para {t}? (s/n): ").strip().lower() == 's':
                    save_result(scan_results)
        
        elif choice == "3":
            network_range = input("Digite o range da rede (ex.: 192.168.1.0/24): ").strip()
            ping_scan(network_range)
        
        elif choice == "4":
            view_results()
        
        elif choice == "5":
            console.print("Encerrando o script.", style="bold blue")
            break
        
        elif choice == "6":
            run_masscan()
        
        else:
            console.print("Opção inválida.", style="bold red")

if __name__ == "__main__":
    main_menu()