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
CONTEXT_MESSAGE_Protecao = (
    "Objetivo: Fornecer uma análise técnica, aprofundada e correlacionada dos resultados dos scans de PenTest, "
    "identificando, classificando e interpretando os riscos e vulnerabilidades detectados no alvo. "
    "Os resultados foram coletados por diversas ferramentas (Nmap, Nikto, Amass, theHarvester, sublist3r, dnsrecon e SSLyze) e podem conter dados sobre "
    "port scanning, detecção de serviços, enumeração de subdomínios, vulnerabilidades conhecidas e informações DNS. \n\n"
    
    "Instruções:\n"
    "1. Analise detalhadamente os resultados apresentados, organizando-os por ferramenta e destacando informações críticas.\n"
    "2. Identifique e classifique as vulnerabilidades e riscos encontrados, determinando a gravidade de cada item (ex.: baixa, média, alta) e, sempre que possível, referenciando CVEs ou boas práticas de segurança.\n"
    "3. Forneça recomendações técnicas específicas para a mitigação ou correção de cada vulnerabilidade, incluindo sugestões de controles e medidas corretivas.\n"
    "4. Considere possíveis falsos positivos e indique sugestões para sua validação, se aplicável.\n"
    "5. A análise deve conter uma avaliação de impacto, detalhando como as vulnerabilidades podem ser exploradas e afetar o ambiente.\n"
    "6. Utilize terminologia técnica de PenTest e de segurança da informação. \n\n"
    
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
    "1. Analise detalhadamente os resultados apresentados, organizando-os por ferramenta e destacando as informações críticas para a exploração das falhas.\n"
    "2. Identifique e classifique as vulnerabilidades e riscos encontrados, determinando a gravidade de cada item (ex.: baixa, média, alta) e, sempre que possível, referenciando CVEs e evidências técnicas.\n"
    "3. Para cada vulnerabilidade, forneça sugestões de vetores de exploração, descrevendo como um atacante poderia utilizar a falha para comprometer o alvo, e, se possível, inclua ideias de proof-of-concept.\n"
    "4. Apresente recomendações técnicas específicas para a mitigação ou correção das vulnerabilidades, sugerindo controles e medidas corretivas adequadas.\n"
    "5. Considere a possibilidade de falsos positivos, indicando métodos para sua validação.\n"
    "6. A análise deve incluir uma avaliação do impacto, detalhando as consequências de uma exploração bem-sucedida para o ambiente.\n"
    "7. Utilize terminologia técnica de PenTest e de segurança da informação.\n\n"
    
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

def save_to_database(timestamp, target, combined_output, analysis):
    """
    Insere um novo registro na tabela scan_results.
    - timestamp: string de data/hora
    - target: alvo (IP ou domínio)
    - combined_output: texto completo dos resultados das ferramentas
    - analysis: texto (JSON ou string) da análise retornada pela API
    """
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO scan_results (timestamp, target, combined_output, analysis)
           VALUES (?, ?, ?, ?)""",
        (timestamp, target, combined_output, analysis)
    )
    conn.commit()
    conn.close()

# ==================== FUNÇÕES AUXILIARES ====================

def log_message(msg):
    """Exibe uma mensagem no terminal com data/hora."""
    console.print(f"[bold][{datetime.now().isoformat()}][/bold] {msg}")

def is_ip(target):
    """Retorna True se o target for um endereço IP no formato xxx.xxx.xxx.xxx."""
    return re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target) is not None

def normalize_target(target):
    """
    Normaliza a entrada removendo os seguintes prefixos:
    "http://", "https://", "www.", "http" e "https".
    Retorna o domínio em formato 'puro'.
    """
    t = target.lower().strip()
    for prefix in ["http://", "https://", "www.", "http", "https"]:
        if t.startswith(prefix):
            t = t[len(prefix):]
    return t

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
        ("Intensive_Scan", ["nmap", "-T4", "-A", "-v", "--script", "vuln,exploit", normalized_target]),
        ("Comprehensive_Scan", ["nmap", "-sS", "-sU", "-T4", "-A", "-v", "-PE", "-PP", "-PA3389", "-PU40125", "-PY", "-g", "53", "--script", "default or (discovery and safe)", normalized_target]),
        ("Additional_Info", ["nmap", "-sV", "--script=asn-query,whois-ip,ip-geolocation-maxmind,default", normalized_target]),
        ("DDoS_Simulation", ["nmap", "-sU", "--script", "ntp-monlist,dns-recursion,snmp-sysdescr", "-p", "U:19,53,123,161", normalized_target]),
        ("Firewall_Check", ["nmap", "-sA", "-Pn", "--script", "firewall-bypass", normalized_target]),
        ("Full_Scan", ["nmap", "-p-", "-A", "-T4", normalized_target])
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
        "context": CONTEXT_MESSAGE_Protecao
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
    """
    # Salva em JSON
    data_to_save = {"timestamp": datetime.now().isoformat(), "result": result_data}
    results_list = []
    if os.path.exists(RESULTS_FILE):
        try:
            with open(RESULTS_FILE, "r", encoding="utf-8") as f:
                results_list = json.load(f)
        except Exception as e:
            console.print(f"[-] Erro ao ler resultados existentes: {e}", style="bold red")
    results_list.append(data_to_save)
    try:
        with open(RESULTS_FILE, "w", encoding="utf-8") as f:
            json.dump(results_list, f, indent=4, ensure_ascii=False)
        console.print(f"[+] Resultados salvos em '{RESULTS_FILE}'", style="bold green")
    except Exception as e:
        console.print(f"[-] Erro ao salvar resultados: {e}", style="bold red")
    
    # Salva no banco de dados
    try:
        # Monta dados para o DB
        timestamp = data_to_save["timestamp"]
        target = result_data.get("target", "N/A")
        combined_output = result_data.get("combined_output", "N/A")
        
        # Exemplo: usa a análise do primeiro scanner (Nmap) para salvar no DB
        deepseek_analysis = result_data.get("nmap_analysis")
        if isinstance(deepseek_analysis, dict):
            analysis_str = json.dumps(deepseek_analysis, ensure_ascii=False, indent=2)
        else:
            analysis_str = str(deepseek_analysis)
        
        save_to_database(timestamp, target, combined_output, analysis_str)
        console.print("[+] Resultados também gravados no banco de dados (scan_results.db).", style="bold green")
    except Exception as e:
        console.print(f"[-] Erro ao salvar no banco de dados: {e}", style="bold red")

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

# ==================== MENU PRINCIPAL ====================

def main_menu():
    # Inicializa/cria a tabela do banco de dados, caso ainda não exista.
    init_db()

    while True:
        console.print("\n==== Menu de PenTest ====", style="bold blue")
        console.print("1. Escanear um único IP/Domínio (executa Nmap, Nikto, Amass, theHarvester, sublist3r, dnsrecon e SSLyze de forma sequencial)")
        console.print("2. Escanear uma lista de IPs/Domínios (arquivo)")
        console.print("3. Descoberta de dispositivos na rede (ping scan)")
        console.print("4. Visualizar resultados salvos")
        console.print("5. Exportar resultados para HTML")
        console.print("6. Sair")
        console.print("7. Executar Masscan (menu exclusivo)")
        choice = input("Escolha uma opção: ").strip()
        
        if choice == "1":
            target = input("Digite o IP ou domínio para escanear: ").strip()
            # Aqui chamamos a função SEQUENCIAL que envia cada resultado individual à API
            scan_results = run_scans_sequential(target)
            # Exibe os resultados individuais (opcional, mas útil)
            display_sequential_results(scan_results)
            # Salva os resultados no JSON local e no banco de dados
            save_result(scan_results)
        
        elif choice == "2":
            file_path = input("Digite o caminho do arquivo com a lista de IPs/Domínios: ").strip()
            if not os.path.exists(file_path):
                console.print(f"[-] Arquivo '{file_path}' não encontrado.", style="bold red")
                continue
            
            with open(file_path, "r", encoding="utf-8") as f:
                targets = [line.strip() for line in f if line.strip()]
            
            for t in targets:
                console.print(f"\n=== Iniciando scans para: {t} ===", style="bold blue")
                scan_results = run_scans_sequential(t)
                
                # Exibe uma parte do resultado (ou use display_sequential_results, se preferir)
                console.print(scan_results["combined_output"][:500] + "... [primeiros 500 caracteres]", style="bold yellow")
                
                confirm = input(f"Deseja salvar os resultados do alvo {t}? (s/n): ").strip().lower()
                if confirm == 's':
                    save_result(scan_results)
                else:
                    console.print(f"[*] Resultados para {t} não salvos.", style="bold yellow")
        
        elif choice == "3":
            network_range = input("Digite o range da rede (ex.: 192.168.1.0/24): ").strip()
            ips = ping_scan(network_range)
            if ips:
                console.print("\n=== IPs Encontrados ===", style="bold blue")
                console.print("\n".join(ips))
        
        elif choice == "4":
            view_results()
        
        elif choice == "5":
            export_results_to_html()
        
        elif choice == "6":
            console.print("Encerrando o script.", style="bold blue")
            break
        
        elif choice == "7":
            run_masscan()
        
        else:
            console.print("Opção inválida. Tente novamente.", style="bold red")

if __name__ == "__main__":
    main_menu()