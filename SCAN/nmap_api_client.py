#!/usr/bin/env python3
"""
Script de PenTest que consome a API do DeepSeek via Ollama.

Funcionalidades:
    - Escaneamento de um único IP/Domínio utilizando Nmap, Nikto, Amass, theHarvester, sublist3r e dnsrecon.
    - Todos os scanners (exceto masscan) utilizam a mesma entrada (alvo) e são executados juntos.
    - Menu separado para executar o masscan, que solicita os parâmetros necessários.
    - Integração dos resultados de todas as ferramentas em uma única saída, enviada para a API do DeepSeek.
    - Visualização e exportação dos resultados (JSON e HTML).
    - Salvamento automático dos IPs encontrados em network_devices.txt.
    - **Gravação dos resultados no banco de dados SQLite (scan_results.db).**

Requisitos:
    - Python 3.7+
    - Ferramentas instaladas e acessíveis via linha de comando: Nmap, Nikto, Amass, theHarvester, sublist3r, dnsrecon e masscan.
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
    "Os resultados foram coletados por diversas ferramentas (Nmap, Nikto, Amass, theHarvester, sublist3r e dnsrecon) e podem conter dados sobre "
    "port scanning, detecção de serviços, enumeração de subdomínios, vulnerabilidades conhecidas e informações DNS. \n\n"
    
    "Instruções:\n"
    "1. Analise detalhadamente os resultados apresentados, organizando-os por ferramenta e destacando informações críticas.\n"
    "2. Identifique e classifique as vulnerabilidades e riscos encontrados, determinando a gravidade de cada item (ex.: baixa, média, alta) e, sempre que possível, referenciando CVEs ou boas práticas de segurança.\n"
    "3. Forneça recomendações técnicas específicas para a mitigação ou correção de cada vulnerabilidade, incluindo sugestões de controles e medidas corretivas.\n"
    "4. Considere possíveis falsos positivos e indique sugestões para sua validação, se aplicável.\n"
    "5. A análise deve conter uma avaliação de impacto, detalhando como as vulnerabilidades podem ser exploradas e afetar o ambiente.\n"
    "6. Utilize terminologia técnica de PenTest e de segurança da informação, e apresente toda a análise em Português do Brasil (PT-BR). Resultados sempre em Português do Brasil (PT-BR). \n\n"
    
    "Você está recebendo dados levantados pelos softwares: Nmap, Nikto, Amass, theHarvester, sublist3r e dnsrecon."
)

CONTEXT_MESSAGE_Exploracao = (
    "Objetivo: Fornecer uma análise técnica, aprofundada e orientada para a exploração das vulnerabilidades detectadas pelo SCAN, "
    "identificando, classificando e interpretando os riscos e falhas de segurança encontrados no alvo, e sugerindo vetores de exploração e proof-of-concept quando aplicável. "
    "Os dados foram coletados por diversas ferramentas (Nmap, Nikto, Amass, theHarvester, sublist3r e dnsrecon) e podem incluir informações sobre "
    "port scanning, detecção de serviços, enumeração de subdomínios, vulnerabilidades conhecidas, banners e informações DNS.\n\n"
    
    "Instruções:\n"
    "1. Analise detalhadamente os resultados apresentados, organizando-os por ferramenta e destacando as informações críticas para a exploração das falhas.\n"
    "2. Identifique e classifique as vulnerabilidades e riscos encontrados, determinando a gravidade de cada item (ex.: baixa, média, alta) e, sempre que possível, referenciando CVEs e evidências técnicas.\n"
    "3. Para cada vulnerabilidade, forneça sugestões de vetores de exploração, descrevendo como um atacante poderia utilizar a falha para comprometer o alvo, e, se possível, inclua ideias de proof-of-concept.\n"
    "4. Apresente recomendações técnicas específicas para a mitigação ou correção das vulnerabilidades, sugerindo controles e medidas corretivas adequadas.\n"
    "5. Considere a possibilidade de falsos positivos, indicando métodos para sua validação.\n"
    "6. A análise deve incluir uma avaliação do impacto, detalhando as consequências de uma exploração bem-sucedida para o ambiente.\n"
    "7. Utilize terminologia técnica de PenTest e de segurança da informação, e apresente toda a análise em Português do Brasil (PT-BR).\n\n"
    
    "Você está recebendo dados levantados pelos softwares: Nmap, Nikto, Amass, theHarvester, sublist3r e dnsrecon."
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

def send_to_deepseek(scan_data):
    """
    Envia os dados combinados para a API do DeepSeek com o contexto de Proteção.
    Retorna a resposta da API como dicionário.
    
    Melhoria solicitada:
    - Após o envio, exibe o conteúdo (scan_data) que foi de fato enviado para a API.
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
            
            # *** Exibir na tela o conteúdo que foi enviado para a API ***
            console.print("\n=== Conteúdo Enviado para a API ===", style="bold cyan")
            console.print(scan_data)  # Exibe tudo que foi enviado
            
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
        # Montar dados para o DB
        timestamp = data_to_save["timestamp"]
        target = result_data.get("target", "N/A")
        combined_output = result_data.get("combined_output", "N/A")
        
        # A análise pode vir como dicionário. Convertemos para JSON, se for o caso.
        deepseek_analysis = result_data.get("deepseek_analysis")
        if isinstance(deepseek_analysis, dict):
            analysis_str = json.dumps(deepseek_analysis, ensure_ascii=False, indent=2)
        else:
            analysis_str = str(deepseek_analysis)  # caso seja None ou string
        
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

# ==================== FUNÇÃO PRINCIPAL PARA RODAR TODOS OS SCANS ====================

def run_all_scans(target):
    """
    Executa todas as ferramentas (Nmap, Nikto, Amass, theHarvester, sublist3r e dnsrecon) para o alvo.
    Retorna um dicionário com as saídas individuais e uma chave 'combined_output' com todos os resultados combinados.
    """
    # 1) Nmap principal
    nmap_output = run_nmap_scan(target)
    
    # 2) Caso seja um domínio, resolver IP e executar Nmap adicional
    ip_address = get_server_ip(target)
    if ip_address and ip_address != target:
        nmap_ip_output = run_nmap_scan(ip_address)
    else:
        nmap_ip_output = "Scan adicional não realizado (alvo já é IP ou resolução falhou)."
    
    # 3) Nikto
    nikto_output = run_nikto_scan(target)
    
    # 4) Amass (apenas se não for IP)
    amass_output = run_amass_enum(target) if not is_ip(target) else "Amass não executado para IP."
    
    # 5) theHarvester
    theharvester_output = run_theharvester(target)
    
    # 6) Sublist3r
    sublist3r_output = run_sublist3r(target)
    
    # 7) dnsrecon
    dnsrecon_output = run_dnsrecon(target)
    
    # Combina tudo em um único texto
    combined_output = (
        f"=== RESULTADOS NMAP para {target} ===\n{nmap_output}\n"
        f"=== RESULTADOS NMAP (IP resolvido: {ip_address if ip_address else 'N/A'}) ===\n{nmap_ip_output}\n"
        f"=== RESULTADOS NIKTO para {target} ===\n{nikto_output}\n"
        f"=== RESULTADOS AMASS para {target} ===\n{amass_output}\n"
        f"=== RESULTADOS theHarvester para {target} ===\n{theharvester_output}\n"
        f"=== RESULTADOS sublist3r para {target} ===\n{sublist3r_output}\n"
        f"=== RESULTADOS dnsrecon para {target} ===\n{dnsrecon_output}\n"
    )
    
    return {
        "target": target,
        "nmap_output": nmap_output,
        "nmap_ip_output": nmap_ip_output,
        "nikto_output": nikto_output,
        "amass_output": amass_output,
        "theharvester_output": theharvester_output,
        "sublist3r_output": sublist3r_output,
        "dnsrecon_output": dnsrecon_output,
        "combined_output": combined_output
    }

# ==================== MENU PRINCIPAL ====================

def main_menu():
    # Inicializa/cria a tabela do banco de dados, caso ainda não exista.
    init_db()

    while True:
        console.print("\n==== Menu de PenTest ====", style="bold blue")
        console.print("1. Escanear um único IP/Domínio (executa Nmap, Nikto, Amass, theHarvester, sublist3r e dnsrecon)")
        console.print("2. Escanear uma lista de IPs/Domínios (arquivo)")
        console.print("3. Descoberta de dispositivos na rede (ping scan)")
        console.print("4. Visualizar resultados salvos")
        console.print("5. Exportar resultados para HTML")
        console.print("6. Sair")
        console.print("7. Executar Masscan (menu exclusivo)")
        choice = input("Escolha uma opção: ").strip()
        
        if choice == "1":
            target = input("Digite o IP ou domínio para escanear: ").strip()
            # Executa todos os scans para o alvo
            scan_results = run_all_scans(target)
            
            # Envia resultados combinados para API
            analysis = send_to_deepseek(scan_results["combined_output"])
            if analysis:
                console.print("\n=== Análise do DeepSeek (resultados combinados) ===", style="bold blue")
                console.print(analysis)
            else:
                console.print("[-] A análise combinada não foi obtida.", style="bold red")
            
            # Salva no JSON local e no banco de dados
            to_save = scan_results.copy()
            to_save["deepseek_analysis"] = analysis
            save_result(to_save)
        
        elif choice == "2":
            file_path = input("Digite o caminho do arquivo com a lista de IPs/Domínios: ").strip()
            if not os.path.exists(file_path):
                console.print(f"[-] Arquivo '{file_path}' não encontrado.", style="bold red")
                continue
            
            with open(file_path, "r", encoding="utf-8") as f:
                targets = [line.strip() for line in f if line.strip()]
            
            for t in targets:
                console.print(f"\n=== Iniciando scans para: {t} ===", style="bold blue")
                scan_results = run_all_scans(t)
                
                # Mostra parcialmente no console (opcional)
                console.print(scan_results["combined_output"][:500] + "... [exibindo apenas primeiros 500 caracteres]", style="bold yellow")
                
                confirm = input(f"Deseja enviar o resultado do alvo {t} para análise do DeepSeek? (s/n): ").strip().lower()
                if confirm == 's':
                    analysis = send_to_deepseek(scan_results["combined_output"])
                    if analysis:
                        console.print("\n=== Análise do DeepSeek ===", style="bold blue")
                        console.print(analysis)
                        # Salva no JSON e DB
                        to_save = scan_results.copy()
                        to_save["deepseek_analysis"] = analysis
                        save_result(to_save)
                    else:
                        console.print(f"[-] A análise não foi obtida para {t}.", style="bold red")
                else:
                    console.print(f"[*] Resultado para {t} não enviado para análise.", style="bold yellow")
                    # Mesmo se não enviar para a API, podemos querer salvar localmente ou não.
                    # Caso queira apenas salvar local sem análise:
                    # save_result(scan_results)
        
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