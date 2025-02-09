#!/usr/bin/env python3
"""
API Server para integração com DeepSeek via Ollama - Versão Melhorada

Autor: Thalles Canela
Data: 2025-02-02 (Atualizado: 2025-02-08)
"""

import os
import sys
import json
import logging
import sqlite3
import subprocess
import re
import zlib
from datetime import datetime
from flask import Flask, request, jsonify
import requests
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console

# ==================== CONFIGURAÇÕES ====================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FOLDER = os.path.join(BASE_DIR, "logs")
DB_FOLDER = os.path.join(BASE_DIR, "db")
DB_FILE = os.path.join(DB_FOLDER, "api_logs.db")
LOG_FILE = os.path.join(LOG_FOLDER, "api_server.log")
MAX_WORKERS = 4
API_PORT = 5000
MAX_CONTENT_LENGTH = 1024 * 1024 * 1024  # 1GB
API_KEY = os.getenv("PENTEST_API_KEY", "sk_prod_1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
OLLAMA_TIMEOUT = 7200  # 2 horas em segundos

# Configuração de pastas
os.makedirs(LOG_FOLDER, exist_ok=True)
os.makedirs(DB_FOLDER, exist_ok=True)

# Configuração do logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.config['JSON_AS_ASCII'] = False

# Executor para tarefas assíncronas
executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

# Inicializa o console do rich
console = Console()

# ==================== BANCO DE DADOS ====================
def init_db():
    """Inicializa o banco de dados SQLite"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                client_ip TEXT,
                status TEXT,
                processing_time REAL,
                data_size INTEGER
            )
        ''')
        conn.commit()
    except Exception as e:
        logging.error(f"Erro inicializando banco de dados: {str(e)}")
    finally:
        conn.close()

def log_request(client_ip, status, processing_time, data_size):
    """Registra a requisição no banco de dados"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO requests 
            (timestamp, client_ip, status, processing_time, data_size)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            datetime.utcnow().isoformat(),
            client_ip,
            status,
            processing_time,
            data_size
        ))
        conn.commit()
    except Exception as e:
        logging.error(f"Erro registrando requisição: {str(e)}")
    finally:
        conn.close()

# ==================== FUNÇÕES DO DEEPSEEK ====================
def test_ollama():
    """Verifica a disponibilidade do Ollama e do modelo"""
    try:
        # Teste de versão do Ollama
        subprocess.run(
            ["ollama", "--version"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10
        )
        
        # Teste de interação com o modelo
        test_result = subprocess.run(
            ["ollama", "run", "deepseek-r1:14b", "Teste de conexão"],
            capture_output=True,
            text=True,
            timeout=30
        )
        return "error" not in test_result.stderr.lower()
    except Exception as e:
        logging.error(f"Falha no teste do Ollama: {str(e)}")
        return False

def clean_analysis_result(text):
    """Limpa a saída do modelo"""
    cleaned = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)
    cleaned = re.sub(r'\n\s*\n', '\n\n', cleaned)
    return cleaned.strip()

def process_analysis(scan_data, context):
    """Executa a análise com o DeepSeek"""
    start_time = datetime.now()
    input_message = f"{context}\n\nDados do Scan:\n{scan_data}"
    
    try:
        console.print("[*] Iniciando análise com DeepSeek...", style="bold yellow")
        process = subprocess.run(
            ["ollama", "run", "deepseek-r1:14b"],
            input=input_message,
            capture_output=True,
            text=True,
            timeout=OLLAMA_TIMEOUT
        )
        
        if process.returncode != 0:
            raise subprocess.CalledProcessError(
                process.returncode,
                "ollama run deepseek-r1:14b",
                output=process.stdout,
                stderr=process.stderr
            )
            
        output = clean_analysis_result(process.stdout)
        processing_time = (datetime.now() - start_time).total_seconds()
        
        console.print(f"[+] Análise concluída em {processing_time:.2f}s", style="bold green")
        return output
    
    except subprocess.TimeoutExpired:
        console.print("[-] Timeout na análise com DeepSeek", style="bold red")
        return "Erro: Tempo excedido na análise"
    except Exception as e:
        console.print(f"[-] Erro no processamento: {str(e)}", style="bold red")
        return f"Erro na análise: {str(e)}"

# ==================== ENDPOINTS DA API ====================
@app.route("/analyze", methods=["POST"])
def analyze():
    """Endpoint principal para análise"""
    start_time = datetime.now()
    client_ip = request.remote_addr
    data_size = len(request.data)
    status = "failed"
    
    # Verificação de autenticação
    if request.headers.get('X-API-Key') != API_KEY:
        console.print(f"[-] Tentativa de acesso não autorizada de {client_ip}", style="bold red")
        return jsonify({"error": "Não autorizado"}), 401
    
    try:
        console.print(f"[+] Requisição recebida de {client_ip}", style="bold green")
        
        # Verificar encoding e descomprimir
        if request.headers.get('Content-Encoding') == 'zlib':
            compressed_data = request.data
            json_data = zlib.decompress(compressed_data).decode('utf-8')
        else:
            json_data = request.data.decode('utf-8')  # Fallback para dados não comprimidos

        data = json.loads(json_data)
        
        # Validação dos dados
        if 'scan_data' not in data or 'context' not in data:
            raise ValueError("Campos obrigatórios ausentes")
            
        # Processamento principal
        console.print("[*] Processando análise...", style="bold yellow")
        result = process_analysis(data['scan_data'], data['context'])
        processing_time = (datetime.now() - start_time).total_seconds()
        status = "success"
        
        # Resposta síncrona
        if 'callback_url' not in data:
            log_request(client_ip, status, processing_time, data_size)
            console.print("[+] Análise concluída e enviada ao cliente.", style="bold green")
            return jsonify({
                "analysis": result,
                "processing_time": processing_time
            }), 200
        
        # Processamento assíncrono
        def callback_task():
            try:
                console.print(f"[*] Enviando resultados para {data['callback_url']}...", style="bold yellow")
                requests.post(
                    data['callback_url'],
                    json={"analysis": result},
                    timeout=30
                )
                console.print("[+] Resultados enviados com sucesso.", style="bold green")
            except Exception as e:
                console.print(f"[-] Erro no callback: {str(e)}", style="bold red")
        
        executor.submit(callback_task)
        log_request(client_ip, "async_started", processing_time, data_size)
        console.print("[*] Análise em andamento (modo assíncrono).", style="bold yellow")
        return jsonify({
            "message": "Análise em andamento",
            "callback_url": data['callback_url']
        }), 202
        
    except zlib.error:
        error_msg = "Erro na descompressão dos dados"
    except json.JSONDecodeError:
        error_msg = "Formato JSON inválido"
    except ValueError as e:
        error_msg = str(e)
    except Exception as e:
        error_msg = f"Erro interno: {str(e)}"
    
    processing_time = (datetime.now() - start_time).total_seconds()
    log_request(client_ip, status, processing_time, data_size)
    console.print(f"[-] Erro na requisição: {error_msg}", style="bold red")
    return jsonify({"error": error_msg}), 400

@app.route("/health", methods=["GET"])
def health_check():
    """Endpoint de verificação de saúde"""
    return jsonify({
        "status": "online",
        "timestamp": datetime.utcnow().isoformat(),
        "ollama_available": test_ollama()
    })

# ==================== INICIALIZAÇÃO ====================
if __name__ == "__main__":
    init_db()
    
    if not test_ollama():
        console.print("[-] Ollama/deepseek-r1:14b não disponível!", style="bold red")
        sys.exit(1)
        
    try:
        console.print(f"[+] Iniciando servidor na porta {API_PORT}", style="bold green")
        app.run(
            host="0.0.0.0",
            port=API_PORT,
            threaded=True
        )
    except Exception as e:
        console.print(f"[-] Falha ao iniciar servidor: {str(e)}", style="bold red")
        sys.exit(1)