#!/usr/bin/env python3
"""
API Server para integração com DeepSeek via Ollama - Versão Melhorada e Reestruturada

Modo de execução local (para desenvolvimento):
    python api_deepseek.py

Modo de execução em produção (exemplo):
    gunicorn --bind 0.0.0.0:5000 --workers 4 "api_deepseek:create_app()"

Autor: Thalles Canela
Data: 2025-02-02 (Última atualização: 2025-02-15)
"""

import os
import sys
import json
import logging
import sqlite3
import subprocess
import re
import zlib
import requests

from datetime import datetime
from flask import Flask, request, jsonify
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console

# ---------------------- Configuração do Modelo ----------------------
# Variável global para selecionar o modelo a ser utilizado.
# O valor padrão é deepseek-r1:32b e poderá ser alterado em tempo de execução.
SELECTED_MODEL = "deepseek-r1:32b"

# ---------------------- Opções de melhoria ----------------------
try:
    from pydantic import BaseModel, ValidationError
    USE_PYDANTIC = True
except ImportError:
    USE_PYDANTIC = False

try:
    from flask_compress import Compress
    COMPRESS_AVAILABLE = True
except ImportError:
    COMPRESS_AVAILABLE = False

# ---------------------- CONFIGURAÇÕES ----------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FOLDER = os.path.join(BASE_DIR, "logs")
DB_FOLDER = os.path.join(BASE_DIR, "db")
DB_FILE = os.path.join(DB_FOLDER, "api_logs.db")
LOG_FILE = os.path.join(LOG_FOLDER, "api_server.log")

os.makedirs(LOG_FOLDER, exist_ok=True)
os.makedirs(DB_FOLDER, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

API_PORT = int(os.getenv("API_PORT", 5000))
API_KEY = os.getenv("PENTEST_API_KEY", "sk_prod_1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
MAX_CONTENT_LENGTH = 1024 * 1024 * 1024  # 1GB

OLLAMA_TIMEOUT = 7200  # 2 horas em segundos

MAX_WORKERS = 4
executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

console = Console()

# ---------------------- BANCO DE DADOS ----------------------
def init_db():
    """
    Inicializa o banco de dados SQLite:
      - Cria a tabela 'requests' (se não existir) para armazenar logs de requisições.
    """
    try:
        with sqlite3.connect(DB_FILE) as conn:
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
    except Exception:
        logging.exception("Erro inicializando banco de dados")

def log_request(client_ip, status, processing_time, data_size):
    """
    Registra no SQLite cada requisição feita ao endpoint /analyze.
    Guarda dados como IP do cliente, status, tempo de processamento e tamanho da requisição.
    """
    try:
        with sqlite3.connect(DB_FILE) as conn:
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
    except Exception:
        logging.exception("Erro registrando requisição")

# ---------------------- FUNÇÕES DE ANÁLISE/OLLAMA ----------------------
def test_ollama():
    """
    Verifica a disponibilidade do Ollama e do modelo selecionado.
    - Checa se 'ollama --version' executa com sucesso.
    - Tenta rodar o modelo escolhido com o prompt 'Teste de conexão'.
    """
    try:
        subprocess.run(
            ["ollama", "--version"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10
        )
        test_result = subprocess.run(
            ["ollama", "run", SELECTED_MODEL, "Teste de conexão"],
            capture_output=True,
            text=True,
            timeout=30
        )
        return "error" not in test_result.stderr.lower()
    except Exception as e:
        logging.error(f"Falha no teste do Ollama: {str(e)}")
        return False

def clean_analysis_result(text):
    """
    Garante que a saída do modelo esteja limpa e formatada para o usuário.
    Aplica limpeza extra para o qwen2.5:14b removendo tags, metadados e tokens de controle.
    """
    # Remove conteúdos indesejados, como tags <think>...</think>
    cleaned = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)
    # Remove quebras de linha múltiplas, garantindo espaçamento adequado entre tópicos
    cleaned = re.sub(r'\n\s*\n', '\n\n', cleaned)
    if SELECTED_MODEL == "qwen2.5:14b":
        # Limpeza extra para qwen2.5:14b: remoção de tags HTML e tokens entre colchetes
        cleaned = re.sub(r'<[^>]+>', '', cleaned)
        cleaned = re.sub(r'\[.*?\]', '', cleaned)
    return cleaned.strip()

analysis_cache = {}  # Cache para evitar reprocessamento de análises idênticas

def process_analysis(scan_data, context):
    """
    Executa a análise utilizando o modelo selecionado via Ollama.
    - Gera uma chave CRC32 para cache.
    - Executa o subprocesso "ollama run" e trata a saída.
    - Retorna o resultado "limpo" e formatado.
    """
    start_time = datetime.now()
    input_message = f"{context}\n\nDados do Scan:\n{scan_data}"
    cache_key = zlib.crc32(input_message.encode('utf-8'))
    
    if cache_key in analysis_cache:
        console.print("[CACHE] Retornando resultado em cache.", style="bold cyan")
        return analysis_cache[cache_key]

    try:
        console.print(f"[*] Iniciando análise com {SELECTED_MODEL}...", style="bold yellow")
        process = subprocess.run(
            ["ollama", "run", SELECTED_MODEL],
            input=input_message,
            capture_output=True,
            text=True,
            timeout=OLLAMA_TIMEOUT
        )
        if process.returncode != 0:
            raise subprocess.CalledProcessError(
                process.returncode,
                f"ollama run {SELECTED_MODEL}",
                output=process.stdout,
                stderr=process.stderr
            )
        output = clean_analysis_result(process.stdout)
        processing_time = (datetime.now() - start_time).total_seconds()
        console.print(f"[+] Análise concluída em {processing_time:.2f}s", style="bold green")
        analysis_cache[cache_key] = output
        return output

    except subprocess.TimeoutExpired:
        console.print("[-] Timeout na análise com o modelo selecionado", style="bold red")
        return "Erro: Tempo excedido na análise"
    except Exception as e:
        console.print(f"[-] Erro no processamento: {str(e)}", style="bold red")
        logging.exception("Erro no processamento da análise")
        return f"Erro na análise: {str(e)}"

# ---------------------- CRIAÇÃO DO FLASK ----------------------
def create_flask_app() -> Flask:
    """
    Cria e retorna a instância Flask.
    Configura compressão (se disponível) e outras opções.
    """
    flask_app = Flask(__name__)
    flask_app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
    flask_app.config['JSON_AS_ASCII'] = False
    if COMPRESS_AVAILABLE:
        Compress(flask_app)
    return flask_app

app = create_flask_app()

# ---------------------- MODELO DE VALIDAÇÃO (opcional) ----------------------
if USE_PYDANTIC:
    class AnalyzeRequest(BaseModel):
        scan_data: str
        context: str
        callback_url: str | None = None

# ---------------------- ROTAS ----------------------
@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Endpoint principal para análise (POST /analyze).
    Fluxo:
      - Verifica a API Key no cabeçalho.
      - Descomprime os dados se necessário.
      - Valida os campos obrigatórios (usando Pydantic, se disponível).
      - Processa a análise via modelo selecionado.
      - Retorna o resultado de forma síncrona ou assíncrona (se callback_url for fornecido).
    """
    start_time = datetime.now()
    client_ip = request.remote_addr
    data_size = len(request.data)
    status = "failed"

    if request.headers.get('X-API-Key') != API_KEY:
        console.print(f"[-] Tentativa de acesso não autorizado de {client_ip}", style="bold red")
        return jsonify({"error": "Não autorizado"}), 401

    try:
        console.print(f"[+] Requisição recebida de {client_ip}", style="bold green")
        if request.headers.get('Content-Encoding') == 'zlib':
            compressed_data = request.data
            json_data = zlib.decompress(compressed_data).decode('utf-8')
        else:
            json_data = request.data.decode('utf-8')

        if USE_PYDANTIC:
            payload = AnalyzeRequest(**json.loads(json_data))
            scan_data = payload.scan_data
            context = payload.context
            callback_url = payload.callback_url
        else:
            data = json.loads(json_data)
            if 'scan_data' not in data or 'context' not in data:
                raise ValueError("Campos obrigatórios ausentes (scan_data, context)")
            scan_data = data['scan_data']
            context = data['context']
            callback_url = data.get('callback_url')

        console.print("[*] Processando análise...", style="bold yellow")
        result = process_analysis(scan_data, context)
        processing_time = (datetime.now() - start_time).total_seconds()
        status = "success"

        if not callback_url:
            log_request(client_ip, status, processing_time, data_size)
            console.print("[+] Análise concluída e enviada ao cliente.", style="bold green")
            return jsonify({
                "analysis": result,
                "processing_time": processing_time
            }), 200

        # Processamento assíncrono com callback
        def callback_task():
            try:
                console.print(f"[*] Enviando resultados para {callback_url}...", style="bold yellow")
                requests.post(
                    callback_url,
                    json={"analysis": result},
                    timeout=30
                )
                console.print("[+] Resultados enviados com sucesso.", style="bold green")
            except Exception as e:
                logging.exception("Erro no callback")
                console.print(f"[-] Erro no callback: {str(e)}", style="bold red")

        executor.submit(callback_task)
        log_request(client_ip, "async_started", processing_time, data_size)
        console.print("[*] Análise em andamento (modo assíncrono).", style="bold yellow")
        return jsonify({
            "message": "Análise em andamento",
            "callback_url": callback_url
        }), 202

    except zlib.error:
        error_msg = "Erro na descompressão dos dados"
    except json.JSONDecodeError:
        error_msg = "Formato JSON inválido"
    except Exception as e:
        logging.exception("Erro geral no endpoint /analyze")
        error_msg = f"Erro interno: {str(e)}"

    processing_time = (datetime.now() - start_time).total_seconds()
    log_request(client_ip, status, processing_time, data_size)
    console.print(f"[-] Erro na requisição: {error_msg}", style="bold red")
    return jsonify({"error": error_msg}), 400

@app.route("/health", methods=["GET"])
def health_check():
    """
    Endpoint de verificação de saúde (GET /health).
    Retorna status, timestamp UTC e disponibilidade do Ollama.
    """
    return jsonify({
        "status": "online",
        "timestamp": datetime.utcnow().isoformat(),
        "ollama_available": test_ollama()
    })

# ---------------------- HANDLERS GLOBAIS DE ERROS ----------------------
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Rota não encontrada"}), 404

@app.errorhandler(400)
def bad_request(e):
    logging.error("Bad Request: " + str(e))
    return jsonify({"error": "Requisição malformada", "details": str(e)}), 400

@app.errorhandler(500)
def internal_error(e):
    logging.exception("Erro interno (500)")
    return jsonify({"error": "Erro interno do servidor"}), 500

# ---------------------- CRIAÇÃO FINAL DA APP ----------------------
def create_app():
    """
    Função de fábrica para uso com Gunicorn.
    Inicializa o banco de dados e verifica a disponibilidade do modelo via Ollama.
    """
    init_db()
    if not test_ollama():
        console.print(f"[-] Ollama/{SELECTED_MODEL} não disponível!", style="bold red")
    return app

# ---------------------- ENTRY POINT (DESENVOLVIMENTO) ----------------------
if __name__ == "__main__":
    print("Escolha o modelo para análise (por fabricante):")
    print("1) qwq:latest")
    print("2) qwen2.5:32b")
    print("3) qwen2.5:14b")
    print("4) deepseek-r1:32b")
    print("5) deepseek-r1:14b")
    choice = input("Digite uma opção (1 a 5): ").strip()

    if choice == "1":
        SELECTED_MODEL = "qwq:latest"
    elif choice == "2":
        SELECTED_MODEL = "qwen2.5:32b"
    elif choice == "3":
        SELECTED_MODEL = "qwen2.5:14b"
    elif choice == "4":
        SELECTED_MODEL = "deepseek-r1:32b"
    elif choice == "5":
        SELECTED_MODEL = "deepseek-r1:14b"
    else:
        SELECTED_MODEL = "deepseek-r1:32b"
        console.print("Opção inválida, usando deepseek-r1:32b como padrão", style="bold red")

    console.print(f"Modelo selecionado: {SELECTED_MODEL}", style="bold cyan")

    local_app = create_app()
    try:
        console.print(f"[+] Iniciando servidor na porta {API_PORT}", style="bold green")
        local_app.run(host="0.0.0.0", port=API_PORT, threaded=True)
    except Exception as e:
        console.print(f"[-] Falha ao iniciar servidor: {str(e)}", style="bold red")
        sys.exit(1)