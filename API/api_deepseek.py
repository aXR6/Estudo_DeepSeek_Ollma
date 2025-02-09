#!/usr/bin/env python3
"""
API Server para integração com DeepSeek via Ollama - Versão Melhorada e Reestruturada

Em produção: gunicorn --bind 0.0.0.0:5000 --workers 4 app:app
Onde app:app se refere ao arquivo app.py (sem a extensão) e à variável app ou application instanciada.

Autor: Thalles Canela
Atualizado com melhorias (exemplo por ChatGPT)
Data: 2025-02-02 (Última atualização: 2025-02-09)
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

# ---------------------- Opções de melhoria ----------------------
# 1) Validação declarativa com Pydantic (opcional).
#    pip install pydantic
try:
    from pydantic import BaseModel, ValidationError
    USE_PYDANTIC = True
except ImportError:
    USE_PYDANTIC = False

# 2) Compactar respostas se o cliente suportar.
#    pip install flask-compress
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

# Configuração do logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

# Configurações de ambiente
API_PORT = int(os.getenv("API_PORT", 5000))
API_KEY = os.getenv("PENTEST_API_KEY", "sk_prod_1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
MAX_CONTENT_LENGTH = 1024 * 1024 * 1024  # 1GB

# Configurações de análise/Ollama
OLLAMA_TIMEOUT = 7200  # 2 horas em segundos

# Executor para tarefas assíncronas
MAX_WORKERS = 4
executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

# Inicializa o console do rich
console = Console()

# Criação do Flask
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.config['JSON_AS_ASCII'] = False

# Se disponível, comprime respostas
if COMPRESS_AVAILABLE:
    Compress(app)

# ---------------------- MODELO DE VALIDAÇÃO (opcional) ----------------------
# Se Pydantic estiver instalado, podemos validar as requisições de forma declarativa.
if USE_PYDANTIC:
    class AnalyzeRequest(BaseModel):
        scan_data: str
        context: str
        callback_url: str | None = None


# ---------------------- BANCO DE DADOS ----------------------
def init_db():
    """Inicializa o banco de dados SQLite."""
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
    except Exception as e:
        logging.exception("Erro inicializando banco de dados")


def log_request(client_ip, status, processing_time, data_size):
    """Registra a requisição no banco de dados."""
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
    except Exception as e:
        logging.exception("Erro registrando requisição")


# ---------------------- FUNÇÕES DE ANÁLISE/OLLAMA ----------------------
def test_ollama():
    """Verifica a disponibilidade do Ollama e do modelo."""
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
    """Remove tags e espaçamentos desnecessários da saída do modelo."""
    cleaned = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)
    cleaned = re.sub(r'\n\s*\n', '\n\n', cleaned)
    return cleaned.strip()


# ---------------------- CACHE SIMPLES ----------------------
# Exemplo simples de cache para evitar refazer análise idêntica.
# Para produção, considere um Redis ou outra solução robusta.
analysis_cache = {}  # dict: {crc_key: output_str}


def process_analysis(scan_data, context):
    """Executa a análise com o DeepSeek."""
    start_time = datetime.now()
    input_message = f"{context}\n\nDados do Scan:\n{scan_data}"

    # Gera uma chave única para cache usando CRC32
    cache_key = zlib.crc32(input_message.encode('utf-8'))
    if cache_key in analysis_cache:
        console.print("[CACHE] Retornando resultado em cache.", style="bold cyan")
        return analysis_cache[cache_key]

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

        # Armazena no cache para chamadas futuras
        analysis_cache[cache_key] = output
        return output
    
    except subprocess.TimeoutExpired:
        console.print("[-] Timeout na análise com DeepSeek", style="bold red")
        return "Erro: Tempo excedido na análise"
    except Exception as e:
        console.print(f"[-] Erro no processamento: {str(e)}", style="bold red")
        logging.exception("Erro no processamento da análise")
        return f"Erro na análise: {str(e)}"


# ---------------------- ENDPOINTS ----------------------
@app.route("/analyze", methods=["POST"])
def analyze():
    """Endpoint principal para análise."""
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

        # Verificar encoding e descomprimir se necessário
        if request.headers.get('Content-Encoding') == 'zlib':
            compressed_data = request.data
            json_data = zlib.decompress(compressed_data).decode('utf-8')
        else:
            json_data = request.data.decode('utf-8')

        # (Opcional) Usar Pydantic para validar entrada
        if USE_PYDANTIC:
            payload = AnalyzeRequest(**json.loads(json_data))
            scan_data = payload.scan_data
            context = payload.context
            callback_url = payload.callback_url
        else:
            # Caso Pydantic não esteja instalado, valida manualmente
            data = json.loads(json_data)
            if 'scan_data' not in data or 'context' not in data:
                raise ValueError("Campos obrigatórios ausentes (scan_data, context)")
            scan_data = data['scan_data']
            context = data['context']
            callback_url = data.get('callback_url')

        # Processamento principal
        console.print("[*] Processando análise...", style="bold yellow")
        result = process_analysis(scan_data, context)
        processing_time = (datetime.now() - start_time).total_seconds()
        status = "success"

        # Resposta síncrona (sem callback)
        if not callback_url:
            log_request(client_ip, status, processing_time, data_size)
            console.print("[+] Análise concluída e enviada ao cliente.", style="bold green")
            return jsonify({
                "analysis": result,
                "processing_time": processing_time
            }), 200

        # Processamento assíncrono (com callback)
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
    except ValidationError as e:
        # Se Pydantic falhar
        error_msg = str(e)
    except ValueError as e:
        error_msg = str(e)
    except Exception as e:
        logging.exception("Erro geral no endpoint /analyze")
        error_msg = f"Erro interno: {str(e)}"

    processing_time = (datetime.now() - start_time).total_seconds()
    log_request(client_ip, status, processing_time, data_size)
    console.print(f"[-] Erro na requisição: {error_msg}", style="bold red")
    return jsonify({"error": error_msg}), 400


@app.route("/health", methods=["GET"])
def health_check():
    """Endpoint de verificação de saúde."""
    return jsonify({
        "status": "online",
        "timestamp": datetime.utcnow().isoformat(),
        "ollama_available": test_ollama()
    })


# ---------------------- HANDLERS GLOBAIS DE ERROS (Opcional) ----------------------
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Rota não encontrada"}), 404

@app.errorhandler(500)
def internal_error(e):
    logging.exception("Erro interno (500)")
    return jsonify({"error": "Erro interno do servidor"}), 500


# ---------------------- INICIALIZAÇÃO ----------------------
def create_app():
    """Função que cria e configura a aplicação Flask."""
    init_db()  # Inicializa/migra schema do banco

    # Teste de disponibilidade do Ollama
    if not test_ollama():
        console.print("[-] Ollama/deepseek-r1:14b não disponível!", style="bold red")
    return app


# ---------------------- ENTRY POINT ----------------------
if __name__ == "__main__":
    application = create_app()

    # Aviso: Em produção, use Gunicorn ou outro WSGI server:
    # gunicorn --bind 0.0.0.0:5000 app:app
    # (onde "app.py" é este arquivo e "app" é a instância do Flask)
    try:
        console.print(f"[+] Iniciando servidor na porta {API_PORT}", style="bold green")
        application.run(host="0.0.0.0", port=API_PORT, threaded=True)
    except Exception as e:
        console.print(f"[-] Falha ao iniciar servidor: {str(e)}", style="bold red")
        sys.exit(1)