#!/usr/bin/env python3
"""
API Server para integração com DeepSeek via Ollama - Versão Melhorada e Reestruturada

Modo de execução local (para desenvolvimento):
    python api_deepseek.py

Modo de execução em produção (exemplo):
    gunicorn --bind 0.0.0.0:5000 --workers 4 "api_deepseek:create_app()"

Autor: Thalles Canela
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
#    Caso instalado, habilita validação de campos via classes Pythonic (mais seguro e legível).
try:
    from pydantic import BaseModel, ValidationError
    USE_PYDANTIC = True
except ImportError:
    USE_PYDANTIC = False

# 2) Compactar respostas se o cliente suportar.
#    pip install flask-compress
#    Auxilia no envio de respostas comprimidas, reduzindo tráfego de rede.
try:
    from flask_compress import Compress
    COMPRESS_AVAILABLE = True
except ImportError:
    COMPRESS_AVAILABLE = False


# ---------------------- CONFIGURAÇÕES ----------------------
# Define diretórios básicos para logs e banco de dados
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FOLDER = os.path.join(BASE_DIR, "logs")
DB_FOLDER = os.path.join(BASE_DIR, "db")
DB_FILE = os.path.join(DB_FOLDER, "api_logs.db")
LOG_FILE = os.path.join(LOG_FOLDER, "api_server.log")

# Cria diretórios se não existirem
os.makedirs(LOG_FOLDER, exist_ok=True)
os.makedirs(DB_FOLDER, exist_ok=True)

# Configuração do logging (arquivos + saída padrão)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

# Variáveis de ambiente e valores padrão
API_PORT = int(os.getenv("API_PORT", 5000))  # Porta onde a API ficará disponível
API_KEY = os.getenv("PENTEST_API_KEY", "sk_prod_1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
MAX_CONTENT_LENGTH = 1024 * 1024 * 1024  # 1GB limite de tamanho de requisição

# Tempo máximo (em segundos) para a análise via Ollama
OLLAMA_TIMEOUT = 7200  # 2 horas em segundos

# Definição de pool de threads para processar chamadas assíncronas
MAX_WORKERS = 4
executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

# Inicializa o console do rich (para logs coloridos e formatados)
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
    Verifica a disponibilidade do Ollama e do modelo 'deepseek-r1:14b'.
    - Primeiro, checa se o 'ollama --version' executa com sucesso.
    - Depois, tenta rodar o modelo com o prompt 'Teste de conexão'.
    """
    try:
        # Testa se o Ollama está instalado e responde à versão
        subprocess.run(
            ["ollama", "--version"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10
        )
        
        # Teste de interação simples com o modelo
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
    """
    Remove tags desnecessárias e espaçamentos da saída do modelo, 
    por exemplo <think>... </think> e quebras de linha múltiplas.
    """
    cleaned = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)
    cleaned = re.sub(r'\n\s*\n', '\n\n', cleaned)
    return cleaned.strip()


# ---------------------- CACHE SIMPLES ----------------------
# Dicionário para armazenar resultados de análises, evitando reprocessar conteúdo idêntico.
analysis_cache = {}  # dict: {crc_key: output_str}


def process_analysis(scan_data, context):
    """
    Executa a análise usando o Ollama com o modelo deepseek-r1:14b.
    - Gera uma chave CRC32 para cachear resultados repetidos.
    - Chama o subprocess 'ollama run'.
    - Retorna o texto 'limpo' como resultado da análise.
    """
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
        
        # Verifica se houve erro no subprocess
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

        # Salva resultado em cache para chamadas futuras
        analysis_cache[cache_key] = output
        return output
    
    except subprocess.TimeoutExpired:
        console.print("[-] Timeout na análise com DeepSeek", style="bold red")
        return "Erro: Tempo excedido na análise"
    except Exception as e:
        console.print(f"[-] Erro no processamento: {str(e)}", style="bold red")
        logging.exception("Erro no processamento da análise")
        return f"Erro na análise: {str(e)}"


# ---------------------- CRIAÇÃO DO FLASK ----------------------
def create_flask_app() -> Flask:
    """
    Cria e retorna a instância Flask básica.
    Note que o DB não é inicializado aqui; apenas configuramos a aplicação.
    """
    flask_app = Flask(__name__)
    flask_app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
    flask_app.config['JSON_AS_ASCII'] = False

    # Se disponível, comprime respostas
    if COMPRESS_AVAILABLE:
        Compress(flask_app)

    return flask_app

# Cria a aplicação Flask em escopo global
app = create_flask_app()


# ---------------------- MODELO DE VALIDAÇÃO (opcional) ----------------------
if USE_PYDANTIC:
    class AnalyzeRequest(BaseModel):
        """
        Caso a biblioteca Pydantic esteja instalada, esta classe 
        valida automaticamente os campos esperados na requisição.
        """
        scan_data: str
        context: str
        callback_url: str | None = None


# ---------------------- ROTAS ----------------------
@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Endpoint principal para análise (POST /analyze).
    Fluxo:
      - Verifica API Key no cabeçalho.
      - Possível descompressão de dados via 'Content-Encoding: zlib'.
      - Validação dos campos 'scan_data', 'context' e, opcionalmente, 'callback_url'.
      - Se 'callback_url' não estiver presente, retorna resultado síncrono.
      - Se estiver presente, processa e faz POST assíncrono no callback.
    """
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

        # Verifica se a requisição foi comprimida em zlib
        if request.headers.get('Content-Encoding') == 'zlib':
            compressed_data = request.data
            json_data = zlib.decompress(compressed_data).decode('utf-8')
        else:
            json_data = request.data.decode('utf-8')

        # Se Pydantic estiver disponível, faz a validação
        if USE_PYDANTIC:
            payload = AnalyzeRequest(**json.loads(json_data))
            scan_data = payload.scan_data
            context = payload.context
            callback_url = payload.callback_url
        else:
            # Validação manual se Pydantic não estiver instalado
            data = json.loads(json_data)
            if 'scan_data' not in data or 'context' not in data:
                raise ValueError("Campos obrigatórios ausentes (scan_data, context)")
            scan_data = data['scan_data']
            context = data['context']
            callback_url = data.get('callback_url')

        # Processa a análise via Ollama
        console.print("[*] Processando análise...", style="bold yellow")
        result = process_analysis(scan_data, context)
        processing_time = (datetime.now() - start_time).total_seconds()
        status = "success"

        # Caso não exista callback_url, retorna resultado imediatamente (síncrono)
        if not callback_url:
            log_request(client_ip, status, processing_time, data_size)
            console.print("[+] Análise concluída e enviada ao cliente.", style="bold green")
            return jsonify({
                "analysis": result,
                "processing_time": processing_time
            }), 200

        # Caso exista callback_url, processa em modo assíncrono
        def callback_task():
            """
            Tarefa executada em background para enviar resultado ao callback_url.
            Utiliza requests.post para enviar o JSON {'analysis': result}.
            """
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
        # Se Pydantic falhar, retorna erro de validação
        error_msg = str(e)
    except ValueError as e:
        error_msg = str(e)
    except Exception as e:
        logging.exception("Erro geral no endpoint /analyze")
        error_msg = f"Erro interno: {str(e)}"

    # Em caso de erro, loga a requisição com status "failed" e retorna mensagem
    processing_time = (datetime.now() - start_time).total_seconds()
    log_request(client_ip, status, processing_time, data_size)
    console.print(f"[-] Erro na requisição: {error_msg}", style="bold red")
    return jsonify({"error": error_msg}), 400


@app.route("/health", methods=["GET"])
def health_check():
    """
    Endpoint de verificação de saúde (GET /health).
    Retorna JSON com status e hora UTC.
    Também verifica a disponibilidade do Ollama (test_ollama()).
    """
    return jsonify({
        "status": "online",
        "timestamp": datetime.utcnow().isoformat(),
        "ollama_available": test_ollama()
    })


# ---------------------- HANDLERS GLOBAIS DE ERROS (Opcional) ----------------------
@app.errorhandler(404)
def not_found(e):
    """
    Caso acesse uma rota inexistente, retorna erro 404 em formato JSON.
    """
    return jsonify({"error": "Rota não encontrada"}), 404

@app.errorhandler(500)
def internal_error(e):
    """
    Captura erros internos do servidor.
    Usa logging.exception para exibir stacktrace no log.
    """
    logging.exception("Erro interno (500)")
    return jsonify({"error": "Erro interno do servidor"}), 500


# ---------------------- CRIAÇÃO FINAL DA APP ----------------------
def create_app():
    """
    Função de fábrica para uso com Gunicorn.
    Exemplo de uso em produção:
        gunicorn --bind 0.0.0.0:5000 --workers 4 "api_deepseek:create_app()"

    Observação:
      - O Gunicorn chamará esta função e usará o retorno dela como app WSGI.
      - Aqui é o local onde inicializamos o banco de dados (init_db()) 
        e checamos a disponibilidade do Ollama.
    """
    # Inicializa/migra schema do banco
    init_db()

    # Testa se Ollama e modelo estão disponíveis
    if not test_ollama():
        console.print("[-] Ollama/deepseek-r1:14b não disponível!", style="bold red")

    return app  # Retorna a app Flask instanciada globalmente


# ---------------------- ENTRY POINT (DESENVOLVIMENTO) ----------------------
if __name__ == "__main__":
    # Se rodar localmente (sem Gunicorn), usamos esta abordagem:
    local_app = create_app()
    try:
        console.print(f"[+] Iniciando servidor na porta {API_PORT}", style="bold green")
        local_app.run(host="0.0.0.0", port=API_PORT, threaded=True)
    except Exception as e:
        console.print(f"[-] Falha ao iniciar servidor: {str(e)}", style="bold red")
        sys.exit(1)