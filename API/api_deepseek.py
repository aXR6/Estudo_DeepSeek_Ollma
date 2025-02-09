#!/usr/bin/env python3
"""
API Server para integração com DeepSeek via Ollama - Versão Melhorada
Arquitetura ASGI com Quart, async/await, conexão via API HTTP, pool de conexões com SQLite,
validação de dados com Pydantic, rate limiting e outras otimizações.

Autor: Thalles Canela
Data: 2025-02-02 (Atualizado: 2025-02-08)
"""

import os
import sys
import json
import logging
import re
import zlib
import asyncio
from datetime import datetime, timedelta
from typing import Optional

from quart import Quart, request, jsonify, Response
from quart_rate_limiter import RateLimiter, rate_limit
from pydantic import BaseModel, ValidationError
import httpx
import databases

# Importa Rich para saída elegante
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.logging import RichHandler

console = Console()

# ------------------------------
# Criação dos diretórios necessários
# ------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FOLDER = os.path.join(BASE_DIR, "logs")
DB_FOLDER = os.path.join(BASE_DIR, "db")
DB_FILE = os.path.join(DB_FOLDER, "api_logs.db")

os.makedirs(LOG_FOLDER, exist_ok=True)
os.makedirs(DB_FOLDER, exist_ok=True)

# ------------------------------
# Configuração de Logging Unificado com Formatter Personalizado
# ------------------------------

class CustomFormatter(logging.Formatter):
    level_emoji = {
        logging.DEBUG: "🐞",
        logging.INFO: "✅",
        logging.WARNING: "⚠️",
        logging.ERROR: "⛔",
        logging.CRITICAL: "🔥"
    }
    def format(self, record):
        timestamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        emoji = self.level_emoji.get(record.levelno, "")
        message = record.getMessage()
        return f"[{timestamp}] {emoji} {message}"

console_handler = RichHandler()
console_handler.setFormatter(CustomFormatter())
file_handler = logging.FileHandler(os.path.join(LOG_FOLDER, "api_server.log"))
file_handler.setFormatter(CustomFormatter())

logging.basicConfig(
    level=logging.INFO,
    handlers=[console_handler, file_handler]
)

# ------------------------------
# Configurações Gerais
# ------------------------------
API_PORT = int(os.getenv("API_PORT", "5000"))
MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", str(1024 * 1024 * 1024)))  # 1GB
API_KEY = os.getenv("PENTEST_API_KEY", "sk_prod_1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
OLLAMA_API_URL = os.getenv("OLLAMA_API_URL", "http://localhost:11434")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "7200"))  # 2 horas em segundos
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "4"))
APP_VERSION = "2.1.0"

# ------------------------------
# Inicializa o aplicativo Quart (ASGI)
# ------------------------------
app = Quart(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

# Rate limiting: utiliza chave baseada no endereço remoto
rate_limiter = RateLimiter(app, key_function=lambda: request.remote_addr)

# ------------------------------
# Configuração do banco de dados assíncrono com databases (SQLite)
# ------------------------------
DATABASE_URL = f"sqlite:///{DB_FILE}"
database = databases.Database(DATABASE_URL)

# ------------------------------
# Modelo Pydantic para validação de entrada
# ------------------------------
class AnalysisRequest(BaseModel):
    scan_data: str
    context: str
    callback_url: Optional[str] = None

# ------------------------------
# Funções Utilitárias
# ------------------------------
def clean_analysis_result(text: str) -> str:
    cleaned = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)
    cleaned = re.sub(r'\n\s*\n', '\n\n', cleaned)
    return cleaned.strip()

async def log_request(client_ip: str, status: str, processing_time: float, data_size: int) -> None:
    query = """
        INSERT INTO requests (timestamp, client_ip, status, processing_time, data_size)
        VALUES (:timestamp, :client_ip, :status, :processing_time, :data_size)
    """
    values = {
        "timestamp": datetime.utcnow().isoformat(),
        "client_ip": client_ip,
        "status": status,
        "processing_time": processing_time,
        "data_size": data_size
    }
    try:
        await database.execute(query=query, values=values)
    except Exception as e:
        logging.error(f"Erro registrando requisição: {str(e)}")

async def init_db() -> None:
    query = """
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            client_ip TEXT,
            status TEXT,
            processing_time REAL,
            data_size INTEGER
        )
    """
    try:
        await database.execute(query)
    except Exception as e:
        logging.error(f"Erro inicializando banco de dados: {str(e)}")

http_client = httpx.AsyncClient(timeout=OLLAMA_TIMEOUT)

async def test_ollama() -> bool:
    try:
        response = await http_client.get(f"{OLLAMA_API_URL}/api/version")
        response.raise_for_status()
        test_payload = {"model": "deepseek-r1:14b", "prompt": "Teste de conexão"}
        response = await http_client.post(f"{OLLAMA_API_URL}/api/generate", json=test_payload)
        response.raise_for_status()
        return "error" not in response.text.lower()
    except Exception as e:
        logging.error(f"Falha no teste do Ollama: {str(e)}")
        return False

async def process_analysis(scan_data: str, context: str) -> str:
    start_time = datetime.now()
    input_message = f"{context}\n\nDados do Scan:\n{scan_data}"
    payload = {"model": "deepseek-r1:14b", "prompt": input_message}
    try:
        logging.info("Iniciando análise com DeepSeek...")
        response = await http_client.post(f"{OLLAMA_API_URL}/api/generate", json=payload)
        response.raise_for_status()
        output = clean_analysis_result(response.text)
        processing_time = (datetime.now() - start_time).total_seconds()
        logging.info(f"Análise concluída em {processing_time:.2f} segundos")
        return output
    except httpx.TimeoutException:
        logging.error("Timeout na análise com DeepSeek")
        return "Erro: Tempo excedido na análise"
    except Exception as e:
        logging.error(f"Erro no processamento: {str(e)}")
        return f"Erro na análise: {str(e)}"

async def send_callback(callback_url: str, result: str) -> None:
    try:
        logging.info(f"Enviando resultados para {callback_url}...")
        async with httpx.AsyncClient(timeout=30) as client:
            await client.post(callback_url, json={"analysis": result})
        logging.info("Resultados enviados com sucesso.")
    except Exception as e:
        logging.error(f"Erro no callback: {str(e)}")

def print_startup_banner(port: int, version: str, db_status: bool, ollama_status: bool, model_status: bool):
    banner_text = f"🛡️ API DeepSeek Pentest                    Versão: {version}\n                                             Porta: {port}"
    banner_panel = Panel(banner_text, title="Inicializando Serviço", subtitle="by Thalles Canela", style="bold cyan", padding=(1, 2))
    console.print(banner_panel)
    
    table = Table(title="Status dos Serviços", title_style="bold green", box=box.ROUNDED, border_style="blue", padding=(0, 1))
    table.add_column("Serviço", justify="left", style="bold cyan", no_wrap=True)
    table.add_column("Status", justify="center", style="bold white")
    table.add_row("Banco de Dados", "✅ Conectado" if db_status else "❌ Desconectado")
    table.add_row("Ollama API", "✅ Disponível" if ollama_status else "❌ Indisponível")
    table.add_row("Modelo (deepseek-r1:14b)", "✅ Carregado" if model_status else "❌ Não carregado")
    console.print(table)
    
    status_panel = Panel(f"✅ API em execução!\nURL: http://localhost:{port}\nModo: 🟡 Desenvolvimento", title="Status", style="bold green", padding=(1, 2))
    console.print(status_panel)

# ------------------------------
# Global Error Handler para Requisições
# ------------------------------
@app.errorhandler(Exception)
async def handle_unexpected_error(e: Exception) -> Response:
    logging.error(f"Erro inesperado: {str(e)}")
    # Retorna uma mensagem padronizada e encerra a aplicação (se necessário)
    return jsonify({"error": "Erro inesperado ocorreu. A aplicação está sendo encerrada."}), 500

# ------------------------------
# Middleware After Request para Log Unificado
# ------------------------------
@app.after_request
async def log_requests(response: Response) -> Response:
    timestamp = datetime.now().strftime("%H:%M:%S")
    method = request.method
    path = request.path
    status = response.status_code
    client = request.remote_addr or "unknown"
    if 200 <= status < 300:
        emoji = "✅"
    elif 400 <= status < 500:
        emoji = "⚠️"
    else:
        emoji = "⛔"
    log_data = {
        "method": method,
        "path": path,
        "status": status,
        "client": client
    }
    console.print(f"[{timestamp}] {emoji} {json.dumps(log_data)}", style="bold")
    return response

# ------------------------------
# Endpoints
# ------------------------------
@app.route("/analyze", methods=["POST"])
@rate_limit(50, timedelta(minutes=1))
async def analyze() -> Response:
    start_time = datetime.now()
    client_ip = request.remote_addr or "unknown"
    data_bytes = await request.get_data()
    data_size = len(data_bytes)
    status = "failed"

    if request.headers.get("X-API-Key") != API_KEY:
        logging.warning(f"Acesso não autorizado de {client_ip}")
        return jsonify({"error": "Não autorizado"}), 401

    try:
        if request.headers.get("Content-Encoding") == "zlib":
            json_data = zlib.decompress(data_bytes).decode("utf-8")
        else:
            json_data = data_bytes.decode("utf-8")
        payload = json.loads(json_data)
        try:
            analysis_request = AnalysisRequest(**payload)
        except ValidationError as ve:
            raise ValueError(ve.errors())

        logging.info(f"Requisição recebida de {client_ip}")
        logging.info("Processando análise...")
        result = await process_analysis(analysis_request.scan_data, analysis_request.context)
        processing_time = (datetime.now() - start_time).total_seconds()
        status = "success"

        if not analysis_request.callback_url:
            await log_request(client_ip, status, processing_time, data_size)
            return jsonify({
                "analysis": result,
                "processing_time": processing_time
            }), 200

        asyncio.create_task(send_callback(analysis_request.callback_url, result))
        await log_request(client_ip, "async_started", processing_time, data_size)
        return jsonify({
            "message": "Análise em andamento",
            "callback_url": analysis_request.callback_url
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
    await log_request(client_ip, status, processing_time, data_size)
    logging.error(f"Erro na requisição: {error_msg}")
    return jsonify({"error": error_msg}), 400

@app.route("/health", methods=["GET"])
async def health_check() -> Response:
    ollama_status = await test_ollama()
    return jsonify({
        "status": "online",
        "timestamp": datetime.utcnow().isoformat(),
        "ollama_available": ollama_status
    })

# ------------------------------
# Startup e Shutdown
# ------------------------------
@app.before_serving
async def startup() -> None:
    await database.connect()
    await init_db()
    db_status = True
    ollama_status = await test_ollama()
    model_status = True  # Assumindo que o modelo já foi carregado
    if not ollama_status:
        logging.error("Ollama/deepseek-r1:14b não disponível!")
        sys.exit(1)
    print_startup_banner(API_PORT, APP_VERSION, db_status, ollama_status, model_status)
    logging.info(f"Servidor iniciado com sucesso na porta {API_PORT}")

@app.after_serving
async def shutdown() -> None:
    await database.disconnect()
    await http_client.aclose()
    console.print("[bold yellow]⏹️ Servidor interrompido pelo usuário")
    console.print("[bold magenta]👋 Encerrando aplicação...")

# ------------------------------
# Inicialização do Servidor ASGI com Tratamento Global de Erros Críticos
# ------------------------------
if __name__ == "__main__":
    try:
        import hypercorn.asyncio
        from hypercorn.config import Config

        config = Config()
        config.bind = [f"0.0.0.0:{API_PORT}"]
        asyncio.run(hypercorn.asyncio.serve(app, config))
    except Exception as e:
        console.print(f"[bold red]Erro inesperado: {str(e)}[/bold red]")
        sys.exit(1)