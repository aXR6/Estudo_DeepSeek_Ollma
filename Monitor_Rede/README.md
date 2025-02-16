# ART-System

**Sistema Avançado de Detecção e Resposta a Ameaças em Tempo Real**

O ART-System é uma ferramenta desenvolvida em Python para monitorar o tráfego de rede em tempo real, detectar padrões suspeitos (como DDoS, port scanning e brute force) e responder automaticamente a ameaças. Com um mecanismo de aprendizado contínuo e integração com análise preditiva via IA, o sistema ajusta sua baseline de tráfego e toma decisões inteligentes (por exemplo, bloquear ou limitar conexões) com base em métricas de risco e confiabilidade.

## Sumário
- [Visão Geral](#visão-geral)
- [Funcionalidades](#funcionalidades)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Configuração](#configuração)
- [Uso](#uso)
- [Arquitetura e Fluxo de Processamento](#arquitetura-e-fluxo-de-processamento)
- [Procedimentos Avançados](#procedimentos-avançados)
- [Resolução de Problemas e Debug](#resolução-de-problemas-e-debug)
- [Contribuições](#contribuições)
- [Licença](#licença)
- [Autor e Revisão](#autor-e-revisão)

## Visão Geral

O ART-System captura e analisa pacotes de rede utilizando o módulo Scapy, agregando estatísticas em tempo real para identificar anomalias como:

- **Alta taxa de pacotes (PPS)**: Comparando o total de pacotes com um limite definido.
- **SYN flood**: Monitorando a proporção de pacotes SYN dentro do tráfego TCP.
- **Port scanning**: Identificando IPs que acessam um número elevado de portas em um curto período.

Após a detecção, os dados são enviados para uma API externa que, por meio de um contexto detalhado (incluindo histórico de PPS, estatísticas por IP e baseline de tráfego), retorna uma análise contendo campos como confidence, decision (ex.: block, throttle, alert ou no_action), analysis_summary, recommended_actions e risk_score. Dependendo do resultado e de um limiar de confiança configurado, o sistema executa ações automatizadas utilizando comandos do iptables.

Durante os primeiros minutos de execução, o sistema opera em “modo de aprendizado”, coletando dados para estabelecer a baseline do tráfego normal. Após esse período, o ART-System passa a comparar os valores atuais com os padrões aprendidos, refinando a detecção de anomalias.

## Funcionalidades

### Monitoramento Contínuo:
- Captura de pacotes em tempo real utilizando o AsyncSniffer do Scapy.
- Processamento periódico de pacotes com janela de análise configurável.

### Detecção de Anomalias:
- Verificação de alta taxa de pacotes (PPS).
- Detecção de SYN flood por meio da proporção de pacotes SYN.
- Identificação de port scanning com base no número de portas acessadas por IP.

### Aprendizado Contínuo:
- Modo de aprendizado inicial (300 segundos) para definição da baseline de tráfego.
- Atualização dinâmica dos parâmetros de referência (avg_pps e syn_ratio).

### Análise Preditiva e Resposta Automatizada:
- Integração com uma API externa que recebe um contexto enriquecido e retorna recomendações.
- Execução de respostas inteligentes: bloqueio ou limitação de conexões via iptables, respeitando a whitelist configurada.

### Gerenciamento Seguro:
- Tratamento de sinais (SIGINT e SIGTERM) para uma parada limpa do sistema.
- Validação e mesclagem hierárquica da configuração (usando deepmerge) para garantir a integridade dos parâmetros.

## Requisitos
- Python: 3.10 ou superior
- Scapy: 2.5.0 ou superior
- Requests: 2.31.0 ou superior
- PyYAML: Para leitura e validação de arquivos YAML
- Privilégios de Root/Sudo: Necessários para captura de pacotes e execução de comandos (iptables)

## Instalação

### Passo a Passo

Clone o repositório:
```bash
git clone https://github.com/seu-usuario/art_system.git
cd art_system
```

Crie e ative um ambiente virtual (opcional, mas recomendado):
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/MacOS
# ou, no Windows:
venv\Scripts\activate
```

Instale as dependências:
```bash
pip install -r requirements.txt
```

Certifique-se de que o arquivo `requirements.txt` contenha as bibliotecas necessárias (scapy, requests, pyyaml, etc.).

## Configuração

O ART-System utiliza arquivos YAML para configurar parâmetros de rede, API, logging e segurança. A configuração do sistema é feita por meio de um arquivo (por exemplo, `config.yaml`), que será mesclado com valores padrão definidos no código.

### Exemplo de Configuração (`config.yaml`)
```yaml
network:
    interface: "enp8s0"         # Interface de monitoramento
    whitelist:
        - "192.168.3.100"         # IP ou rede que não será bloqueada
    max_pps: 5000              # Limite de pacotes por segundo para alerta
    max_syn_ratio: 0.8         # Proporção máxima de pacotes SYN permitida
    burst_window: 5            # Janela de análise em segundos

api:
    endpoint: "http://localhost:5000/analyze"
    key: "sk_prod_1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    timeout: 30                # Tempo máximo de espera pela resposta da API
    threshold: 0.85            # Confiança mínima para execução de ações

logging:
    level: "INFO"              # Níveis possíveis: DEBUG, INFO, WARNING, etc.
    file: "/var/log/art_system.log"
```

**Atenção:** Se alguma seção estiver ausente ou mal formatada, o sistema exibirá mensagens de erro e encerrará a execução.

## Uso

Para executar o ART-System, é necessário ter privilégios de root/sudo. O comando básico é:
```bash
sudo python3 art_system.py --config config.yaml
```

### Fluxo de Operação

#### Captura de Pacotes:
- O sistema inicia o sniffer em tempo real utilizando o AsyncSniffer do Scapy.
- Durante cada janela de análise (definida por `burst_window`), os pacotes são processados e os contadores são atualizados.

#### Detecção e Aprendizado:
- Nos primeiros 300 segundos, o sistema opera em modo de aprendizado, coletando dados para estabelecer a baseline de tráfego.
- Após esse período, o ART-System compara os dados atuais com os valores da baseline e detecta anomalias (alta PPS, SYN flood, port scanning).

#### Análise Preditiva:
- Quando anomalias são detectadas, um contexto enriquecido (incluindo estatísticas, histórico e uma mensagem de instrução) é enviado para uma API externa.
- A API retorna uma análise com campos como confidence, decision, analysis_summary, recommended_actions e risk_score.

#### Resposta Automatizada:
- Se a confiança da análise exceder o limiar configurado, o sistema executa as ações recomendadas (ex.: bloqueio ou limitação de conexões) usando iptables.
- Antes de aplicar qualquer ação, o sistema verifica se o IP está na whitelist.

## Arquitetura e Fluxo de Processamento

### Componentes Principais

#### TrafficAnalyzer:
- Processa cada pacote, atualiza contadores e coleta estatísticas (total, TCP, UDP, ICMP, SYN e estatísticas por IP).
- Detecta anomalias com base na taxa de pacotes, proporção SYN e atividade de port scanning.
- Opera em modo de aprendizado para estabelecer uma baseline (avg_pps e syn_ratio).

#### ThreatResponder:
- Gerencia a execução de ações de resposta (bloqueio ou limitação de conexões) via iptables.
- Verifica a whitelist para evitar ações sobre IPs confiáveis.

#### APIClient:
- Responsável por enviar os dados de tráfego e o contexto de anomalias para uma API externa.
- Recebe uma análise que orienta as ações de resposta.

#### ARTSystem:
- Orquestra o monitoramento: inicia o sniffer, processa pacotes periodicamente, gerencia a detecção de anomalias e aciona a API para análise.
- Implementa um ciclo de captura, análise e resposta, garantindo uma operação contínua e robusta.

### Pipeline de Processamento
1. **Captura:** Inicia o AsyncSniffer e acumula pacotes durante o `burst_window`.
2. **Análise:** Cada pacote é processado para atualizar contadores e estatísticas; as anomalias são detectadas.
3. **Envio à API:** Em caso de anomalias, um contexto detalhado (incluindo a mensagem de instrução e dados históricos) é enviado para a API externa.
4. **Decisão e Resposta:** Com base na análise recebida, se a confiança for alta, ações de resposta (block ou throttle) são executadas.

## Procedimentos Avançados

### Instalação em Sistemas Debian/Ubuntu
```bash
# Instalação de dependências do sistema
sudo apt install build-essential libpcap-dev python3-dev

# Clone o repositório
git clone https://github.com/seu-usuario/art_system.git
cd art_system

# Ambiente isolado com Poetry (opcional)
curl -sSL https://install.python-poetry.org | python3 -
poetry install --extras "monitoring analysis"

# Instalação do serviço systemd
sudo cp config/art-system.service /etc/systemd/system/
sudo systemctl enable art-system
```

### Configuração Modularizada
Você pode dividir a configuração em múltiplos arquivos YAML (ex.: `network.yaml`, `api.yaml`, `logging.yaml`, etc.).

#### Exemplo de arquivo `network.yaml`:
```yaml
network:
    interface: enp8s0
    promiscuous: false
    whitelist:
        - 192.168.1.0/24
        - 10.0.0.2
    thresholds:
        pps: 5000
        syn_ratio: 0.75
        scan_ports: 15
        burst_window: 5
```

### Validação de Configuração
Verifique a sintaxe dos arquivos YAML e teste o carregamento da configuração:
```bash
# Verificar sintaxe YAML
python3 -c "import yaml, sys; yaml.safe_load(open(sys.argv[1]))" config.yaml

# Testar carregamento
art_system --config config.yaml --validate

# Gerar configuração padrão
art_system --generate-config > default_config.yaml
```

### Operação e Monitoramento

#### Comandos Essenciais
```bash
# Iniciar com logs detalhados
sudo art_system --config production.yaml -vv

# Modo de diagnóstico com captura de pacotes
sudo art_system --debug --capture-file dump.pcap
```

#### Gerenciamento de Serviço
```bash
sudo systemctl start art-system
sudo journalctl -u art-system -f
```

#### Monitoramento em Tempo Real
```bash
# Painel de tráfego (requer rich)
watch -n 1 "sudo art_system --status | jq .traffic"

# Visualizar regras iptables ativas
sudo iptables -L ART-INPUT -nv --line-numbers

# Monitorar decisões da IA
tail -f /var/log/art_system.log | grep AI_DECISION
```

#### Integração com Ferramentas Externas
```bash
# Exportar métricas para Prometheus
art_system --export-metrics format=prometheus port=9111

# Enviar alertas para Slack via webhook
art_system --alert-webhook url=https://hooks.slack.com/services/...
```

## Resolução de Problemas e Debug

### Erros Comuns e Possíveis Soluções

| Erro | Causa Provável | Solução |
|------|----------------|---------|
| CRITICAL:root:Erro ao carregar configuração | Formato inválido no YAML | Verificar indentação e sintaxe do arquivo |
| PermissionError: [Errno 1] | Privilégios insuficientes | Executar com sudo e conferir capabilities |
| No such device: 'enp8s0' | Interface de rede incorreta | Listar interfaces com `ip -br link` |
| OSError: Failed to open | Conflito com outro sniffer | Liberar a porta com `sudo killall tcpdump` |

### Técnicas de Debug
No código, é possível ativar o modo diagnóstico para ajudar na depuração:
```python
from debug import enable_debug_mode
enable_debug_mode(
        packet_capture=True,
        api_validation=True,
        iptables_dry_run=True
)
```

### Coleta de Diagnóstico
```bash
# Gerar pacote completo de diagnóstico
sudo art_system --diagnostic output=art_diagnostics.tar.gz

# Testar conectividade com a API
art_system --test-api endpoint=http://localhost:5000/analyze
```

## Contribuições
Contribuições, sugestões e correções são muito bem-vindas! Abra uma issue ou envie um pull request para ajudar a aprimorar o ART-System.

## Licença
Este projeto está licenciado sob a MIT License.

## Autor e Revisão
**Autor:** Thalles Canela  
**Revisão:** 1.8.2