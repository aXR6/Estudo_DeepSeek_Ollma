# ART-System

Sistema Avançado de Detecção e Resposta a Ameaças em Tempo Real

O ART-System é uma solução em Python para monitoramento contínuo do tráfego de rede, detecção de padrões suspeitos (como DDoS, port scanning e brute force) e resposta automatizada a ameaças. Com uma abordagem integrada de análise preditiva via IA e aprendizado contínuo, o sistema visa aumentar a segurança da rede por meio de ações automatizadas (por exemplo, bloqueio ou limitação de conexões) e de integração com APIs externas para análises avançadas.

## Funcionalidades

### Monitoramento Contínuo
- Captura de pacotes em tempo real utilizando o módulo Scapy.

### Detecção de Anomalias
- Verificação de alta taxa de pacotes (PPS)
- Detecção de SYN flood (proporção de pacotes SYN acima do limite)
- Identificação de port scanning (quando um IP acessa muitos portos em um curto período)

### Análise Preditiva
- Integração com uma API externa para analisar dados do tráfego e definir ações com base em uma confiança mínima definida.

### Resposta Automatizada
- Execução de ações de resposta (como bloqueio ou limitação de tráfego) via comandos do sistema (iptables).

### Aprendizado Contínuo
- Atualiza a baseline do tráfego após um período de aprendizado para se adaptar a padrões normais e melhorar a detecção de anomalias.

## Requisitos
- Python: 3.10 ou superior
- Scapy: 2.5.0 ou superior
- Requests: 2.31.0 ou superior
- YAML: Para leitura de configurações (utilizando a biblioteca pyyaml)
- Privilégios de Root/Sudo: Necessário para captura de pacotes e execução de comandos do sistema (iptables).

## Instalação

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

Certifique-se de incluir no seu `requirements.txt` as bibliotecas necessárias (scapy, requests, pyyaml, etc.).

## Configuração

O ART-System utiliza um arquivo de configuração em YAML para definir parâmetros de rede, API e logging. Um exemplo de configuração (`config.yaml`) é:
```yaml
network:
    interface: "enp8s0"
    whitelist:
        - "192.168.3.100"
    max_pps: 5000
    max_syn_ratio: 0.8
    burst_window: 5

api:
    endpoint: "http://localhost:5000/analyze"
    key: "sk_prod_1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    timeout: 30
    threshold: 0.85

logging:
    level: "INFO"
    file: "/var/log/art_system.log"
```

**Atenção:** O arquivo de configuração será mesclado com os valores padrão definidos no código. Caso alguma seção esteja ausente ou mal formatada, o sistema exibirá mensagens de erro e encerrará a execução.

## Uso

O ART-System deve ser executado com privilégios de root/sudo para permitir a captura de pacotes. Para iniciar o sistema, utilize:
```bash
sudo python3 art_system.py --config config.yaml
```

O sistema iniciará o sniffer de pacotes e, em intervalos definidos (de acordo com a configuração `burst_window`), processará os pacotes capturados. Caso anomalias sejam detectadas, o sistema:
- Captura um resumo do tráfego recente.
- Envia os dados para uma API externa para análise.
- Executa as ações de resposta recomendadas (como bloquear ou limitar conexões) utilizando iptables.

## Estrutura do Código

### DEFAULT_CONFIG
Define os parâmetros padrão para rede, API e logging.

### TrafficAnalyzer (classe)
Responsável por:
- Reiniciar os contadores temporais.
- Atualizar a baseline do tráfego.
- Processar cada pacote (verificando camadas IP, TCP, UDP, ICMP).
- Detectar anomalias (alta taxa de pacotes, alta proporção de pacotes SYN e port scanning).

### ThreatResponder (classe)
Gerencia as respostas a ameaças:
- Bloqueia IPs suspeitos utilizando iptables.
- Limita conexões de IPs que excedem limites.
- Verifica se um IP está na whitelist antes de aplicar ações.

### APIClient (classe)
Gerencia a comunicação com uma API externa para enviar dados do tráfego e receber recomendações de ações.

### ARTSystem (classe)
Orquestra o monitoramento:
- Inicia o sniffer de pacotes (AsyncSniffer do Scapy).
- Processa os pacotes em intervalos definidos.
- Chama o analisador para identificar anomalias.
- Em caso de anomalias, captura dados de tráfego, envia para análise via API e executa respostas.

### Funções Auxiliares
- `load_config(file_path)`: Carrega e valida o arquivo de configuração YAML.
- `deepmerge(default, custom)`: Realiza a mesclagem hierárquica entre o padrão e as configurações do usuário.
- `setup_logging(config)`: Configura o sistema de logging com base nas definições.

### Sinalização de Interrupção
O sistema trata sinais (SIGINT e SIGTERM) para realizar uma parada limpa do monitoramento.

## Contribuições

Contribuições, sugestões e correções são bem-vindas! Por favor, abra uma issue ou envie um pull request para ajudar a melhorar o ART-System.

## Licença

Este projeto está licenciado sob a MIT License.

## Autor

Thalles Canela

**Revisão:** 1.8.2