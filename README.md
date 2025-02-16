# Visão Geral

## ART-System
Ferramenta desenvolvida em Python para monitorar o tráfego de rede em tempo real, detectar anomalias (como DDoS, SYN flood e port scanning) e responder automaticamente às ameaças. Opera inicialmente em modo de aprendizado para estabelecer uma baseline de tráfego e, em seguida, utiliza uma API externa com análise preditiva para determinar e executar ações (por exemplo, bloqueio via iptables).

## Projeto de PenTest com Integração à API DeepSeek
Solução para automatizar testes de penetração em IPs e domínios. Utiliza um conjunto de ferramentas open-source (como Nmap, Nikto, Amass, theHarvester, Sublist3r, dnsrecon e Masscan) para identificar vulnerabilidades e dispositivos ativos. A integração com a API DeepSeek (via Ollama) permite análises detalhadas, com classificação de riscos, referências a CVEs e recomendações de mitigação, além de possibilitar a visualização dos resultados no terminal, exportação em JSON e HTML.

# Funcionalidades

## ART-System
### Monitoramento Contínuo
- Captura de pacotes com Scapy (AsyncSniffer) e análise em janelas configuráveis.

### Detecção de Anomalias
- Identifica alta taxa de pacotes, ataques SYN flood e port scanning.

### Aprendizado e Adaptação
- Modo de aprendizado inicial para definir a baseline de tráfego, com atualização dinâmica de parâmetros.

### Análise Preditiva e Resposta
- Envio de dados para uma API externa que retorna uma análise com recomendações, possibilitando respostas automatizadas via iptables (respeitando listas de permissões).

## Projeto de PenTest DeepSeek
### Automação de Scans
- Integra diversas ferramentas para realizar testes de penetração abrangentes, identificando serviços ativos e vulnerabilidades.

### Integração com API DeepSeek
- Processa os resultados dos scans, identificando riscos e sugerindo medidas corretivas com base em análises inteligentes.

### Visualização e Exportação
- Resultados exibidos de forma interativa no terminal (usando Rich), com possibilidade de exportação em JSON ou HTML.

### Descoberta de Dispositivos
- Realiza scans de rede para mapear dispositivos ativos, com opções de configuração personalizada no Masscan.

# Instalação e Configuração

## Requisitos Gerais
### Python
- ART-System: 3.10 ou superior
- PenTest: 3.7 ou superior

### Bibliotecas e Ferramentas
- Dependências Python: scapy, requests, pyyaml, rich, entre outras específicas.
- Ferramentas de segurança: Nmap, Nikto, Amass, dnsrecon, Masscan, theHarvester, Sublist3r.

### Permissões
- Execução com privilégios de root/sudo para captura de pacotes e comandos de rede.

## Passos para Instalação
### Clone o repositório
```bash
git clone https://github.com/seu-usuario/projeto-seguranca-integrada.git
cd projeto-seguranca-integrada
```

### Configure o ambiente virtual (opcional)
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/MacOS
```

### Instale as dependências
```bash
pip install -r requirements.txt
```

### Ajuste as configurações
- Para o ART-System, edite o arquivo `config.yaml` com os parâmetros de rede, API e logging.
- Para o Projeto de PenTest, siga as instruções de instalação para as ferramentas de segurança e configure a integração com a API DeepSeek.

# Execução

## ART-System
Execute com privilégios de root:
```bash
sudo python3 art_system.py --config config.yaml
```

## Projeto de PenTest
Inicie o script interativo para escolher as abordagens de PenTest:
```bash
python3 script_pentest.py
```

# Conclusão
Esta solução integrada oferece uma abordagem completa para a segurança cibernética, combinando:

- **Detecção e Resposta Automatizada**: Com ART-System, ameaças em tempo real são monitoradas e neutralizadas de forma inteligente.
- **Testes de Penetração Inteligentes**: Com o projeto DeepSeek, vulnerabilidades são identificadas e analisadas, permitindo ações corretivas precisas.

Ambos os projetos, além de fortalecerem a segurança, contam com a integração de inteligência artificial para aprimorar a análise e a tomada de decisões, tornando a proteção de redes e sistemas mais robusta e proativa.