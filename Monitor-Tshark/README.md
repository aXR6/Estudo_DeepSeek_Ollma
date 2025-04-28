# Monitor-Tshark

Monitor de rede em tempo real que captura pacotes TCP usando Scapy, identifica varreduras (NULL, SYN, XMAS) e exibe alertas dinâmicos no terminal com Rich, além de manter um painel de “Top Victims” baseado na contagem de eventos por IP.

## Funcionalidades

- **Detecção de scans TCP**: Identifica NULL (nenhuma flag), SYN (apenas SYN) e XMAS (FIN+PSH+URG). [Documentação do Scapy](https://scapy.readthedocs.io/)
- **Exibição ao vivo**: Tabela de alertas e painel de “Top N IPs vítimas” atualizados em tempo real via `rich.live.Live`. [Documentação do Rich](https://rich.readthedocs.io/)
- **Rotação de logs diária**: Utiliza `logging.handlers.TimedRotatingFileHandler` para criar logs a cada meia-noite, mantendo até 7 backups. [Documentação do Python](https://docs.python.org/3/library/logging.handlers.html#timedrotatingfilehandler)
- **Configuração por linha de comando**: Argumentos para interface, diretório de logs, tamanho máximo da tabela e número de vítimas, via `argparse`. [Documentação do Python](https://docs.python.org/3/library/argparse.html)
- **Resumo de vítimas**: Construção de tabela com `rich.table.Table`, exibindo contagem por IP. [Documentação do Rich](https://rich.readthedocs.io/)
- **Compatível com múltiplas interfaces**: Basta informar `--interface <nome>` (verifique interfaces com `ip addr show`).

## Instalação

1. Clone este repositório:

    ```bash
    git clone <URL_DO_REPOSITORIO>
    cd <NOME_DO_REPOSITORIO>
    ```

2. Certifique-se de ter Python 3.8+ instalado.

3. Em Debian 12, instale dependências via APT:

    ```bash
    sudo apt update
    sudo apt install python3-scapy python3-rich
    ```

4. (Opcional) Crie um ambiente virtual e instale via pip:

    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    pip install scapy rich
    ```

5. Conceda capacidade de captura RAW ao Python (evita rodar como root):

    ```bash
    sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
    ```

## Uso

Execute o script com os seguintes parâmetros:

```bash
python3 mon_ataque.py \
  --interface enp6s18 \
  --log-dir logs \
  --max-rows 60 \
  --top-victims 10
```

### Parâmetros

- `-i, --interface`: Nome da interface de rede (ex: eth0, wlan0, enp6s18).
- `-l, --log-dir`: Pasta para armazenar logs de eventos.
- `-n, --max-rows`: Quantidade de linhas antes de limpar a tabela de alertas.
- `-t, --top-victims`: Número de IPs vítimas a exibir no painel de resumo.

**Dica**: Use `sniff(iface=…, filter="tcp", …)` para reduzir tráfego processado.

## Estrutura do Código

- `parse_args()`: Configuração de `argparse` para parâmetros de execução.
- `setup_logger()`: Inicializa logger com `TimedRotatingFileHandler` para logs diários.
- `detect_scan_type()`: Lógica de detecção de scan via flags TCP.
- `create_table()` / `create_summary_table()`: Constroem tabelas Rich para alertas e resumo de vítimas.
- `main()`: Abre `Live` com as duas tabelas e inicia `sniff()`, chamando `packet_callback` para cada pacote.

## Logs

- **Arquivo**: `<log-dir>/netmon.log`
- **Rotação**: À meia-noite, mantém 7 dias de histórico.

## Automação da Execução

Para facilitar a inicialização automática do monitor em sistemas Linux, você pode usar o script `run_monitor.sh`, que:

1. Cria e ativa um ambiente virtual em `.venv`.
2. Instala as dependências (`scapy` e `rich`).
3. Concede a capacidade `CAP_NET_RAW` ao Python do ambiente virtual.
4. Garante o diretório de logs.
5. Executa o `mon_ataque.py` com seus parâmetros.

### Uso do `run_monitor.sh`

```bash
chmod +x run_monitor.sh   # Torna o script executável
./run_monitor.sh <INTERFACE> <LOG_DIR> <MAX_ROWS> <TOP_VICTIMS>
```

Por exemplo:

```bash
./run_monitor.sh enp6s18 logs 60 10
```

Isso vai:

- Criar/entrar em `.venv`.
- Instalar/atualizar dependências.
- Configurar permissões de raw socket.
- Preparar o diretório `logs`.
- Iniciar o monitor com os parâmetros informados.

**Dica extra**: Para iniciar automaticamente no boot, adicione ao crontab do root:

```bash
@reboot /caminho/para/run_monitor.sh enp6s18 /caminho/para/logs 60 10
```

## Contribuição

Pull requests são bem-vindos. Para mudanças maiores, abra uma issue antes para alinharmos requisitos.
