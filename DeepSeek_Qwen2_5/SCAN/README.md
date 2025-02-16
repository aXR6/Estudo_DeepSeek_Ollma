# Script de PenTest - Integração com DeepSeek API

## Objetivo
Este script foi desenvolvido para realizar testes de penetração automatizados em um único IP ou domínio, utilizando diversas ferramentas de segurança. O objetivo é coletar e analisar informações de segurança do alvo, enviando os resultados para a API do DeepSeek via Ollama para uma análise detalhada.

## Funcionalidades
- **Escaneamento de um único IP/Domínio**: Utiliza ferramentas como Nmap, Nikto, Amass, theHarvester, sublist3r e dnsrecon.
- **Execução simultânea dos scanners**: Todos os scanners (exceto Masscan) utilizam o mesmo alvo e são executados juntos.
- **Execução separada do Masscan**: Permite configurar os parâmetros de execução manualmente.
- **Integração com DeepSeek API**: Consolida e envia os resultados para análise detalhada.
- **Exportação de resultados**: Os resultados podem ser visualizados e exportados em formatos JSON e HTML.
- **Salvamento automático de dispositivos descobertos**: Endereços IP encontrados são armazenados em `network_devices.txt`.

## Requisitos
### Dependências
- **Python**: Versão 3.7+
- **Bibliotecas Python**: Instalar com o comando:
  ```bash
  pip install requests rich
  ```
- **Ferramentas de segurança** (devem estar instaladas e acessíveis via linha de comando):
  - Nmap
  - Nikto
  - Amass
  - theHarvester
  - sublist3r
  - dnsrecon
  - masscan
- **API do DeepSeek**: Deve estar rodando localmente via Ollama.

### Instalação das Ferramentas no Debian 12
Para garantir o funcionamento correto no Debian 12, instale as ferramentas necessárias com os seguintes comandos:

```bash
sudo apt update && sudo apt install -y nmap nikto amass dnsrecon masscan
pip install requests rich
```

Para instalar o theHarvester e sublist3r:
```bash
git clone https://github.com/laramies/theHarvester.git /opt/theHarvester
cd /opt/theHarvester && pip install -r requirements.txt

git clone https://github.com/aboul3la/Sublist3r.git /opt/Sublist3r
cd /opt/Sublist3r && pip install -r requirements.txt
```

## Como Funciona o Script
O script possui um menu interativo onde é possível escolher entre diferentes opções de escaneamento. O fluxo principal segue os seguintes passos:

1. **Selecionar um alvo**: Inserir um IP ou domínio.
2. **Executar os scans**: O script executa Nmap, Nikto, Amass, theHarvester, sublist3r e dnsrecon no alvo.
3. **Coletar os resultados**: Os dados são coletados e consolidados.
4. **Enviar para análise**: Os resultados são enviados para a API do DeepSeek para uma análise avançada.
5. **Visualizar e exportar**: O usuário pode visualizar os resultados e exportá-los para JSON ou HTML.

## Uso
### Executando o Script
Após instalar todas as dependências, execute o script com o comando:

```bash
python3 script_pentest.py
```

### Opções do Menu
1. **Escanear um único IP/Domínio**: Executa todas as ferramentas para um único alvo.
2. **Escanear uma lista de IPs/Domínios**: Lê alvos de um arquivo e executa os scans.
3. **Descoberta de dispositivos na rede**: Executa um ping scan para identificar dispositivos ativos.
4. **Visualizar resultados salvos**: Mostra os resultados de escaneamentos anteriores.
5. **Exportar resultados para HTML**: Salva os resultados em um arquivo `.html`.
6. **Sair**: Fecha o script.
7. **Executar Masscan**: Executa o Masscan com parâmetros configuráveis.

## Sistema Operacional Recomendado
O script foi testado e otimizado para rodar no **Debian 12**, garantindo compatibilidade com as ferramentas utilizadas. No entanto, ele pode ser adaptado para outras distribuições Linux com as devidas configurações.

## Autor
Desenvolvido por **Thalles Canela**
Última atualização: **08 de fevereiro de 2025**