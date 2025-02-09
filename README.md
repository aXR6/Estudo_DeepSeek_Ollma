# Projeto de PenTest com Integração à API DeepSeek

## Objetivo do Projeto
Este projeto foi desenvolvido para automatizar testes de penetração (PenTest) em IPs e domínios, utilizando um conjunto de ferramentas avançadas de segurança e inteligência artificial. A principal inovação do projeto é a integração com a **API DeepSeek via Ollama**, permitindo uma análise detalhada e inteligente dos dados coletados, fornecendo insights valiosos sobre vulnerabilidades, ameaças e possíveis medidas corretivas.

## Funcionalidades do Projeto
### 1. **Automação de Scans de Segurança**
O projeto reúne diversas ferramentas open-source para realizar um PenTest abrangente, incluindo:
- **Nmap**: Para análise de portas e serviços ativos.
- **Nikto**: Para análise de vulnerabilidades em servidores web.
- **Amass**: Para enumeração de subdomínios.
- **theHarvester**: Para coleta de informações sobre emails, hosts e subdomínios.
- **Sublist3r**: Para enumeração de subdomínios utilizando diferentes fontes de dados.
- **dnsrecon**: Para análise detalhada de registros DNS.
- **Masscan**: Para escaneamento ultrarrápido de portas.

### 2. **Integração com API DeepSeek**
A API DeepSeek processa os resultados dos scans e fornece análises detalhadas, identificando:
- Riscos e vulnerabilidades classificadas por gravidade.
- Referências a CVEs conhecidos para correlação de ameaças.
- Medidas de mitigação e recomendações técnicas.
- Possíveis falsos positivos e sugestões para validação.

### 3. **Visualização e Exportação de Resultados**
Os resultados podem ser:
- **Visualizados diretamente no terminal**, utilizando o Rich para melhor formatação.
- **Salvos em JSON**, permitindo posterior processamento e análise.
- **Exportados para HTML**, facilitando a apresentação e documentação.

### 4. **Descoberta de Dispositivos na Rede**
O projeto inclui um **scan de rede via Nmap**, identificando dispositivos ativos e salvando os IPs detectados em `network_devices.txt`.

### 5. **Execução Personalizada do Masscan**
Possui um menu exclusivo para a configuração personalizada do **Masscan**, permitindo definir:
- Range de IPs
- Portas alvo
- Taxa de envio de pacotes

## Instalação e Configuração
### Requisitos
O projeto foi desenvolvido e testado no **Debian 12**, garantindo compatibilidade com:
- **Python 3.7+**
- **Bibliotecas Python**:
  ```bash
  pip install requests rich
  ```
- **Ferramentas de segurança**:
  ```bash
  sudo apt update && sudo apt install -y nmap nikto amass dnsrecon masscan
  ```
- **Instalação de theHarvester e Sublist3r**:
  ```bash
  git clone https://github.com/laramies/theHarvester.git /opt/theHarvester
  cd /opt/theHarvester && pip install -r requirements.txt

  git clone https://github.com/aboul3la/Sublist3r.git /opt/Sublist3r
  cd /opt/Sublist3r && pip install -r requirements.txt
  ```
- **Configuração da API DeepSeek**:
  ```bash
  curl -fsSL https://ollama.com/install.sh | sh
  ```

## Como Executar o Projeto
Após instalar todas as dependências, execute o script com:
```bash
python3 script_pentest.py
```
O menu interativo permitirá escolher a melhor abordagem para o PenTest.

## Imagens:
Imagem da API funcionando:
![API](https://i.postimg.cc/Hn95v59S/Captura-de-tela-de-2025-02-09-13-35-36.png)

Imagem do SCAN funcionando:
![SCAN](https://i.postimg.cc/T34bsTnX/Captura-de-tela-de-2025-02-09-13-39-10.png)

## Conclusão
Este projeto automatiza um processo essencial de segurança cibernética, unindo poderosas ferramentas de PenTest com a inteligência artificial da API DeepSeek. O resultado é uma análise precisa e aprofundada das vulnerabilidades detectadas, permitindo que equipes de segurança atuem de forma mais eficiente na mitigação de riscos.

## Autor
Desenvolvido por **Thalles Canela**
Última atualização: **08 de fevereiro de 2025**