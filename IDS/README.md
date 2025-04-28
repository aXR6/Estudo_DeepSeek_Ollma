# 🛡️ IDS Setup Script

Automatize a configuração de um servidor de segurança e otimização de tráfego de rede com este script. Ele integra ferramentas como Suricata, CrowdSec, Fail2Ban, IPSet, Squid e configura QoS para priorizar tráfego de jogos, streaming e downloads.

---

## 📋 Sumário

- [�️ IDS Setup Script](#️-ids-setup-script)
  - [📋 Sumário](#-sumário)
  - [🚀 Visão Geral](#-visão-geral)
  - [⚙️ Funcionalidades](#️-funcionalidades)
  - [📦 Requisitos](#-requisitos)
  - [🛠️ Instalação](#️-instalação)
  - [🧪 Verificação](#-verificação)
  - [📄 Licença](#-licença)

---

## 🚀 Visão Geral

Este script Bash automatiza a configuração de um servidor de segurança de rede, incluindo:

- Criação de uma bridge transparente entre duas interfaces de rede.
- Instalação e configuração de ferramentas de segurança: Suricata, CrowdSec, Fail2Ban.
- Configuração de bloqueio de IPs maliciosos com IPSet.
- Implementação de QoS para priorização de tráfego de jogos, streaming e downloads.
- Configuração básica de cache com Squid.
- Salvamento e aplicação persistente de regras do iptables.

---

## ⚙️ Funcionalidades

- **Bridge de Rede**: Cria uma bridge (`br0`) entre as interfaces `enp6s18` e `enp6s19`, atribuindo o IP `192.168.1.10/24`.
- **Suricata**: Instala e configura o Suricata para monitorar o tráfego na interface `br0`.
- **CrowdSec**: Instala e inicia o CrowdSec para análise de logs e proteção contra comportamentos maliciosos.
- **Fail2Ban**: Ativa o Fail2Ban com configurações padrão para prevenção de ataques de força bruta.
- **IPSet**: Cria uma lista de IPs maliciosos utilizando fontes confiáveis e aplica bloqueios via iptables.
- **QoS**: Configura QoS utilizando `tc` e `iptables` para priorizar tráfego de jogos, streaming e downloads.
- **Squid**: Instala e ativa o Squid com configurações básicas de cache.
- **Persistência de Regras**: Salva as regras do iptables para aplicação automática em reinicializações.

---

## 📦 Requisitos

- Sistema operacional baseado em Debian (ex: Ubuntu).
- Acesso root ou permissões de superusuário.
- Interfaces de rede: `enp6s18` e `enp6s19`.

---

## 🛠️ Instalação

1. Clone este repositório:

    ```bash
    git clone https://github.com/seuusuario/ids-setup.git
    cd ids-setup
    ```

2. Torne o script executável:

    ```bash
    chmod +x ids-setup.sh
    ```

3. Execute o script:

    ```bash
    sudo ./ids-setup.sh
    ```

    O script criará um log detalhado em `/var/log/ids-setup.log`.

---

## 🧪 Verificação

Após a execução do script, verifique se os serviços estão ativos:

```bash
systemctl status suricata
systemctl status crowdsec
systemctl status fail2ban
systemctl status squid
systemctl status netfilter-persistent
```

Verifique as regras do iptables:

```bash
iptables -L -v
iptables -t mangle -L -v
```

Verifique a bridge de rede:

```bash
brctl show
ip addr show br0
```

---

## 📄 Licença

Este projeto está licenciado sob a [MIT License](LICENSE).

---
