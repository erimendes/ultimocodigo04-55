# Agente Autônomo de Segurança Cibernética

Um sistema de monitoramento de segurança cibernética com agente autônomo baseado em IA que detecta, analisa e responde a ameaças em tempo real.

## Arquitetura

O sistema foi implementado usando arquitetura modular orientada a objetos, dividido nos seguintes componentes:

- **Config**: Gerencia todas as configurações e chaves de API
- **SecurityLogger**: Sistema de logs com rotação de arquivos
- **ThreatIntelligence**: Análise de ameaças usando múltiplas fontes (VirusTotal, AbuseIPDB)
- **NetworkMonitor**: Monitoramento de pacotes de rede usando Scapy
- **SecurityAgent**: Agente de segurança com workflow de decisão usando LangGraph
- **NotificationSystem**: Sistema de notificações para alertas (Telegram, Discord)
- **SecurityUI**: Interface do usuário construída com Streamlit

## Requisitos

- Python 3.8+
- Streamlit
- Scapy
- LangChain
- LangGraph
- Plotly
- Requests

## Instalação

```bash
pip install -r requirements.txt
```

## Uso

Execute o aplicativo Streamlit:

```bash
streamlit run ultima.py
```

## Funcionalidades

- Monitoramento de tráfego de rede em tempo real
- Análise de ameaças com base em inteligência (VirusTotal, AbuseIPDB)
- Bloqueio automático de IPs maliciosos
- Interface gráfica para visualização de ameaças e logs
- Alertas em tempo real para ameaças graves (Telegram, Discord)
- Botão de teste para facilitar a demonstração

## Estrutura do Projeto

```
.
├── ultima.py                # Arquivo principal
├── security_monitor/        # Pacote principal
│   ├── __init__.py          # Inicializador do pacote
│   ├── config.py            # Configurações e variáveis de ambiente
│   ├── logger.py            # Sistema de logs
│   ├── threat_intelligence.py # Análise de inteligência de ameaças
│   ├── network_monitor.py   # Monitoramento de rede
│   ├── security_agent.py    # Agente de segurança autônomo
│   ├── notification.py      # Sistema de notificações
│   └── ui.py                # Interface Streamlit
└── logs/                    # Diretório de logs (criado automaticamente)
```

## Como Testar

1. Inicie a aplicação
2. Clique em "Iniciar Monitoramento"
3. Use o botão "Gerar Tráfego de Teste" para simular tráfego
4. Observe os logs em tempo real
5. Consulte a inteligência de ameaças usando o campo de busca de IP 