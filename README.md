SegurancaComIA (Motor Cognitivo)
O SegurancaComIA é um ecossistema de defesa cibernética de alta performance, projetado para monitoramento, análise semântica de tráfego e resposta ativa a incidentes. Diferente de sistemas tradicionais, ele utiliza inteligência artificial local para classificar payloads em tempo real.

🏗️ Arquitetura de Defesa em Camadas
O sistema opera através de dois módulos integrados:

Camada 1 (Sensor/Sentinela): Implementada em monitor_network.py. Realiza a captura bruta de pacotes via Scapy, filtragem de tráfego e geração de telemetria persistente.

Camada 2 (Cérebro/Motor Cognitivo): Implementada em auditoria.py. Consome os logs do Sentinela, analisa o contexto do payload através de modelos de IA (via Ollama) e executa bloqueios automáticos via iptables.

🚀 Funcionalidades Principais
Análise Semântica: Uso de LLMs (Qwen2.5) para identificar padrões de ataque que filtros de rede comuns ignorariam.

Resposta Ativa (Active Defense): Integração direta com o netfilter (iptables) para banimento automático.

Performance: Arquitetura desacoplada que não bloqueia o fluxo de rede enquanto processa a inferência da IA.

Dashboard em Tempo Real: Monitoramento visual de temperatura de GPU, volume de tráfego e mural de vereditos de segurança.

🛠️ Como rodar o ecossistema
Inicie o Sensor:

Bash
sudo python3 monitor_network.py
Inicie o Motor Cognitivo:

Bash
sudo python3 auditoria.py
🛡️ Aviso Legal
Este software é uma ferramenta experimental de defesa. O uso de automação de iptables requer privilégios de root e deve ser configurado cuidadosamente para evitar o bloqueio de serviços essenciais.

✒️ Autor
Joelson Angelo - Ethical Hacker | Python Developer# Projeto_Seguran-a_Com_IA
Projeto de Segurança e IPS com IA local

# Motor Cognitivo IPS

O **Motor Cognitivo IPS** é uma ferramenta de monitoramento de rede e prevenção de intrusão (IPS) que utiliza Inteligência Artificial Local para classificar tráfego e detectar anomalias em tempo real.

## 🛠️ Tecnologias e Dependências

Para rodar este projeto, você precisará do Python 3 instalado no sistema. As dependências necessárias são:

- `requests`: Para comunicação com a API local do Ollama.
- `ollama`: (Opcional, se desejar controlar o modelo via Python).
- `tkinter`: (Geralmente incluído no Python, para interfaces).

## 🚀 Como Instalar

### 1. Clonar o Repositório
```bash
git clone git@github.com:joeangelo21/SegurancaComIA.git
cd SegurancaComIA
2. Instalar Bibliotecas
Instale as dependências via pip:

Bash
pip install requests
3. Configuração do Modelo Local
Este projeto depende do Ollama rodando na sua máquina.

Instale o Ollama em ollama.com.

Puxe o modelo utilizado pelo script:

Bash
ollama run qwen2.5:3b
🛡️ Como Executar
O script monitora arquivos de log em tempo real e utiliza o iptables para bloqueios. Por isso, a execução requer privilégios de superusuário:

Bash
sudo python3 auditoria.py
⚠️ Aviso de Segurança
Esta é uma ferramenta de pesquisa em segurança da informação. O uso de iptables para bloquear IPs pode causar negação de serviço a si mesmo caso não seja configurado corretamente. Certifique-se de manter sua rede local na WHITELIST dentro do arquivo auditoria.py.

Desenvolvido por Jose Joelson Angelo de Sousa Filho.

Sentinela: Detector de Ameaças com IA
Como funciona
O Sentinela realiza a varredura contínua da rede em busca de atividade suspeita.

Ao detectar um tráfego anômalo, o Sentinela extrai o IP e envia para análise minuciosa da IA Local.

Se a IA confirmar a intenção maliciosa, o Sentinela executa a regra de bloqueio automaticamente.

Requisitos
Python 3.x

Bibliotecas: (liste aqui as bibliotecas que você usa, ex: scapy, ollama, etc)

Sistema: Privilégios de root (necessário para manipulação de pacotes e iptables)
