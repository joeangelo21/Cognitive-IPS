# Projeto_Seguran-a_Com_IA
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
