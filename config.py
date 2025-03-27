import os
import streamlit as st

class Config:
    """Classe para gerenciar todas as configurações do sistema"""
    
    def __init__(self):
        # Configurar chaves de API
        self._set_environment_variables()
        self._load_api_keys()
        
    def _set_environment_variables(self):
        """Define as variáveis de ambiente com as chaves de API"""
        os.environ["VT_API_KEY"] = "465392e355f68039e47c72ce731b82fbc4459d3903813530cab0214af927f4f3"
        os.environ["ABUSE_IPDB_KEY"] = "356676efec9ac05ed7bbde67d84325da5009fab0267ada0ef296a2acafe728420d3f171ab37dd54d"
        os.environ["TELEGRAM_BOT_TOKEN"] = "7850300754:AAFlB_0ugzCtHnLmqar6l5a5VnRxziGNaxo"
        os.environ["TELEGRAM_CHAT_ID"] = "7111234268"
        os.environ["DISCORD_WEBHOOK"] = "https://discord.com/api/webhooks/1353428276168753354/Y7rRG42HsMDBlB59LV4hX8j3v_k2kOfH6a2ZToqpV7bSoSH79Bhv_RcV2hUrf2Y_SSrH"
        os.environ["OPENAI_API_KEY"] = "sk-proj-0123456789abcdef0123456789abcdef"
    
    def _load_api_keys(self):
        """Carrega as chaves de API das variáveis de ambiente"""
        self.vt_api_key = os.getenv("VT_API_KEY")
        self.abuse_ipdb_key = os.getenv("ABUSE_IPDB_KEY")
        self.telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
        self.telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID")
        self.discord_webhook = os.getenv("DISCORD_WEBHOOK")
        self.openai_api_key = os.getenv("OPENAI_API_KEY") 