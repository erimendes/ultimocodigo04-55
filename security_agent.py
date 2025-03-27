import os
import json
import streamlit as st
from datetime import datetime
from typing import Dict
import time
import threading
import random
import subprocess
import platform

class SecurityAgent:
    """Classe principal de agente de segurança que coordena ações de defesa"""
    
    def __init__(self, config, logger, threat_intel, notification_system):
        self.config = config
        self.logger = logger
        self.threat_intel = threat_intel
        self.notification_system = notification_system
        
        # Inicializar conjunto de IPs bloqueados na sessão
        if "blocked_ips" not in st.session_state:
            st.session_state.blocked_ips = set()
            
        # Inicializar conjunto de IPs em monitoramento na sessão
        if "monitored_ips" not in st.session_state:
            st.session_state.monitored_ips = set()
            
        # Inicializar estatísticas de ameaças
        if "threat_stats" not in st.session_state:
            st.session_state.threat_stats = {
                "high": 0,
                "medium": 0,
                "low": 0
            }
        
        self._last_analysis_time = 0
        self._analysis_lock = threading.Lock()
    
    def analyze_threat(self, threat_data):
        """Analisa uma ameaça detectada e toma ações apropriadas"""
        try:
            # Obter o IP da ameaça
            threat_ip = threat_data.get("ip", "desconhecido")
            
            # Verificar se o IP já está bloqueado
            if threat_ip in st.session_state.blocked_ips:
                self.logger.log_activity(f"IP {threat_ip} já está bloqueado. Ignorando nova ameaça.", "warning")
                return
            
            # Verificar se o IP já está em monitoramento
            if threat_ip in st.session_state.monitored_ips:
                self.logger.log_activity(f"IP {threat_ip} já está em monitoramento. Atualizando dados.", "warning")
            
            # Log da análise
            self.logger.log_activity(f"⚠️ Analisando ameaça do IP: {threat_ip}", "warning")
            
            # Simular processo de análise
            time.sleep(0.5)  # Simular processamento
            
            # Determinar nível de ameaça final baseado em diversos fatores
            if "risk_level" in threat_data:
                risk_level = threat_data["risk_level"]
            else:
                # Usar classificador de ML simulado para determinar o risco
                risk_level = self._classify_threat(threat_data)
            
            # Incrementar estatísticas
            if risk_level in st.session_state.threat_stats:
                st.session_state.threat_stats[risk_level] += 1
            
            # Tomar ação com base no nível de risco
            if risk_level == "high":
                # Para ameaças de alto risco, bloquear automaticamente
                self.block_ip(threat_ip)
                threat_level = "ALTO"
                self.logger.log_activity(f"🔒 Análise concluída. Nível de ameaça: {threat_level}", "error")
                
                # Notificar (simulado)
                notification_text = f"Alerta de Segurança: IP {threat_ip} bloqueado automaticamente (Ameaça de alto risco)"
                self.notification_system.send_notification(notification_text, "alta")
                
            elif risk_level == "medium":
                # Para ameaças de médio risco, adicionar ao monitoramento
                self.monitor_ip(threat_ip)
                threat_level = "MÉDIO"
                self.logger.log_activity(f"🔍 Análise concluída. Nível de ameaça: {threat_level}", "warning")
                self.logger.log_activity(f"👁️ IP {threat_ip} adicionado ao monitoramento contínuo", "warning")
                
                # Notificar (simulado)
                notification_text = f"Alerta de Segurança: IP {threat_ip} colocado em monitoramento (Ameaça de risco médio)"
                self.notification_system.send_notification(notification_text, "média")
                
            else:
                # Para ameaças de baixo risco, apenas registrar
                threat_level = "BAIXO"
                self.logger.log_activity(f"🔒 Análise concluída. Nível de ameaça: {threat_level}", "info")
            
            return threat_level
            
        except Exception as e:
            self.logger.log_activity(f"Erro ao analisar ameaça: {str(e)}", "error")
            return None
            
    def monitor_ip(self, ip):
        """Adiciona um IP ao monitoramento contínuo"""
        if ip in st.session_state.monitored_ips:
            self.logger.log_activity(f"IP {ip} já está em monitoramento", "info")
            return "já está em monitoramento"
            
        # Adicionar ao conjunto de IPs monitorados
        st.session_state.monitored_ips.add(ip)
        self.logger.log_activity(f"IP {ip} adicionado ao monitoramento contínuo", "warning")
        
        return "colocado em monitoramento"

    def _classify_threat(self, threat_data):
        """Classifica o nível de ameaça com base nos dados recebidos"""
        # Garantir que as chances de cada nível sejam iguais (33% cada)
        # Este classificador simulado ignora o risk_level inicial da threat_data
        # para garantir uma distribuição igual entre os três níveis
        rand_val = random.random()
        if rand_val < 0.33:
            return "high"
        elif rand_val < 0.66:
            return "medium"
        else:
            return "low"
    
    def block_ip(self, ip):
        """Bloqueia um IP na lista negra
        
        Args:
            ip (str): Endereço IP a ser bloqueado
        """
        # Verificar se o IP já está bloqueado
        if ip in st.session_state.blocked_ips:
            self.logger.log_activity(f"IP {ip} já está bloqueado", 'info')
            return "já está bloqueado"
            
        # Registrar ação
        self.logger.log_activity(f"🛡️ Bloqueando IP malicioso: {ip}", 'success')
        
        # Adicionar ao conjunto de IPs bloqueados
        st.session_state.blocked_ips.add(ip)
        
        # Implementar bloqueio real com base no sistema operacional
        success = self._real_ip_block(ip)
        
        if success:
            self.logger.log_activity(f"✅ IP {ip} bloqueado com sucesso no firewall", 'success')
            return "bloqueado com sucesso"
        else:
            self.logger.log_activity(f"⚠️ Bloqueio do IP {ip} registrado apenas no sistema (falha no firewall)", 'warning')
            return "registrado apenas no sistema"
            
    def _real_ip_block(self, ip):
        """Implementa o bloqueio real do IP no sistema operacional
        
        Args:
            ip (str): Endereço IP a ser bloqueado
            
        Returns:
            bool: True se o bloqueio for bem-sucedido, False caso contrário
        """
        try:
            system = platform.system().lower()
            
            if system == "windows":
                # Bloqueio no Windows Firewall
                rule_name = f"BlockIP-{ip.replace('.', '-')}"
                
                # Verificar se a regra já existe
                check_command = f'netsh advfirewall firewall show rule name="{rule_name}"'
                result = subprocess.run(check_command, shell=True, capture_output=True, text=True)
                
                if "No rules match the specified criteria" not in result.stdout:
                    # Regra já existe
                    return True
                
                # Criar regra para bloquear o IP
                command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in interface=any action=block remoteip={ip}'
                subprocess.run(command, shell=True, check=True)
                
                # Criar regra para tráfego de saída também
                command_out = f'netsh advfirewall firewall add rule name="{rule_name}-out" dir=out interface=any action=block remoteip={ip}'
                subprocess.run(command_out, shell=True, check=True)
                
                return True
                
            elif system == "linux":
                # Bloqueio com iptables no Linux
                # Verificar se o IP já está bloqueado
                check_command = f"sudo iptables -C INPUT -s {ip} -j DROP"
                result = subprocess.run(check_command, shell=True, capture_output=True)
                
                if result.returncode != 0:
                    # IP não está bloqueado, adicionar regra
                    command = f"sudo iptables -A INPUT -s {ip} -j DROP"
                    subprocess.run(command, shell=True, check=True)
                    
                    # Bloquear tráfego de saída também
                    command_out = f"sudo iptables -A OUTPUT -d {ip} -j DROP"
                    subprocess.run(command_out, shell=True, check=True)
                
                return True
                
            else:
                # Sistema não suportado
                self.logger.log_activity(f"Sistema operacional {system} não suportado para bloqueio real", 'error')
                return False
                
        except Exception as e:
            self.logger.log_activity(f"Erro ao bloquear IP {ip} no firewall: {str(e)}", 'error')
            return False
            
    def unblock_ip(self, ip):
        """Remove um IP da lista negra
        
        Args:
            ip (str): Endereço IP a ser desbloqueado
        """
        # Verificar se o IP está bloqueado
        if ip not in st.session_state.blocked_ips:
            self.logger.log_activity(f"IP {ip} não está bloqueado", 'info')
            return "não estava bloqueado"
            
        # Remover do conjunto de IPs bloqueados
        st.session_state.blocked_ips.remove(ip)
        
        # Implementar desbloqueio real
        success = self._real_ip_unblock(ip)
        
        # Registrar ação
        if success:
            self.logger.log_activity(f"✅ IP {ip} desbloqueado com sucesso", 'success')
            return "desbloqueado com sucesso"
        else:
            self.logger.log_activity(f"⚠️ IP {ip} removido apenas do sistema (falha no firewall)", 'warning')
            return "removido apenas do sistema"
            
    def _real_ip_unblock(self, ip):
        """Remove o bloqueio real do IP no sistema operacional
        
        Args:
            ip (str): Endereço IP a ser desbloqueado
            
        Returns:
            bool: True se o desbloqueio for bem-sucedido, False caso contrário
        """
        try:
            system = platform.system().lower()
            
            if system == "windows":
                # Desbloqueio no Windows Firewall
                rule_name = f"BlockIP-{ip.replace('.', '-')}"
                
                # Remover regra de entrada
                command = f'netsh advfirewall firewall delete rule name="{rule_name}"'
                subprocess.run(command, shell=True, check=True)
                
                # Remover regra de saída
                command_out = f'netsh advfirewall firewall delete rule name="{rule_name}-out"'
                subprocess.run(command_out, shell=True, check=True)
                
                return True
                
            elif system == "linux":
                # Desbloqueio com iptables no Linux
                command = f"sudo iptables -D INPUT -s {ip} -j DROP"
                subprocess.run(command, shell=True, check=True)
                
                # Remover regra de saída
                command_out = f"sudo iptables -D OUTPUT -d {ip} -j DROP"
                subprocess.run(command_out, shell=True, check=True)
                
                return True
                
            else:
                # Sistema não suportado
                self.logger.log_activity(f"Sistema operacional {system} não suportado para desbloqueio real", 'error')
                return False
                
        except Exception as e:
            self.logger.log_activity(f"Erro ao desbloquear IP {ip} no firewall: {str(e)}", 'error')
            return False 