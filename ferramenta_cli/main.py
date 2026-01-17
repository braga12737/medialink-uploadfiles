
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP Logger Pro - Ferramenta Avançada por Braga Developer
Servidor: https://medialink-uploads.vercel.app
"""

import requests
import json
import time
import os
import socket
import subprocess
import platform
from datetime import datetime
import sys
import ipaddress
import whois
import dns.resolver
import geoip2.database
from colorama import init, Fore, Back, Style
import threading
from queue import Queue
import concurrent.futures

init(autoreset=True)

BASE_URL = "https://medialink-uploads.vercel.app"
SENHA_ADMIN = "2311"

class IPLoggerPro:
    def __init__(self):
        self.sessao = requests.Session()
        self.sessao.headers.update({
            'User-Agent': 'BragaDeveloperPro/2.0',
            'Accept': 'application/json'
        })
        self.link_ativo = None
        self.id_ativo = None
        self.arquivo_log = None
        self.arquivo_json = None
        self.ips_coletados = {}
        self.total_visitas = 0
        self.coleta_ativa = True
        self.monitorando = False
        
        try:
            self.geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        except:
            self.geoip_reader = None
    
    def limpar_tela(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def cabecalho(self):
        self.limpar_tela()
        print(Fore.CYAN + "=" * 80)
        print(Fore.YELLOW + Style.BRIGHT + "IP LOGGER PRO - BRAGA DEVELOPER")
        print(Fore.CYAN + "=" * 80)
        print(Fore.MAGENTA + "COLETA AVANÇADA DE INFORMAÇÕES DE REDE E HARDWARE")
        print(Fore.CYAN + "-" * 80)
        print()
    
    def mostrar_menu(self):
        self.cabecalho()
        print(Fore.GREEN + Style.BRIGHT + "MENU PRINCIPAL")
        print(Fore.CYAN + "-" * 40)
        print(Fore.WHITE + Style.BRIGHT + "[1] " + Fore.YELLOW + "GERAR NOVO LINK E MONITORAR")
        print(Fore.WHITE + Style.BRIGHT + "[2] " + Fore.CYAN + "MONITORAR LINK EXISTENTE")
        print(Fore.WHITE + Style.BRIGHT + "[0] " + Fore.RED + "SAIR")
        print(Fore.CYAN + "-" * 40)
        print()
    
    def aguardar_enter(self):
        input(Fore.WHITE + Style.DIM + "Pressione " + Fore.YELLOW + "ENTER" + Fore.WHITE + Style.DIM + " para continuar...")
    
    def verificar_conexao(self):
        try:
            resposta = self.sessao.get(f"{BASE_URL}/gerar/{SENHA_ADMIN}", timeout=5)
            return resposta.status_code in [200, 403]
        except:
            return False
    
    def coletar_dns_externo(self, ip):
        resultados = {
            'dns_reverso': 'Nao disponivel',
            'dns_resolvido': [],
            'mx_records': [],
            'txt_records': []
        }
        
        try:
            try:
                hostname, aliases, _ = socket.gethostbyaddr(ip)
                resultados['dns_reverso'] = hostname
            except:
                pass
            
            if resultados['dns_reverso'] != 'Nao disponivel':
                dominio = resultados['dns_reverso']
                
                try:
                    resp_a = dns.resolver.resolve(dominio, 'A')
                    resultados['dns_resolvido'] = [str(r) for r in resp_a]
                except:
                    pass
                
                try:
                    resp_mx = dns.resolver.resolve(dominio, 'MX')
                    resultados['mx_records'] = [str(r.exchange) for r in resp_mx]
                except:
                    pass
                
                try:
                    resp_txt = dns.resolver.resolve(dominio, 'TXT')
                    resultados['txt_records'] = [''.join(r.strings) for r in resp_txt]
                except:
                    pass
        
        except Exception as e:
            pass
        
        return resultados
    
    def verificar_portas(self, ip, portas=[80, 443, 22, 21, 25, 53, 3389, 8080, 8443]):
        portas_abertas = []
        
        def verificar_porta(porta):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                resultado = sock.connect_ex((ip, porta))
                sock.close()
                return porta if resultado == 0 else None
            except:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(verificar_porta, porta) for porta in portas]
            for future in concurrent.futures.as_completed(futures):
                resultado = future.result()
                if resultado:
                    portas_abertas.append(resultado)
        
        return sorted(portas_abertas)
    
    def coletar_info_whois(self, ip):
        info = {
            'registro': 'Nao disponivel',
            'rede': 'Nao disponivel',
            'cidr': 'Nao disponivel',
            'pais': 'Nao disponivel',
            'criado': 'Nao disponivel'
        }
        
        try:
            w = whois.whois(ip)
            
            if w.get('nets'):
                net_info = w['nets'][0]
                info['registro'] = net_info.get('description', 'Nao disponivel')
                info['rede'] = net_info.get('name', 'Nao disponivel')
                info['cidr'] = net_info.get('cidr', 'Nao disponivel')
                info['pais'] = net_info.get('country', 'Nao disponivel')
                info['criado'] = net_info.get('created', 'Nao disponivel')
        
        except Exception as e:
            pass
        
        return info
    
    def analisar_ip(self, ip):
        info = {
            'tipo': 'Desconhecido',
            'publico': False,
            'reservado': False,
            'multicast': False,
            'local': False
        }
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            info['tipo'] = 'IPv6' if ip_obj.version == 6 else 'IPv4'
            info['publico'] = ip_obj.is_global
            info['privado'] = ip_obj.is_private
            info['reservado'] = ip_obj.is_reserved
            info['multicast'] = ip_obj.is_multicast
            info['local'] = ip_obj.is_loopback or ip_obj.is_link_local
            
            if info['privado']:
                info['faixa'] = 'Rede Privada'
            elif info['publico']:
                info['faixa'] = 'Rede Publica'
            elif info['reservado']:
                info['faixa'] = 'Reservado IANA'
        
        except:
            pass
        
        return info
    
    def coletar_geolocalizacao_local(self, ip):
        geo = {
            'cidade': 'Nao disponivel',
            'pais': 'Nao disponivel',
            'latitude': 'Nao disponivel',
            'longitude': 'Nao disponivel'
        }
        
        if self.geoip_reader:
            try:
                resposta = self.geoip_reader.city(ip)
                geo['cidade'] = resposta.city.name or 'Nao disponivel'
                geo['pais'] = resposta.country.name or 'Nao disponivel'
                geo['latitude'] = resposta.location.latitude
                geo['longitude'] = resposta.location.longitude
            except:
                pass
        
        return geo
    
    def calcular_risco(self, dados):
        pontuacao = 0
        flags = []
        
        if dados.get('proxy') or dados.get('vpn'):
            pontuacao += 30
            flags.append('Proxy/VPN')
        
        if dados.get('hospedagem'):
            pontuacao += 20
            flags.append('Data Center')
        
        if len(dados.get('portas_abertas', [])) > 5:
            pontuacao += 15
            flags.append('Muitas portas')
        
        if dados.get('ip_info', {}).get('reservado') or dados.get('ip_info', {}).get('multicast'):
            pontuacao += 10
            flags.append('IP Especial')
        
        if dados.get('movel'):
            pontuacao -= 5
            flags.append('Movel')
        
        if pontuacao >= 40:
            return 'ALTO', pontuacao, flags
        elif pontuacao >= 20:
            return 'MEDIO', pontuacao, flags
        else:
            return 'BAIXO', pontuacao, flags
    
    def mostrar_info_link(self, link_principal, link_monitor, link_dados):
        self.cabecalho()
        print(Fore.GREEN + Style.BRIGHT + "LINK GERADO COM SUCESSO")
        print(Fore.CYAN + "-" * 80)
        print()
        
        print(Fore.WHITE + Style.BRIGHT + "LINK PARA ENVIAR A PESSOA:")
        print(Fore.YELLOW + Style.BRIGHT + f"  {link_principal}")
        print()
        
        print(Fore.WHITE + Style.BRIGHT + "PAINEL WEB PARA VISUALIZACAO:")
        print(Fore.MAGENTA + f"  {link_monitor}")
        print()
        
        print(Fore.WHITE + Style.BRIGHT + "API DOS DADOS (JSON):")
        print(Fore.CYAN + f"  {link_dados}")
        print()
        
        print(Fore.CYAN + "-" * 80)
        print(Fore.WHITE + f"ID do Link: " + Fore.YELLOW + self.id_ativo)
        print(Fore.WHITE + f"Arquivo de Log: " + Fore.GREEN + self.arquivo_log)
        print(Fore.WHITE + f"Arquivo JSON: " + Fore.MAGENTA + self.arquivo_json)
        print(Fore.CYAN + "-" * 80)
        print()
    
    def exibir_visita_detalhada(self, visita):
        rede = visita.get('rede', {})
        cliente = visita.get('cliente', {})
        geo_api = rede.get('geolocalizacao', {})
        
        ip = rede.get('ip', 'DESCONHECIDO')
        hora_atual = datetime.now().strftime('%H:%M:%S')
        data_completa = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
        
        print(Fore.CYAN + "=" * 80)
        print(Fore.YELLOW + Style.BRIGHT + f"NOVO ACESSO DETECTADO - {hora_atual}")
        print(Fore.CYAN + "=" * 80)
        print()
        
        print(Fore.MAGENTA + Style.BRIGHT + "INFORMACOES BASICAS")
        print(Fore.CYAN + "-" * 40)
        print(Fore.WHITE + "ID da Visita: " + Fore.CYAN + visita.get('id', 'N/A'))
        print(Fore.WHITE + "Data/Hora: " + Fore.GREEN + data_completa)
        print(Fore.WHITE + "IP: " + Fore.RED + Style.BRIGHT + ip)
        print(Fore.WHITE + "Versao IP: " + Fore.YELLOW + rede.get('versao', 'N/A'))
        print()
        
        info_ip = self.analisar_ip(ip)
        dns_info = self.coletar_dns_externo(ip)
        whois_info = self.coletar_info_whois(ip)
        portas = self.verificar_portas(ip)
        geo_local = self.coletar_geolocalizacao_local(ip)
        
        print(Fore.MAGENTA + Style.BRIGHT + "ANALISE DO IP")
        print(Fore.CYAN + "-" * 40)
        print(Fore.WHITE + "Tipo: " + Fore.CYAN + info_ip.get('tipo', 'N/A'))
        print(Fore.WHITE + "Publico: " + Fore.GREEN + ("Sim" if info_ip.get('publico') else "Nao"))
        print(Fore.WHITE + "Privado: " + Fore.GREEN + ("Sim" if info_ip.get('privado') else "Nao"))
        print(Fore.WHITE + "Faixa: " + Fore.YELLOW + info_ip.get('faixa', 'N/A'))
        
        dns_reverso = rede.get('dnsReverso') or dns_info.get('dns_reverso')
        if dns_reverso and dns_reverso != 'Nao disponivel':
            print(Fore.WHITE + "DNS Reverso: " + Fore.MAGENTA + dns_reverso)
        print()
        
        print(Fore.MAGENTA + Style.BRIGHT + "LOCALIZACAO GEOGRAFICA")
        print(Fore.CYAN + "-" * 40)
        
        cidade = geo_api.get('cidade') or geo_local.get('cidade')
        pais = geo_api.get('pais') or geo_local.get('pais')
        regiao = geo_api.get('regiao') or geo_api.get('nomeRegiao')
        isp = geo_api.get('isp') or geo_api.get('organizacao')
        
        if cidade and cidade != 'Nao disponivel':
            print(Fore.WHITE + "Cidade: " + Fore.GREEN + cidade)
        if regiao:
            print(Fore.WHITE + "Regiao: " + Fore.GREEN + regiao)
        if pais:
            print(Fore.WHITE + "Pais: " + Fore.GREEN + pais)
        
        lat = geo_api.get('latitude') or geo_local.get('latitude')
        lon = geo_api.get('longitude') or geo_local.get('longitude')
        if lat and lon and lat != 'Nao disponivel':
            print(Fore.WHITE + "Coordenadas: " + Fore.YELLOW + f"{lat}, {lon}")
        
        if isp:
            print(Fore.WHITE + "Provedor (ISP): " + Fore.CYAN + isp)
        
        as_num = geo_api.get('as')
        if as_num:
            print(Fore.WHITE + "AS Number: " + Fore.MAGENTA + as_num)
        print()
        
        print(Fore.MAGENTA + Style.BRIGHT + "INFORMACOES DO CLIENTE")
        print(Fore.CYAN + "-" * 40)
        
        dispositivo = cliente.get('dispositivo', 'Desconhecido')
        sistema = cliente.get('sistemaOperacional', 'Desconhecido')
        navegador = cliente.get('navegador', 'Desconhecido')
        
        print(Fore.WHITE + "Dispositivo: " + Fore.CYAN + dispositivo)
        print(Fore.WHITE + "Sistema: " + Fore.CYAN + sistema)
        print(Fore.WHITE + "Navegador: " + Fore.CYAN + navegador)
        
        hardware = cliente.get('detalhesHardware', {})
        if hardware:
            print(Fore.WHITE + "Hardware Detectado:")
            tela = hardware.get('tela', {})
            if tela.get('largura') and tela.get('altura'):
                print(Fore.WHITE + "  Resolucao: " + Fore.YELLOW + f"{tela['largura']}x{tela['altura']}")
            
            if hardware.get('gpu') and hardware['gpu'] not in ['n/a', 'erro']:
                gpu = hardware['gpu']
                if len(gpu) > 40:
                    gpu = gpu[:37] + "..."
                print(Fore.WHITE + "  GPU: " + Fore.MAGENTA + gpu)
            
            if hardware.get('nucleos'):
                print(Fore.WHITE + "  Nucleos CPU: " + Fore.GREEN + str(hardware['nucleos']))
            
            if hardware.get('memoria'):
                print(Fore.WHITE + "  Memoria: " + Fore.GREEN + f"{hardware['memoria']} GB")
        print()
        
        print(Fore.MAGENTA + Style.BRIGHT + "DETECCOES DE SEGURANCA")
        print(Fore.CYAN + "-" * 40)
        
        flags_seguranca = []
        
        if geo_api.get('proxy'):
            print(Fore.RED + Style.BRIGHT + "PROXY/VPN DETECTADO")
            flags_seguranca.append('Proxy/VPN')
        
        if geo_api.get('hospedagem'):
            print(Fore.RED + Style.BRIGHT + "SERVIDOR/DATA CENTER")
            flags_seguranca.append('Data Center')
        
        if geo_api.get('movel'):
            print(Fore.BLUE + "CONEXAO MOVEL DETECTADA")
            flags_seguranca.append('Conexao Movel')
        
        if portas:
            print(Fore.YELLOW + f"PORTAS ABERTAS ({len(portas)}): " + Fore.WHITE + ', '.join(map(str, portas[:10])))
            if len(portas) > 10:
                print(Fore.WHITE + f"  ... e mais {len(portas) - 10} portas")
            flags_seguranca.append(f'{len(portas)} portas abertas')
        
        if whois_info.get('registro') != 'Nao disponivel':
            print(Fore.CYAN + "WHOIS: " + Fore.WHITE + whois_info.get('registro', '')[:50] + "...")
        print()
        
        print(Fore.MAGENTA + Style.BRIGHT + "ANALISE DE RISCO")
        print(Fore.CYAN + "-" * 40)
        
        dados_risco = {
            'proxy': geo_api.get('proxy', False),
            'vpn': geo_api.get('proxy', False),
            'hospedagem': geo_api.get('hospedagem', False),
            'movel': geo_api.get('movel', False),
            'portas_abertas': portas,
            'ip_info': info_ip
        }
        
        nivel_risco, pontuacao, flags_risco = self.calcular_risco(dados_risco)
        
        print(Fore.WHITE + "Nivel de Risco: ", end="")
        if "ALTO" in nivel_risco:
            print(Fore.RED + Style.BRIGHT + nivel_risco)
        elif "MEDIO" in nivel_risco:
            print(Fore.YELLOW + Style.BRIGHT + nivel_risco)
        else:
            print(Fore.GREEN + Style.BRIGHT + nivel_risco)
        
        print(Fore.WHITE + f"Pontuacao: {pontuacao}/100")
        if flags_risco:
            print(Fore.WHITE + "Flags: " + Fore.CYAN + ', '.join(flags_risco))
        
        print(Fore.CYAN + "-" * 80)
        
        dados_extras = {
            'info_ip': info_ip,
            'dns_info': dns_info,
            'whois_info': whois_info,
            'portas_abertas': portas,
            'geo_local': geo_local,
            'analise_risco': {
                'nivel': nivel_risco,
                'pontuacao': pontuacao,
                'flags': flags_risco
            }
        }
        
        self.salvar_log_completo(visita, dados_extras)
        time.sleep(1)
    
    def salvar_log_completo(self, visita, dados_extras):
        if not self.arquivo_log:
            return
        
        timestamp = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
        
        with open(self.arquivo_log, 'a', encoding='utf-8') as f:
            f.write(f"\n{'='*100}\n")
            f.write(f"NOVO ACESSO - {timestamp}\n")
            f.write(f"{'='*100}\n\n")
            
            f.write("INFORMACOES BASICAS:\n")
            f.write(f"  ID: {visita.get('id', 'N/A')}\n")
            f.write(f"  IP: {visita.get('rede', {}).get('ip', 'N/A')}\n")
            f.write(f"  Data/Hora: {timestamp}\n\n")
            
            f.write("LOCALIZACAO:\n")
            geo = visita.get('rede', {}).get('geolocalizacao', {})
            if geo:
                if geo.get('cidade'):
                    f.write(f"  Cidade: {geo['cidade']}\n")
                if geo.get('pais'):
                    f.write(f"  Pais: {geo['pais']}\n")
                if geo.get('isp'):
                    f.write(f"  ISP: {geo['isp']}\n")
                if geo.get('latitude') and geo.get('longitude'):
                    f.write(f"  Coordenadas: {geo['latitude']}, {geo['longitude']}\n")
            
            f.write("\nCLIENTE:\n")
            cliente = visita.get('cliente', {})
            f.write(f"  Dispositivo: {cliente.get('dispositivo', 'N/A')}\n")
            f.write(f"  Sistema: {cliente.get('sistemaOperacional', 'N/A')}\n")
            f.write(f"  Navegador: {cliente.get('navegador', 'N/A')}\n")
            
            f.write("\nDETECCOES:\n")
            if geo.get('proxy'):
                f.write("  [ALERTA] Proxy/VPN Detectado\n")
            if geo.get('hospedagem'):
                f.write("  [ALERTA] Data Center/Server\n")
            
            f.write("\nINFOS AVANCADAS:\n")
            f.write(f"  Tipo IP: {dados_extras['info_ip'].get('tipo', 'N/A')}\n")
            f.write(f"  Publico: {'Sim' if dados_extras['info_ip'].get('publico') else 'Nao'}\n")
            
            if dados_extras['dns_info']['dns_reverso'] != 'Nao disponivel':
                f.write(f"  DNS Reverso: {dados_extras['dns_info']['dns_reverso']}\n")
            
            if dados_extras['portas_abertas']:
                f.write(f"  Portas Abertas: {', '.join(map(str, dados_extras['portas_abertas']))}\n")
            
            f.write(f"\nANALISE DE RISCO: {dados_extras['analise_risco']['nivel']}\n")
            f.write(f"  Pontuacao: {dados_extras['analise_risco']['pontuacao']}/100\n")
            if dados_extras['analise_risco']['flags']:
                f.write(f"  Flags: {', '.join(dados_extras['analise_risco']['flags'])}\n")
            
            f.write(f"\n{'='*100}\n")
        
        if self.arquivo_json:
            try:
                dados_json = []
                if os.path.exists(self.arquivo_json):
                    with open(self.arquivo_json, 'r', encoding='utf-8') as jf:
                        dados_json = json.load(jf)
                
                visita_completa = {
                    **visita,
                    'coletas_avancadas': dados_extras,
                    'timestamp_log': timestamp
                }
                dados_json.append(visita_completa)
                
                with open(self.arquivo_json, 'w', encoding='utf-8') as jf:
                    json.dump(dados_json, jf, indent=2, ensure_ascii=False)
                    
            except Exception as e:
                pass
    
    def iniciar_monitoramento(self, mostrar_links=True):
        self.monitorando = True
        visitas_processadas = set()
        
        try:
            while self.monitorando:
                try:
                    url_status = f"{BASE_URL}/api/status/{self.id_ativo}"
                    resposta = self.sessao.get(url_status, timeout=10)
                    
                    if resposta.status_code == 200:
                        dados = resposta.json()
                        visitantes = dados.get('visitantes', [])
                        
                        novos_acessos = 0
                        for visita in visitantes:
                            visita_id = visita.get('id')
                            if visita_id and visita_id not in visitas_processadas:
                                self.exibir_visita_detalhada(visita)
                                visitas_processadas.add(visita_id)
                                novos_acessos += 1
                        
                        self.total_visitas = len(visitas_processadas)
                        
                        if novos_acessos == 0:
                            print(Fore.WHITE + f"Aguardando acessos... Total: {self.total_visitas} visitas", end='\r')
                    
                    elif resposta.status_code == 404:
                        print()
                        print(Fore.RED + "LINK EXPIRADO OU DELETADO")
                        break
                
                except requests.exceptions.RequestException:
                    print(Fore.RED + "Problema de conexao...", end='\r')
                
                time.sleep(3)
                
        except KeyboardInterrupt:
            self.monitorando = False
            return
    
    def gerar_e_monitorar(self):
        self.cabecalho()
        print(Fore.YELLOW + Style.BRIGHT + "GERANDO NOVO LINK E INICIANDO MONITORAMENTO")
        print(Fore.CYAN + "-" * 80)
        print()
        
        print(Fore.WHITE + "Verificando conexao com o servidor...")
        
        if not self.verificar_conexao():
            print(Fore.RED + Style.BRIGHT + "SERVIDOR INDISPONIVEL")
            print(Fore.WHITE + "Verifique sua internet ou se o servidor esta online.")
            print()
            self.aguardar_enter()
            return
        
        print(Fore.GREEN + "Conectado ao servidor")
        print(Fore.WHITE + "Gerando link unico...")
        
        try:
            url_geracao = f"{BASE_URL}/gerar/{SENHA_ADMIN}"
            resposta = self.sessao.get(url_geracao, timeout=15)
            
            if resposta.status_code == 200:
                dados = resposta.json()
                
                link_principal = dados.get('link', '')
                link_monitor = dados.get('monitor', '')
                link_dados = dados.get('dados', '')
                
                self.link_ativo = link_principal
                self.id_ativo = link_principal.split('/')[-1] if '/' in link_principal else None
                
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                self.arquivo_log = f"logs_detalhados_{self.id_ativo}_{timestamp}.txt"
                self.arquivo_json = f"dados_completos_{self.id_ativo}_{timestamp}.json"
                
                with open(self.arquivo_log, 'w', encoding='utf-8') as f:
                    f.write("=" * 100 + "\n")
                    f.write("IP LOGGER PRO - LOGS DETALHADOS\n")
                    f.write("Desenvolvido por Braga Developer\n")
                    f.write("=" * 100 + "\n")
                    f.write(f"Inicio: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
                    f.write(f"ID: {self.id_ativo}\n")
                    f.write(f"Link de rastreamento: {link_principal}\n")
                    f.write(f"Link do painel: {link_monitor}\n")
                    f.write(f"Link da API: {link_dados}\n")
                    f.write("=" * 100 + "\n\n")
                
                self.mostrar_info_link(link_principal, link_monitor, link_dados)
                print()
                print(Fore.YELLOW + "DICAS IMPORTANTES:")
                print(Fore.WHITE + "1. Compartilhe apenas o PRIMEIRO link (aparece em amarelo)")
                print(Fore.WHITE + "2. Use o segundo link para ver em seu navegador")
                print(Fore.WHITE + "3. Os dados aparecerao AQUI automaticamente")
                print(Fore.WHITE + "4. TUDO sera salvo nos arquivos mencionados acima")
                print()
                print(Fore.CYAN + "=" * 80)
                print()
                print(Fore.GREEN + "INICIANDO MONITORAMENTO AUTOMATICO...")
                print(Fore.WHITE + "Pressione CTRL+C para voltar ao menu")
                print(Fore.CYAN + "=" * 80)
                print()
                
                self.iniciar_monitoramento()
                
                print()
                print(Fore.YELLOW + "Monitoramento interrompido")
                print(Fore.WHITE + f"Total de acessos capturados: {self.total_visitas}")
                print()
                
            elif resposta.status_code == 403:
                print(Fore.RED + Style.BRIGHT + "ACESSO NEGADO")
                print(Fore.WHITE + "A senha do servidor pode ter mudado.")
            else:
                print(Fore.RED + Style.BRIGHT + f"ERRO: {resposta.status_code}")
                
        except Exception as erro:
            print(Fore.RED + Style.BRIGHT + f"ERRO DE CONEXAO: {str(erro)}")
        
        print()
        self.aguardar_enter()
    
    def monitorar_existente(self):
        if not self.id_ativo:
            self.cabecalho()
            print(Fore.YELLOW + Style.BRIGHT + "MONITORAR LINK EXISTENTE")
            print(Fore.CYAN + "-" * 80)
            print()
            
            id_input = input(Fore.WHITE + "Digite o ID do link (ou deixe em branco para usar ultimo): " + Fore.YELLOW).strip()
            
            if id_input:
                self.id_ativo = id_input
                self.arquivo_log = f"logs_monitoramento_{self.id_ativo}.txt"
                self.arquivo_json = f"dados_monitoramento_{self.id_ativo}.json"
            
            if not self.id_ativo:
                print(Fore.RED + "Nenhum ID fornecido")
                self.aguardar_enter()
                return
        
        self.cabecalho()
        print(Fore.YELLOW + Style.BRIGHT + "MONITORANDO LINK EXISTENTE")
        print(Fore.CYAN + "-" * 80)
        print()
        print(Fore.WHITE + f"ID do Link: " + Fore.YELLOW + self.id_ativo)
        
        if self.arquivo_log:
            print(Fore.WHITE + f"Arquivo de Log: " + Fore.GREEN + self.arquivo_log)
        if self.arquivo_json:
            print(Fore.WHITE + f"Arquivo JSON: " + Fore.MAGENTA + self.arquivo_json)
        
        print(Fore.CYAN + "-" * 80)
        print()
        print(Fore.GREEN + "Sistema de monitoramento ATIVADO")
        print(Fore.WHITE + "Aguardando alguem acessar o link...")
        print(Fore.YELLOW + "Pressione CTRL+C para voltar ao menu")
        print()
        
        self.iniciar_monitoramento(mostrar_links=False)
        
        print()
        print(Fore.YELLOW + "Monitoramento interrompido")
        print(Fore.WHITE + f"Total de acessos capturados: {self.total_visitas}")
        print()
        self.aguardar_enter()
    
    def executar(self):
        try:
            while True:
                self.mostrar_menu()
                
                try:
                    escolha = input(Fore.WHITE + Style.BRIGHT + "Sua escolha (1, 2 ou 0): " + Fore.YELLOW).strip()
                    
                    if escolha == '1':
                        self.gerar_e_monitorar()
                    elif escolha == '2':
                        self.monitorar_existente()
                    elif escolha == '0':
                        self.cabecalho()
                        print(Fore.GREEN + Style.BRIGHT + "OBRIGADO POR USAR O IP LOGGER PRO")
                        print(Fore.WHITE + "Desenvolvido por " + Fore.CYAN + "Braga Developer")
                        print()
                        print(Fore.YELLOW + "Seus logs foram salvos nos arquivos:")
                        if self.arquivo_log:
                            print(Fore.WHITE + f"  {self.arquivo_log}")
                        if self.arquivo_json:
                            print(Fore.WHITE + f"  {self.arquivo_json}")
                        print()
                        time.sleep(3)
                        break
                    else:
                        print(Fore.RED + "Opcao invalida")
                        time.sleep(1)
                
                except KeyboardInterrupt:
                    print()
                    continue
                    
        except KeyboardInterrupt:
            print()
        except Exception as erro:
            print(Fore.RED + f"ERRO CRITICO: {str(erro)}")
            input("Pressione Enter para sair...")

if __name__ == "__main__":
    print(Fore.CYAN + "Iniciando IP Logger Pro...")
    time.sleep(1)
    
    try:
        ferramenta = IPLoggerPro()
        ferramenta.executar()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "Programa encerrado")
    except Exception as e:
        print(Fore.RED + f"Erro fatal: {str(e)}")
        input("Pressione Enter para sair...")
