# -*- coding: utf-8 -*-
"""
Created on Thu Feb 20 14:55:28 2020

@author: lantoniaci
"""
import requests
import re
from colorama import *
from bs4 import BeautifulSoup, Comment
import tldextract
import socket
import warnings
import whois

init(autoreset=True)
warnings.filterwarnings("ignore")
class url:
	def __init__(self,url):
		self.url = url
	def verificaUrl(self):
		if len(re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',self.url)) > 0:
			return True
		else:
			print (" > {}Invalid URL!".format(Fore.RED))
			return False

class scan:
	def __init__(self,url):
		self.url = url.url
		user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36'
		self.useragent = {'User-Agent': user_agent}
		self.requisicao = requests.get(self.url,headers=self.useragent,verify=False)
		self.headers = self.requisicao.headers
		self.code = self.requisicao.status_code
		self.conteudo = BeautifulSoup(self.requisicao.content,'lxml')
	def info(self):
		print ("\n {}> INFO".format(Fore.YELLOW))
		if tldextract.extract(self.url).subdomain != "":
			self.hostname = tldextract.extract(self.url).subdomain+"."+tldextract.extract(self.url).domain+"."+tldextract.extract(self.url).suffix
		else:
		   self.hostname = tldextract.extract(self.url).domain+"."+tldextract.extract(self.url).suffix 
		self.ip = socket.gethostbyname(self.hostname)
		print ("   HOSTNAME: {}".format(self.hostname))
		print ("   IP: {}".format(self.ip))
		print ("{}   WHOIS".format(Fore.BLUE))
		try:
			self.ip_info = whois.whois(self.ip)
			try:
				print ("      REGISTRANT: {}".format(self.ip_info['registrar']))
				print ("      NAME: {}".format(self.ip_info['name']))
				print ("      EMAIL(S):")
				for email in self.ip_info['emails']:
					print ("      |{}".format(email))
				print ("      SERVER(S):")
				for nome in self.ip_info['name_servers']:
					print ("      |{}".format(nome))
					print ("      ORG: {}".format(self.ip_info['org']))
			except:
				print ("      REGISTRANT: {}".format(self.ip_info['registrant']))
				print ("      NAME: {}".format(self.ip_info['person']))
				print ("      EMAIL: {}".format(self.ip_info['email']))
				print ("      SERVER(S):")
				for nome in self.ip_info['nserver']:
					print ("      |{}".format(nome))
		except:
			print ("{}     ERROR ON WHOIS LOOKUP".format(Fore.RED))
		print ("{}   HTML".format(Fore.BLUE))
		print ("{}   TITLE: {}".format(Fore.WHITE,self.conteudo.find('title').text))
		opcao1 = input('      EXTRACT MORE INFO?(Y/n)')
		if opcao1 == 'n':
			cando1 = False
		elif opcao1 == 'Y' or opcao1 == '':
			cando1 = True
		while cando1:
			palavras_chave = ['cpf','Cpf','CPF','RG','Rg']
			print ("{}   KEYWORDS".format(Fore.WHITE))
			for palavra in palavras_chave:
				for tag in (self.conteudo.findAll(text=re.compile(palavra))):
					print ("{}     {}: {}[...]{}".format(Fore.LIGHTYELLOW_EX,palavra,tag[0:4],tag[tag.index(palavra)-50:tag.index(palavra)+50]))
			self.link = self.conteudo.findAll('',href=True)
			self.emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+',str(self.requisicao.content))
			self.comentarios = self.conteudo.find_all(string=lambda text: isinstance(text, Comment))
			print ("{}   LINKS [{}]".format(Fore.WHITE,len(self.link)))
			for tag in self.link:
				print ('     - {}'.format(tag['href']))
			print ("{}   EMAILS [{}]".format(Fore.WHITE,len(self.emails)))
			for tag in self.emails:
				print ('     - {}'.format(tag))
			print ("{}   COMMENTS [{}]".format(Fore.WHITE,len(self.comentarios)))
			for tag in self.comentarios:
				print ('     - {}'.format(tag))
			print ("{}   HTTP RESPONSE".format(Fore.BLUE))
			print ("-------------------------------------------------------")
			print ("   HTTP [{}]".format(self.code))
			for cabecalho in self.headers:
				print ("   {} : {}".format(cabecalho,self.headers[cabecalho]))
			print ("-------------------------------------------------------")
			cando1 = False
	def heads(self):
		print ("\n {}> HEADERS".format(Fore.YELLOW))
		secure = ['X-Frame-Options',
				  'X-XSS-Protection',
				  'Content-Security-Policy',
				  'HTTP Strict Transport Security',
				  'X-Content-Type-Options',
				  'X-Permitted-Cross-Domain-Policies',
				  'Referrer-Policy',
				  'Expect-CT'
				  'Feature-Policy']
		sensitive = ['Server',
		             'X-Powered-By',
		             'X-Aspnet-Version',
		             'X-AspNetMvc-Version']
		print ('{}     SECURITY'.format(Fore.WHITE))
		for cabecalho in secure:
			if cabecalho in self.headers:
				print ("{}   [OK] {}{} : {}".format(Fore.LIGHTGREEN_EX,Fore.RESET,cabecalho,self.headers[cabecalho]))
			else:
				print ("{}   [NOK] {}{}".format(Fore.RED,Fore.RESET,cabecalho))
		print ('{}     SENSITIVE INFO'.format(Fore.WHITE))
		for cabecalho in sensitive:
			if cabecalho in self.headers:
				print ("         {} : {}".format(cabecalho,self.headers[cabecalho]))
	def cookies(self):
		print ("\n {}> COOKIES".format(Fore.YELLOW))
		cabecalho = 'Set-Cookie'
		if cabecalho in self.headers:
			cookies = self.headers[cabecalho]
			if 'HttpOnly' in cookies or 'httponly' in cookies:
				print ("{}   [OK] {} HTTPONLY".format(Fore.LIGHTGREEN_EX,Fore.RESET))
			else:
				print ("{}   [NOK] {} HTTPONLY".format(Fore.RED,Fore.RESET))
			if 'Secure' in cookies or 'secure' in cookies:
				print ("{}   [OK] {} SECURE".format(Fore.LIGHTGREEN_EX,Fore.RESET))
			else:
				print ("{}   [NOK] {} SECURE".format(Fore.RED,Fore.RESET))
		else:
			print ("     NONE COOKIES IDENTIFIED")
	def methods(self):
		print ("\n {}> METHODS".format(Fore.YELLOW))
		metodos = ['GET',
				   'POST',
				   'DELETE',
				   'TRACE',
				   'CONNECT',
				   'PUT',
				   'HEAD',
				   'BOB']
		for metodo in metodos:
			requisicao = requests.request(metodo,self.url,headers=self.useragent,verify=False)
			print ("   {} [{}] {}".format(metodo,requisicao.status_code,requisicao.reason))
	def autocomplete(self):
		print ("\n {}> AUTOCOMPLETE".format(Fore.YELLOW))
		inputs = self.conteudo.find_all('input',{'type':'password'})
		print ("   {} PASSWORD INPUT(S) IDENTIFIED.".format(len(inputs)))
		for input in inputs:
			if 'autocomplete="off"' in str(input):
				print ("{}   [OK]{} {}".format(Fore.LIGHTGREEN_EX,Fore.RESET,input))
			else:
				print ("{}   [NOK]{} {}".format(Fore.RED,Fore.RESET,input))
	def enum(self):
		print ("\n {}> ENUM".format(Fore.YELLOW))
		opcao = input('      ENUMERATE WEBSITE DIRECTORIES?(Y/n)')
		if opcao == 'n':
			cando = False
		elif opcao == 'Y' or opcao == '':
			cando = True
		while cando:
			arquivo = 'diretorios.txt'
			i = 1
			if 'https' in self.url:
				http = 'https'
			else:
				http = 'http'
			file = open(arquivo,'r')
			diretorios = file.readlines()
			num_200 = 0
			num_404 = 0
			num_403 = 0
			outros = 0
			print ("      USING FILE '{}'".format(arquivo))
			print ("      ENUMERATING {} DIRECTORIE(S).".format(len(diretorios)))
			for diretorio in diretorios:
				new_url = http+'://'+self.hostname+"/"+diretorio.rstrip('\n')
				print ('      {}/{} - {}% [{}]                                      '.format(i,len(diretorios),int((i/len(diretorios)*100)),new_url),end="\r")
				response = requests.get(new_url)
				if response.status_code == 200:
					num_200 += 1
					print ('{}      #{} {} [{}] {} SIZE: {}'.format(Fore.RED,i,new_url,response.status_code,response.reason,len(response.content)))
					if 'Index of' in str(response.content):
						print ('      | {} INDEX OF'.format(Fore.RED))
						conteudo = BeautifulSoup(response.content,'lxml')
						for fl in conteudo.findAll('a'):
							if (fl.text != 'Name') and (fl.text != 'Last modified') and (fl.text != 'Size') and (fl.text != 'Description') and (fl.text != 'Parent Directory'): 
								print ('      |      {}'.format(fl.text))
						print ('      |  Banner:{}'.format(conteudo.find('address').text))
				elif response.status_code == 404:
					num_404 += 1
				elif response.status_code == 403:
					print ('{}      #{} {} [{}] {} SIZE: {}'.format(Fore.YELLOW,i,new_url,response.status_code,response.reason,len(response.content)))
					num_403 += 1
				else:
					outros += 1
				i += 1
			porc_200 = round(((num_200/len(diretorios))*100),2)
			porc_404 = round(((num_404/len(diretorios))*100),2)
			porc_403 = round(((num_403/len(diretorios))*100),2)
			porc_outros = round(((outros/len(diretorios))*100),2)
			print ('\n\n      SUMMARY\n')
			print ('      |200 OK [{}] {}%'.format(num_200,porc_200))
			print ('            |',end='')
			for x in range(0,int(porc_200)):
				print ('#',sep='',end='')
			print ('\n      |404 NOT FOUND [{}] {}%'.format(num_404,porc_404))
			print ('            |',end='')
			for x in range(0,int(porc_404)):
				print ('#',sep='',end='')
			print ('\n      |403 FORBIDDEN [{}] {}%       '.format(num_403,porc_403))
			print ('            |',end='')
			for x in range(0,int(porc_403)):
				print ('#',sep='',end='')
			print ('\n      |OUTROS [{}] {}%              '.format(outros,porc_outros))
			print ('            |',end='')
			for x in range(0,int(porc_outros)):
				print ('#',sep='',end='')
			cando = False