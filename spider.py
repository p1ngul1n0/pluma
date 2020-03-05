import requests
from bs4 import BeautifulSoup
from colorama import *

class spider:
	def __init__(self,url):
		print ("\n {}> SPIDER".format(Fore.YELLOW))
		self.url_master = url
		self.links_extraidos = []
		self.links_internos = []
		self.links_externos = []
	def extrair(self,url):
		print ('      |-[{}]                                                '.format(url))
		conteudo = BeautifulSoup(requests.get(url).content,'lxml')
		links = conteudo.findAll(href=True)
		for link in links:
			self.links_extraidos.append(str(link['href']))
			for link in self.links_extraidos:
				if 'http' not in link and link[:1] != '/':
					link = self.url_master+'/'+link
				elif 'http' not in link and link[:1] == '/':
					link = self.url_master+link
				if self.url_master in link and link not in self.links_internos:
					self.links_internos.append(link)
					print ('          |-{}'.format(link))
				elif self.url_master not in link and link not in self.links_externos:
					self.links_externos.append(link)
	def resumo(self):
		print ('        |------ {} link(s) interno(s)'.format(len(self.links_internos)))
		print ('        |------ {} link(s) externo(s)'.format(len(self.links_externos)))