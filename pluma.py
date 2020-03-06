# -*- coding: utf-8 -*-
from web import *
from spider import *
from datetime import datetime
import time
from pyfiglet import Figlet

try:
	f = Figlet(font='roman')
	print (f.renderText('Pluma'))
	print ("|-Version: 0.3")
	print ("|-Author: Lucas Antoniaci")  
	print ("_____________________________________________________________________________________________________________________________")
	url = url(input(" > Insert a URL for analysis: "))
	if url.verificaUrl():
		now = datetime.now()
		inicio = time.time()
		print (" > DATA {}".format(now.strftime("%d/%m/%Y %H:%M:%S")))
		scan = scan(url)
		scan.info()
		scan.heads()
		scan.cookies()
		scan.methods()
		scan.autocomplete()
		scan.enum()
		spider = spider(url.url)
		spider.extrair(spider.url_master)
		i = 1
		for link in spider.links_internos:
			spider.extrair(link)
			i += 1
		fim = time.time()
		print ("\n\nAnd...Done! :) [{} secs]".format(int(fim - inicio)))
except (KeyboardInterrupt, SystemExit):
        print ("\nEXECUTION STOPPED!")
