#!/usr/bin/env/python
import time
from threading import *
import argparse
import socket

class bcolors:
	FAIL = '\033[91m'
	ENDC = '\033[0m'

def disable(self):
	self.FAIL = ''
	self.ENDC = ''

try:
	import whois

except ImportError:
	print("\n" + bcolors.FAIL + 'Whois is required: "sudo pip install whois or sudo pip3 install whois"' + bcolors.ENDC + "\n")
	exit(1)

def checkDate(domain,date,registrar,nsfinal):

	date = str(date)
	fecha = date.split()[0]

	dyear = int(fecha.split("-")[0])
	dmonth = int(fecha.split("-")[1])
	dday = int(fecha.split("-")[2])

	tyear = int(time.strftime("%Y"))
	tmonth = int(time.strftime("%m"))
	tday = int(time.strftime("%d"))

	testm = tmonth - 1
	
	if testm < 1:
		testm = 12
		tyear = tyear - 1

	if dyear == tyear and dmonth == testm:
		print (domain + " | " + str(dyear) + "-" + str(dmonth) + "-" + str(dday) + " | " + registrar + " | " + str(nsfinal))

	else:
		pass


def whoisRequest(p):

### Pending to count and save domains which couldn't be analyzed for different reasons
	try:
		domain = whois.query(p)
		date = domain.creation_date
		ns = domain.name_servers
		ns_list = []
		for i in ns:
			ns_list.append(i)
		nsfinal = ns_list[0]		
		
		registrar = domain.registrar
		checkDate(p,date,registrar,nsfinal)

	except:
		pass

def consecutive(lista):

	totaldomain = 0
	xlist = []

	for domain in lista:

		vowels = "aeiouy"
		consonants = list("bcdfghjklmnpqrstvwxz")
		numbers =list("1234567890")
		nc = 0
		nv = 0
		nn = 0
		resultc = 0
		resultv = 0
		resultn = 0

		for char in domain:
			if char in consonants:
				nc = nc + 1
				if nc >= 6 :
					resultc = 1
			else:
				nc = 0
	
			if char in vowels:
				nv = nv +1
				if nv >= 5 :
					resultv = 1
			else:
				nv = 0

			if char in numbers:
				nn = nn +1
				if nn >= 6 :
					resultn = 1
			else:
				nn = 0

		if resultc == 1 or resultv == 1 or resultn == 1 :
			xlist.append(domain)
			totaldomain = totaldomain +1

	for y in sorted([x.strip().split('.')[::-1] for x in xlist]): print ('.'.join(y[::-1]))
	print (bcolors.FAIL + "\nNumber of suspicious domains: " + str(totaldomain) + "\n" + bcolors.ENDC)

def nslookup(domain,ns,ns_l):
		try:
			ip = socket.gethostbyname(domain)
			if ns_l == True:
				if ip == "127.0.0.1" or ip == "0.0.0.0":
					print (domain + " " + bcolors.FAIL + " Loopback detected!!!! This domain resolves: " + ip + bcolors.ENDC)
					pass
		except:
			if ns == True: 
				print(domain + bcolors.FAIL + " This domain can't be resolved" + bcolors.ENDC)
			pass
	
def main():
	parse = argparse.ArgumentParser()
	parse.add_argument('-f', action='store', dest='file', help='path to the CSV file')
	parse.add_argument('-w', action='store_true', dest='onlytime', help='Show only domains registered in the last month')
	parse.add_argument('-d', action='store_true', dest='onlydnscheck', help='Check for many vowels or consonants in a row. Subdomains are NOT included')
	parse.add_argument('-ds', action='store_true', dest='onlydnssubdomaincheck', help='Check for many vowels or consonants in a row. Subdomains included')
	parse.add_argument('-n', action='store_true', dest='nslookup', help="Check if the domain names can't be resolved")
	parse.add_argument('-nl', action='store_true', dest='ns_loopback', help='Check if the domain names resolve a loopback address')
	args = parse.parse_args()

	if args.file == None :
		parse.print_help()
		print("\n")
		exit(1)

	if args.file != None and (args.onlytime == True or args.onlydnscheck == True or args.onlydnssubdomaincheck == True or args.nslookup == True or args.ns_loopback == True):

			try:
				reader = open(args.file, 'r')
				### CSV Split
				lines = reader.read().split('",""'+"\n"'"')
				reader.close()

			except IOError:
				print(bcolors.FAIL + "\n[-] The file '"'%s'"' couldn't been opened." % (args.file) + "\n" + bcolors.ENDC)
				exit(1)

			if args.onlydnssubdomaincheck == True or args.nslookup == True or args.ns_loopback == True:

				lista = []
				for line in set(lines):
					lista.append(line)
				lista = list(set(lista))

				if args.onlydnssubdomaincheck == True:
					print ("[+] Number of domains: " + str(len(lines)))
					print ("[+] Number of unique domains: " + str(len(lista)))
					print ("Checking for many vowels or consonants in a row. Subdomains included.\n")
					consecutive(lista)

				if args.nslookup == True or args.ns_loopback == True:
					print ("[+] Number of domains: " + str(len(lines)))
					print ("[+] Number of unique domains: " + str(len(lista)))
					print ("Checking if the domain names resolve a loopback address.\n")		
					ns = args.nslookup 
					ns_l = args.ns_loopback
					count = 0
					threads = len(lista)
					while count < len(lista):
						for j in range(threads):
							domain = lista[count]
							t = Thread(target=nslookup,args=(domain,ns,ns_l))
							t.start()
							count = count + 1
							time.sleep(.05)

			if args.onlydnscheck == True or args.onlytime == True:
				lista = []
				for line in set(lines):
					try:
						domain = line.split(".")
						d_final = str(domain[-2] + "." + domain[-1])
						d_final = d_final.replace("\n","")
						lista.append(d_final)

					except IndexError:
						gotdata = 'null'

				if args.onlydnscheck == True:
					lista = list(set(lista))
					print ("[+] Number of domains: " + str(len(lines)))
					print ("[+] Number of unique domains: " + str(len(lista)))
					print ("Checking for many vowels or consonants in a row. Subdomains are NOT included.\n")		
					consecutive(lista)

				if args.onlytime == True:
					lista = list(set(lista))
					print ("[+] Number of domains: " + str(len(lines)))
					print ("[+] Number of unique domains: " + str(len(lista)))
					print ("\nChecking domains recently created...\n")
					count = 0
					threads = len(lista)
					while count < len(lista):
						for j in range(threads):
							p = lista[count]
							t = Thread(target=whoisRequest,args=(p,))
							t.start()
							count = count + 1
							time.sleep(.15)

	else:
		parse.print_help()

if __name__ == "__main__":
	main()
