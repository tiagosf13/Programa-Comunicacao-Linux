#!/usr/bin/python3

from cProfile import run
from http import client
from optparse import OptionContainer
import os
from pydoc import cli
import re
from sqlite3 import DatabaseError
import sys
import socket
import signal
import json
import base64
from traceback import print_tb
from tracemalloc import start
from common_comm import send_dict, recv_dict, sendrecv_dict
from getpass import getpass
from collections import OrderedDict

from Crypto.Cipher import AES

RED   = "\033[1;31m"  
BLUE  = "\033[1;34m"
CYAN  = "\033[1;36m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"
YELLOW = "\033[1;33m"
PURPLE = '\033[95m'
WHYTE = "\033[0;37m"




# Verify if response from server is valid
def validate_response (response):
	if response["status"]==False:
		if response["op"]=="ID":
			os.system('cls' if os.name == 'nt' else 'clear')
			print(RED+"NOT VALID ID"+RESET)
			return (response["status"])
		elif response["op"]=="ACTIVE":
			return (response["status"])
	return (response["status"])


# Outcomming message structure: //o que mandamos ao servidor
# { op = "START", client_id, [cipher] }
# { op = "QUIT" }
# { op = "NUMBER", number }
# { op = "STOP" }
#
# Incomming message structure: //o que o servidor manda
# { op = "START", status }
# { op = "QUIT" , status }
# { op = "NUMBER", status }
# { op = "STOP", status, min, max }


#
# Suporte da execução do cliente
#
def verify_password (client_sock, client_id, password):
	dic = { "op": "PASSWORD", "client_id": client_id, "password": password }
	dic = sendrecv_dict(client_sock, dic)
	if validate_response(dic)==True:
		return True
	else:
		return False

def run_client (client_sock):
	os.system('cls' if os.name == 'nt' else 'clear')

	#criar a cifra
	cipherkey = os.urandom(16)
	cipherkey_tosend = str (base64.b64encode (cipherkey), 'utf8')

	client_id = input(CYAN+"Insira o seu ID:\n"+RESET)
	os.system('cls' if os.name == 'nt' else 'clear')

	if check_client_id(client_sock, client_id) == False:
		print("ERROR! ID not Approved!")
		opcao = input("Do you want to register? (Y/n)\n")
		if opcao == "Y":
			os.system('cls' if os.name == 'nt' else 'clear')
			print(GREEN+"Registering...\n\n"+RESET)
			print("Client ID: "+client_id)
			password = getpass("Insira a sua password:\n")
			password_confirm = getpass("Confirme a sua password:\n")
			if password == password_confirm:
				os.system('cls' if os.name == 'nt' else 'clear')
				admin_token = input("Insira o seu token de administrador:\n")
				dic = { "op": "REGISTER", "client_id": client_id, "password": password, "cipher" : cipherkey_tosend, "admin_token": admin_token }
				dic = sendrecv_dict(client_sock, dic)
				os.system('cls' if os.name == 'nt' else 'clear')
				if validate_response(dic)==True:
					run_client(client_sock)
				else:
					print("ERROR! Client not registered!")
		else:
			os.system('cls' if os.name == 'nt' else 'clear')
			print("ERROR! ID not Approved!")
			sys.exit(1)
	else:
		dic_verificar_atividade = { "op": "ACTIVE", "client_id": client_id }
		dic_verificar_atividade = sendrecv_dict(client_sock, dic_verificar_atividade)
		if validate_response(dic_verificar_atividade)==False:
			password = getpass("Insira a sua password:\n")
			if verify_password(client_sock, client_id, password) == False:
				os.system('cls' if os.name == 'nt' else 'clear')
				print("ERROR! PASSWORD not Approved!")
				sys.exit(2)
			else: # password is correct
				dic_ativar = { "op": "START", "client_id": client_id }
				dic_ativar = sendrecv_dict(client_sock, dic_ativar)
				if validate_response(dic_ativar)==False:
					print("ERROR! "+dic_ativar["error"])
					sys.exit(0)
				os.system('cls' if os.name == 'nt' else 'clear')
				start_bool = True
				dic_inicial = {"op": "GET_IDs"}
				dic_inicial = sendrecv_dict(client_sock, dic_inicial)
				while True:
					dic1 = { "op": "CIPHER", "client_id": client_id }
					dic1 = sendrecv_dict(client_sock, dic1)
					if validate_response(dic1) == False:
						print("ERROR! CIPHER not Approved!")
						sys.exit(3)
					else:
						if start_bool == True:
							mensagem_inicial = ""
							dic = { "op": "TALK", "client_id": client_id, "message" : mensagem_inicial }
							dic = sendrecv_dict(client_sock, dic)
							for element in dic["message"]:
								print(CYAN+element[0]+" ("+element[1]+")"+": "+"\n"+WHYTE+element[2]+RESET+"\n")
							start_bool = False
						else:
							print(PURPLE+"-"*50+RESET)
							print(GREEN+"CONNECTED - "+client_id+RESET+"\n")
							dic_active = { "op": "GET_ACTIVE_USERS", "client_id": client_id }
							dic_active = sendrecv_dict(client_sock, dic_active)
							sort_dic_active = OrderedDict(sorted(dic_active["active_users"].items()))
							for element in sort_dic_active:
								if element == client_id:
									continue
								elif dic_active["active_users"][element] == True:
									print(GREEN+element+" - ONLINE"+RESET)
								else:
									print(RED+element+" - OFFLINE"+RESET)
							mensagem = input("\n"+PURPLE+"("+client_id+")>>>"+RESET)
							os.system('cls' if os.name == 'nt' else 'clear')
							dic = { "op": "TALK", "client_id": client_id, "message" : mensagem }

							dic = sendrecv_dict(client_sock, dic)
							
							for element in dic["message"]:
								if element[1]!="":
									print(CYAN+element[0]+" ("+element[1]+")"+": "+"\n"+WHYTE+element[2]+RESET+"\n")
		else:
			print("ERROR! "+dic_verificar_atividade["message"])
			sys.exit(4)


def check_client_id (client_sock, client_id):
	frase_enviar = { "op": "ID", "client_id": client_id }
	dic = sendrecv_dict(client_sock, frase_enviar)
	if validate_response(dic)==True:
		return True
	else:
		return False

def signal_handler(sig, frame):
	sys.exit(0)

def main():
	# validate the number of arguments and eventually print error message and exit with error
	# verify type of of arguments and eventually print error message and exit with error

	signal.signal(signal.SIGINT, signal_handler)

	nome_host = "127.0.0.1" # Localhost by default

	# Verify the number of arguments
	if (len(sys.argv)<1):
		print("ERROR!Not enough arguments!")
		print("Usage: client.py [maquina IPv4]")
		sys.exit(1)
	elif (len(sys.argv)>2):
		print("ERROR!Too much arguments!")
		print("Usage: client.py [maquina IPv4]")
		sys.exit(1)
	# Verify the type of arguments, assuming that the number of arguments is correct
	else:
		# In case the user insert's a fourth argument (user choose's to run the server in another machine [maquina IPv4])
		try:
			if (len(sys.argv) == 2):
				lst_maquina = sys.argv[1].split(".")
				if len(lst_maquina)<4:
					print("ERROR! Wrong IPv4!")
					print("Usage: client.py [maquina IPv4]")
					sys.exit(0)
				for element in lst_maquina:
					if (int(element)<0) or (int(element)>255) or (len(element)>3):
						print("ERROR! Wrong IPv4!")
						print("Usage: client.py [maquina IPv4]")
						sys.exit(0)
				nome_host = sys.argv[2]
			else:
				nome_host = "127.0.0.1"
		except:
			#In case something goes wrong with the fourth argument
			print("ERROR! Wrong IPv4!")
			print("Usage: client.py [maquina IPv4]")
	
	hostname = nome_host
	port = 5005

	print("SERVER IP: "+hostname)
	print("SERVER PORT: "+str(port))


	client_sock = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
	client_sock.connect((hostname, port))

	run_client(client_sock)
	#sys.argv[0]---->client.py
	#sys.argv[1]---->[maquina]

	client_sock.close ()
	sys.exit (0)

if __name__ == "__main__":
    main()
