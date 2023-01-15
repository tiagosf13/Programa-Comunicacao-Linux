#!/usr/bin/python3

from asyncore import read, write
from distutils.command.clean import clean
from email import message
from http import client
from pickle import TRUE
import sys
import socket
import select
import signal
import os
import json
import base64
import csv
import random
from typing import KeysView
from unittest import case
from common_comm import send_dict, recv_dict, sendrecv_dict
from datetime import datetime
import string

from Crypto.Cipher import AES

RED   = "\033[1;31m"  
BLUE  = "\033[1;34m"
CYAN  = "\033[1;36m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"
PURPLE = "\033[95m"
YELLOW = "\033[1;33m"




def get_ids():
	lst = []
	for element in read_json("users.json").keys():
		lst.append(element)
	return { "op": "GET_IDS", "status": True, "ids": lst }

def get_cipher(client_id):
	if client_id in read_json("users.json"):
		dic = { "op": "GET_CIPHER", "status" : True, "cipher": read_json("users.json")[client_id]["cipher"] }
	else:
		dic = { "op": "GET_CIPHER", "status" : False, "error": "Cliente inexistente" }
	return dic

def check_existence_json(token):
	directory = os.getcwd()
	if not os.path.exists(directory+"/users.json"):
		write_json("users.json", {})
	if not os.path.exists(directory+"/admin_token.json"):
		write_json("admin_token.json", [token])
	if not os.path.exists(directory+"/total_data_bytes.json"):
		write_json("total_data_bytes.json", [0])
	else:
		write_json("admin_token.json", [token])
		write_json("total_data_bytes.json", [0])
	return None

def check_existence_sockets_json():
	directory = os.getcwd()
	if not os.path.exists(directory+"/sockets.json"):
		write_json("sockets.json", {})
	return None

def read_json (file_name):
	with open(file_name, "r") as f:
		return json.load(f)

def write_json (file_name, data):
	with open(file_name, "w") as f:
		json.dump(data, f)
	return None

# Return the client_id of a socket or None
def find_client_id (sock):
	dic = read_json("sockets.json")
	for element in dic:
		if dic[element] == sock:
			return element
	return ("No such key")




# Incomming message structure: //o que mandamos ao servidor
# { op = "START", client_id, [cipher] }
# { op = "QUIT" }
# { op = "NUMBER", number }
# { op = "STOP" }
#
# Outcomming message structure: //o que o servidor manda
# { op = "START", status }
# { op = "QUIT" , status }
# { op = "NUMBER", status }
# { op = "STOP", status, min, max }

def check_id (request):
	client_id = request["client_id"]
	if client_id in read_json("users.json"):
		dic = { "op": "ID", "status": True }
	else:
		dic = { "op": "ID", "status": False, "error": "Cliente inexistente" }
	return dic

def check_password (request):
	client_id = request["client_id"]
	password = request["password"]
	if password == read_json("users.json")[client_id]["password"]:
		dic = { "op": "PASSWORD", "status": True }
	else:
		dic = { "op": "PASSWORD", "status": False, "error": "Password incorrect" }
	return dic

def open_csv(filename):
	if not os.path.exists(filename):
		with open(filename, "w") as f:
			f.write("")
		return None
	else:
		with open(filename, "r") as f:
			reader = csv.reader(f)
			lst = list(reader)
			for element in lst:
				if element == []:
					lst.remove(element)
		return lst

def write_csv(filename, data):
	with open(filename, "a") as f:
		writer = csv.writer(f)
		writer.writerow(data)
	return None

def talk(request):
	client_id = request["client_id"]
	message = request["message"]
	message_decoded = message.strip()
	print(message_decoded)
	if message_decoded != "":
		total_data_bytes = read_json("total_data_bytes.json")[0]
		total_data_bytes += len(message_decoded)
		write_csv("data.csv", [datetime.today().strftime('%Y-%m-%d %H:%M:%S'),client_id, message_decoded, len(message_decoded), total_data_bytes])
		write_json("total_data_bytes.json", [total_data_bytes])
	else:
		total_data_bytes = read_json("total_data_bytes.json")[0]
	lst = open_csv("data.csv")
	dic = { "op": "TALK", "status": True, "message": lst, "data_bytes": len(message_decoded), "total_data_bytes": total_data_bytes }
	return dic

def check_active(clien_id):
	usuarios = read_json("users.json")
	if usuarios[clien_id]["active"]:
		return { "op": "ACTIVE", "status": True, "message": "User is active" }
	else:
		return { "op": "ACTIVE", "status": False, "message": "User is not active" }
#
# Suporte de descodificação da operação pretendida pelo cliente
#

def deactivate(client_id):
	try:
		usuarios = read_json("users.json")
		password = usuarios[client_id]["password"]
		cipher = usuarios[client_id]["cipher"]
		socket = usuarios[client_id]["socket"]
		if client_id in usuarios:
			usuarios[client_id] = { "password": password, "cipher": cipher, "socket": socket, "active": False }
			write_json("users.json", usuarios)
			dic = { "op": "START", "status": True }
		else:
			dic = { "op": "START", "status": False, "error": "Cliente inexistente" }
		return dic
	except:
		return { "op": "START", "status": False, "error": "Cliente inexistente" }

def get_active_users():
	usuarios = read_json("users.json")
	dic = {}
	for user in usuarios:
		if usuarios[user]["active"]:
			dic[user] = True
		else:
			dic[user] = False
	return { "op": "GET_ACTIVE_USERS", "status": True, "active_users": dic}

def start (client_sock, request):
	client_id = request["client_id"]
	usuarios = read_json("users.json")
	password = usuarios[client_id]["password"]
	cipher = usuarios[client_id]["cipher"]

	sockets = read_json("sockets.json")
	sockets[client_id] = client_sock
	if client_id in usuarios:
		usuarios[client_id] = { "password": password, "cipher": cipher, "socket": str(client_sock), "active": True }
		write_json("users.json", usuarios)
		sockets[client_id] = str(client_sock)
		write_json("sockets.json", sockets)
		dic = { "op": "START", "status": True }
	else:
		dic = { "op": "START", "status": False, "error": "Cliente inexistente" }
	return dic

def find_client_id(client_sock):
	usuarios = read_json("users.json")
	for user in usuarios:
		if usuarios[user]["socket"] == str(client_sock):
			return user
	return None

def new_msg (client_sock):
	msg = recv_dict(client_sock)
	answer = "NO ANSWER"
	print(GREEN+"Request: ",msg,RESET)
	if msg["op"]=="ID":
		answer = check_id(msg)
	elif msg["op"]=="REGISTER":
		answer = new_client(client_sock, msg)
	elif msg["op"]=="PASSWORD":
		answer = check_password(msg)
	elif msg["op"]=="CIPHER":
		answer = get_cipher(msg["client_id"])
	elif msg["op"]=="TALK":
		answer = talk(msg)
	elif msg["op"]=="GET_IDs":
		answer = get_ids()
	elif msg["op"]=="ACTIVE":
		answer = check_active(msg["client_id"])
	elif msg["op"]=="START":
		answer = start(client_sock, msg)
	elif msg["op"]=="GET_ACTIVE_USERS":
		answer = get_active_users()
	elif msg["op"]=="DEACTIVATE":
		answer = deactivate(find_client_id(msg["client_sock"]))
	print(RED+"Answer: ",answer,RESET)
	print(BOLD+"-"*120+RESET)
	return answer

# read the client request
# detect the operation requested by the client
# execute the operation and obtain the response (consider also operations not available)
# send the response to the client


#
# Suporte da criação de um novo jogador - operação START
#
def new_client (client_sock, request):
	op = request["op"]
	client = request["client_id"]
	password = request["password"]
	if password == "":
		return { "op": op, "status": False, "error": "Password inválida" }
	cipher = request["cipher"]
	admin_token = request["admin_token"]
	if client not in read_json("users.json") and admin_token == read_json("admin_token.json")[0]:
		usuarios = read_json("users.json")
		usuarios[client] = { "password": password, "cipher": cipher, "socket": str(client_sock), "active": None }
		write_json("users.json", usuarios)
		sockets = read_json("sockets.json")
		sockets[client] = str(client_sock)
		write_json("sockets.json", sockets)
		dic = { "op": op, "status": True }
	else:
		if client in read_json("users.json"):
			dic = { "op": op, "status": False, "error": "Client existente" }
		else:
			dic = { "op": op, "status": False, "error": "Admin token incorreto" }
	return dic

# detect the client in the request
# verify the appropriiate conditons for executing this operation
# process the client in the dictionary
# return response message with or without error message



# obtain the client_id from his socket
# verify the appropriate conditions for executing this operation
# process the report file with the QUIT result
# eliminate client from dictionary
# return response message with or without error message


# obtain the client_id from his socket
# verify the appropriate conditions for executing this operation
# process the report file with the result
# eliminate client from dictionary
# return response message with result or error message

def signal_handler(sig, frame):
    sys.exit(0)


def main():
	# validate the number of arguments and eventually print error message and exit with error
	# verify type of of arguments and eventually print error message and exit with error

	os.system('cls' if os.name == 'nt' else 'clear')

	signal.signal(signal.SIGINT, signal_handler)

	port = 5005
	ip_addr = "0.0.0.0"
	server_socket = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
	server_socket.bind ((ip_addr, port))
	server_socket.listen (5)
	server_socket.setblocking(False)

	host_name = socket.gethostname()
	host_ip = socket.gethostbyname(host_name)
	token = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(20))
	print(CYAN+"Server started!\nHost: "+host_name+"\nIP: "+host_ip+"\nPort: "+str(port)+"\nAdmin token: "+token)
	print("Waiting for clients..."+RESET)

	check_existence_json(token)
	check_existence_sockets_json()
	open_csv("data.csv")
	

	clients = []

	while True:
		try:
			available = select.select ([server_socket] + clients, [], [])[0]
		except ValueError:
			# Sockets may have been closed, check for that
			for client_sock in clients:
				if client_sock.fileno () == -1: client_sock.remove (client_sock) # closed
			continue # Reiterate select

		for client_sock in available:
			# New client?
			if client_sock is server_socket:
				newclient, addr = server_socket.accept ()
				clients.append (newclient)
			# Or an existing client
			else:
				try:
					# See if client sent a message
					if len (client_sock.recv (1, socket.MSG_PEEK)) != 0:
						# client socket has a message
						#print ("server" + str (client_sock))
						data_to_send = new_msg (client_sock)
						send_dict(client_sock, data_to_send)
				except: # Or just disconnected
						deactivate(find_client_id(str(client_sock)))
						clients.remove (client_sock)
						client_sock.close()
						break # Reiterate select

if __name__ == "__main__":
	main()