#!/bin/env python3

import socket
import random
import string

HOST = "127.0.0.1"
PORT = 8000

def read_note(id):
    with open("tasks.txt", "r") as f:
        for row in f.readlines():
            _id, nickname, password, value = row.split()
            if int(_id) == int(id):
                return (nickname, password, value)
            pass
        pass
    return None

def save_note(id, nickname, password, value):
    with open('tasks.txt', 'a') as f:
        f.write(f"{id} {nickname} {password} {value}\n")
    pass

def send_value(id, nickname, password, value):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.recv(1024)
        s.sendall(b"1")
        s.recv(1024)
        s.sendall(nickname.encode())
        s.recv(1024)
        s.sendall(password.encode())
        s.recv(1024)
        s.sendall(b"2")
        s.recv(1024)
        s.sendall(nickname.encode())
        s.recv(1024)
        s.sendall(password.encode())
        s.recv(1024)
        s.sendall(value.encode())
        pass
    save_note(id, nickname, password, value)
    return id

def test_value(id):
    note = read_note(id)
    if note == None:
        print(f"error, can't find note with id {id}")
        return
    nickname, password, value = note
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.recv(1024)
        s.sendall(b"3")
        s.recv(1024)
        s.sendall(nickname.encode())
        s.recv(1024)
        s.sendall(password.encode())
        s.recv(1024)
        raw = s.recv(1024)
        raw = raw.decode("utf8")
        start = raw.find("< ") + 2
        return raw[start:start+len(value)] == value
    return False

id = random.randint(1, 10000000)
nickname = "".join(random.choices(string.ascii_letters + string.digits, k=32))
password = "".join(random.choices(string.ascii_letters + string.digits, k=32))
value = "".join(random.choices(string.ascii_letters + string.digits, k=32))
send_value(id, nickname, password, value)
print(test_value(id))
