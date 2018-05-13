import socket
import os
import commands

MEMORY    = "free | grep Mem | awk '{print $3/$2}'"
PROCESSOR = "grep 'cpu ' /proc/stat | awk '{usage=($2+$4)/($2+$4+$5)} END {print usage}'"

HOST = ''
PORT = 80
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST,PORT))
s.listen(1)
while True:
    conn, addr = s.accept()
    print 'Connected by', addr
    while True:
        data = conn.recv(1024)
        if not data:
            break
        elif data == 'hardware-status':
            _, mem  = commands.getstatusoutput(MEMORY)
            _, proc = commands.getstatusoutput(PROCESSOR)
            answer = mem + ' ' + proc
            print(answer)
            conn.send(answer)
        elif data == 'info':
            conn.send('info')
        else:
            conn.send('Bad request')
    conn.close()

