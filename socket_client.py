import socket

HOST = '10.1.2.3'
PORT = 80
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.send('hardware-status')
data = s.recv(1024)
s.close()
print 'Received' , repr(data)
