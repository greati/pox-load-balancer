import socket
import time

HOST = '10.1.2.3'
PORT = 80
SLEEP_SEC = 5

while True:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    start = time.time()
    s.connect((HOST, PORT))
    s.send('info')
    data = s.recv(1024)
    end = time.time()
    s.close()
    print 'Received' , 1000 * (end-start)
    time.sleep(SLEEP_SEC)
