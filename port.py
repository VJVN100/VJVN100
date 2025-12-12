import sys
import socket
import threading
import time

usage = "python3 port_scanner.py TARET START_PORT END_PORT"

print("-"*70)
print("Python Simple Port Scanner")
print("-"*70)

start_time = time.time()

if(len(sys.argv) != 4):
    print(usage)
    sys.exit()

try:
    target = socket.gethostbyname(sys.argv[1])
except socket.gaieror:
    print("Name resolution error")
    sys.exit()

start_port = int(sys.argv[2])
end_port = int(sys.argv[3])

def scan_port(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    conn = s.connect_ex((target, port))
    if conn == 0:
        print("Port {} is Open".format(port))
    s.close()


for port in range(start_port, end_port + 1):

    thread = threading.Thread(target=scan_port, args=(port,))
    thread.start()    

end_time = time.time()
print("Time elapsed :", end_time - start_time)
