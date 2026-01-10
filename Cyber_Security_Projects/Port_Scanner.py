import sys
import socket
import threading
import time

usage = "python3 port_scanner.py TARGET START_PORT END_PORT"

print("-" * 70)
print("Python Simple Port Scanner")
print("-" * 70)

start_time = time.time()

# Check arguments
if len(sys.argv) != 4:
    print(usage)
    sys.exit()

# Resolve target hostname
try:
    target = socket.gethostbyname(sys.argv[1])
except socket.gaierror:
    print("Name resolution error")
    sys.exit()

start_port = int(sys.argv[2])
end_port = int(sys.argv[3])

# Scan a single port
def scan_port(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    result = s.connect_ex((target, port))
    if result == 0:
        print(f"Port {port} is Open")
    s.close()

threads = []

# Create & start threads
for port in range(start_port, end_port + 1):
    thread = threading.Thread(target=scan_port, args=(port,))
    threads.append(thread)
    thread.start()

# Wait for all threads to finish
for thread in threads:
    thread.join()

end_time = time.time()
print("Time elapsed:", end_time - start_time)
