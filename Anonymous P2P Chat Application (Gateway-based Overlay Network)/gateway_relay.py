import socket
import os

LISTEN_PORT = 5005
GATEWAY_LIST_PATH = "gateway_list.txt"

def load_gateway_list(path=GATEWAY_LIST_PATH):
    if os.path.exists(path):
        with open(path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    return []

def relay_udp_packet():
    relay_ips = load_gateway_list()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("", LISTEN_PORT))
    print(f"Relay Gateway {LISTEN_PORT} portunda dinliyor.")
    while True:
        data, addr = s.recvfrom(4096)
        print(f"[RELAY] {addr[0]}:{addr[1]} → {len(data)} byte")
        
        for ip in relay_ips:
            if ip != addr[0]:
                s.sendto(data, (ip, LISTEN_PORT))
                print(f"[RELAY] Forwarded to {ip}:{LISTEN_PORT}")

if __name__ == "__main__":
    relay_udp_packet()
