import socket

BROADCAST_IP = "YOUR_IP_HERE"  
PORT = 5005

def send_udp_broadcast(message: bytes):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(message, (BROADCAST_IP, PORT))
        print(f"[UDP GÖNDERİLDİ] {len(message)} byte → {BROADCAST_IP}:{PORT}")
