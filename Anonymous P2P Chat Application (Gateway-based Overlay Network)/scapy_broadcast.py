
from scapy.all import Ether, IP, UDP, sendp

def send_spoofed_udp(dst_ip, dst_port, data, src_ip, src_mac=None, dst_mac="ff:ff:ff:ff:ff:ff", iface="eth0"):
    # Ethernet katmanı (MAC spoofing)
    ether = Ether(src=src_mac if src_mac else "de:ad:be:ef:00:01", dst=dst_mac)
    # IP ve UDP katmanları (IP spoofing)
    ip = IP(src=src_ip, dst=dst_ip)
    udp = UDP(sport=12345, dport=dst_port)
    pkt = ether / ip / udp / data
    sendp(pkt, iface=iface, verbose=1)

if __name__ == "__main__":
    import sys
    
    dst_ip = "186.165.40.20"      # Broadcast adresi (veya hedef IP)
    dst_port = 5005
    message = b"SPF test: Selam!"
    src_ip = "178.150.70.66"      # İstediğin fake IP
    src_mac = "77:54:34:36:15:12" # İstediğin fake MAC

    iface = "eth0" 
    send_spoofed_udp(dst_ip, dst_port, message, src_ip, src_mac, iface=iface)
