from scapy.all import *
from datetime import datetime

def analizar(pkt):
    hora = datetime.now().strftime("%H:%M:%S")
    
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto  # 6=TCP, 17=UDP, 1=ICMP...
        
        info = f"[{hora}] {src} → {dst} | "
        
        if TCP in pkt:
            info += f"TCP {pkt[TCP].sport} → {pkt[TCP].dport}"
            if pkt[TCP].payload:
                try:
                    payload = pkt[TCP].payload.load.decode('utf-8', errors='ignore')
                    if len(payload) > 0:
                        info += f" | Payload: {payload[:60]}..."
                except:
                    pass
        
        elif UDP in pkt:
            info += f"UDP {pkt[UDP].sport} → {pkt[UDP].dport}"
        
        elif ICMP in pkt:
            info += "ICMP"
        
        print(info)

print("Sniffer iniciado. Filtrando IP/TCP/UDP/ICMP...")
sniff(prn=analizar, store=0, filter="ip")   # solo paquetes IP