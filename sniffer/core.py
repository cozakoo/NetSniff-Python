from scapy.all import *
from datetime import datetime
import logging

class PacketSniffer:
    def __init__(self):
        self.packet_count = 0
        self.stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
    
    def process_packet(self, packet):
        self.packet_count += 1
        
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            
            if TCP in packet:
                self.stats["TCP"] += 1
                proto = f"TCP {packet[TCP].sport} → {packet[TCP].dport}"
            elif UDP in packet:
                self.stats["UDP"] += 1
                proto = f"UDP {packet[UDP].sport} → {packet[UDP].dport}"
            elif ICMP in packet:
                self.stats["ICMP"] += 1
                proto = "ICMP"
            else:
                self.stats["Other"] += 1
                proto = "IP"
            
            logging.info(f"[{datetime.now().strftime('%H:%M:%S')}] {src} → {dst} | {proto}")
            
            # Guardar payload si es interesante
            if TCP in packet and packet[TCP].payload:
                try:
                    payload = bytes(packet[TCP].payload)[:100]
                    if b"HTTP" in payload or b"GET" in payload or b"POST" in payload:
                        logging.info(f"HTTP detectado → {payload.decode(errors='ignore')[:80]}")
                except:
                    pass

    def start(self, iface=None, filter_str=None, count=0, output_pcap=None):
        logging.info(f"Iniciando sniffer en interfaz: {iface or 'todas'}")
        
        sniff(
            iface=iface,
            prn=self.process_packet,
            filter=filter_str,
            count=count,
            store=bool(output_pcap),
            stop_filter=lambda x: False
        )
        
        if output_pcap:
            wrpcap(output_pcap, sniff(offline=True))  # placeholder, se guarda en vivo abajo