import socket
import struct
import platform

OS = platform.system()

print(f"Sistema detectado: {OS}")

# ==========================
# CREACIÓN DEL SOCKET
# ==========================

if OS == "Windows":
    HOST = socket.gethostbyname(socket.gethostname())

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    s.bind((HOST, 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # modo promiscuo Windows
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

else:
    # Linux / macOS
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

print("Escuchando paquetes... Ctrl+C para salir")

try:
    while True:
        packet = s.recvfrom(65565)[0]

        ip_header = packet[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])

        print(f"{src_ip} → {dst_ip} | {len(packet)} bytes")

except KeyboardInterrupt:
    print("Detenido")

    if OS == "Windows":
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)