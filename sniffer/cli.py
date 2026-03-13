import argparse
from scapy.all import get_if_list, conf
from .core import PacketSniffer
from .utils import setup_logging, print_stats, console

def main():
    parser = argparse.ArgumentParser(description="NetSniff - Packet Sniffer Profesional")
    parser.add_argument("-i", "--interface", help="Interfaz de red (ej: eth0, wlan0, Wi-Fi)")
    parser.add_argument("-f", "--filter", help="Filtro BPF (ej: 'tcp port 80' o 'host 192.168.1.1')")
    parser.add_argument("-c", "--count", type=int, default=0, help="Cantidad de paquetes a capturar (0 = infinito)")
    parser.add_argument("-o", "--output", help="Guardar captura en archivo .pcap")
    parser.add_argument("--list", action="store_true", help="Listar interfaces disponibles")
    
    args = parser.parse_args()
    
    setup_logging()
    
    if args.list:
        console.print("[bold green]Interfaces disponibles:[/bold green]")
        for iface in get_if_list():
            console.print(f"  • {iface}")
        return
    
    if not args.interface:
        args.interface = conf.iface  # interfaz por defecto
    
    sniffer = PacketSniffer()
    
    try:
        console.print(f"[bold red]NetSniff iniciado[/bold red] en {args.interface} (Ctrl+C para parar)")
        sniffer.start(
            iface=args.interface,
            filter_str=args.filter,
            count=args.count,
            output_pcap=args.output
        )
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Captura detenida por el usuario[/bold yellow]")
        print_stats(sniffer.stats)
    except PermissionError:
        console.print("[bold red]Error: Ejecuta con sudo/administrador[/bold red]")

if __name__ == "__main__":
    main()