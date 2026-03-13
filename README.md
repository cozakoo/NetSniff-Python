![Dashboard Demo](https://via.placeholder.com/800x400?text=NetSniff+Dashboard+Live)  <!-- reemplaza con GIF tuyo después -->


[<image-card alt="Streamlit App" src="https://static.streamlit.io/badges/streamlit_badge_black_white.svg" ></image-card>](https://tunombre-netsniff.streamlit.app)

## 🚀 Características Destacadas
- Dashboard web interactivo (Streamlit + Plotly)
- **Detección de anomalías en tiempo real con Isolation Forest (scikit-learn)**
- Alertas automáticas + gráfico de anomaly score
- Guardado .pcap + CLI clásica

## 🚀 Características Destacadas
- **CLI clásico** (ya lo tenías)
- **Dashboard Web Interactivo** con Streamlit + Plotly (¡nuevo!)
- Gráficos en tiempo real, tabla filtrable, alertas automáticas
- Deployable en Streamlit Cloud (link público)

**¡Prueba el dashboard en vivo!** → [Enlace a tu Streamlit Cloud]

# NetSniff - Packet Sniffer en Python

Un analizador de tráfico de red profesional escrito en Python con Scapy.  
Captura, filtra y analiza paquetes en tiempo real con interfaz CLI bonita.

## Características
- Captura en tiempo real con filtros BPF
- Guardado en formato .pcap (compatible con Wireshark)
- Estadísticas por protocolo (TCP/UDP/ICMP)
- Logging en archivo + consola
- Detección básica de HTTP
- Soporte multi-plataforma (Linux / Windows / macOS)

## Instalación
```bash
git clone https://github.com/tuusuario/NetSniff-Python.git
cd NetSniff-Python
pip install -r requirements.txt
```

## Uso
```bash
sudo python main.py --interface eth0 --filter "tcp port 80" --output captura.pcap
```

## Tecnologías usadas
- Python 3.10+
- Scapy (packet crafting & sniffing)
- Rich (interfaz terminal bonita)
- Argparse

## Autor
Martín Arcos Vargas [www.linkedin.com/in/martin-arcos]

