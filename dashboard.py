# Bibliotecas necesarias
import threading               # Para ejecutar la captura en segundo plano (hilo separado)
import time                    # Para medir tiempos y pausas
import datetime                # Para timestamps más legibles
import pandas as pd            # Para manejar los datos de paquetes en forma de tabla
import streamlit as st         # Framework web para crear el dashboard interactivo
import plotly.express as px    # Para gráficos bonitos e interactivos
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list, conf
import queue                   # Cola segura para comunicar el hilo sniffer → dashboard
from sklearn.ensemble import IsolationForest   # Algoritmo de detección de anomalías
from sklearn.preprocessing import StandardScaler  # Normaliza datos para el modelo IA

# Cola (queue) thread-safe donde el sniffer va poniendo los paquetes procesados
packet_queue = queue.Queue()
conf.sniff_promisc = False   # Desactiva promisc si falla el hardware filter

def packet_sniffer(iface=None, filter_str=None):
    """
    Función que se ejecuta en un hilo separado.
    Captura paquetes de red con Scapy y los coloca en la cola packet_queue
    para que el dashboard principal los procese.
    
    Parámetros:
        iface (str o None): Nombre o GUID de la interfaz de red.
                            Si es None, Scapy usa la interfaz por defecto.
        filter_str (str o None): Filtro BPF (ej: "tcp port 80", "host 192.168.1.1")
    """
    def process(pkt):
        """
        Función de callback que Scapy llama por cada paquete capturado.
        Solo procesa paquetes con capa IP y extrae la información relevante.
        """
        if IP in pkt:
            # Construimos un diccionario con los datos que nos interesan
            data = {
                'timestamp': datetime.datetime.now(),          # Hora actual (cuando se procesa)
                'src': pkt[IP].src,                            # Dirección IP origen
                'dst': pkt[IP].dst,                            # Dirección IP destino
                'protocol': (
                    'TCP' if TCP in pkt else
                    'UDP' if UDP in pkt else
                    'ICMP' if ICMP in pkt else 'IP'
                ),
                'size': len(pkt),                              # Tamaño total del paquete en bytes
                
                # Puerto origen (solo si es TCP o UDP)
                'sport': (
                    pkt[TCP].sport if TCP in pkt else
                    (pkt[UDP].sport if UDP in pkt else None)
                ),
                
                # Puerto destino (solo si es TCP o UDP)
                'dport': (
                    pkt[TCP].dport if TCP in pkt else
                    (pkt[UDP].dport if UDP in pkt else None)
                )
            }
            # Enviamos el diccionario a la cola (thread-safe)
            packet_queue.put(data)

    # Mensaje de debug opcional (puedes comentarlo después de probar)
    # print(f"[DEBUG] Iniciando captura en: {iface if iface else 'INTERFAZ POR DEFECTO'}")
    # print(f"[DEBUG] Filtro aplicado: {filter_str if filter_str else 'NINGUNO'}")

    try:
        print(f"[Sniffer START] Interfaz: {iface if iface else 'DEFAULT (' + conf.iface + ')'}")
        print(f"[Sniffer] Filtro BPF: '{filter_str if filter_str else 'NINGUNO'}'")
        print("[Sniffer] Iniciando sniff... (debe capturar si hay tráfico)")

        sniff(
            iface=iface,
            prn=process,
            filter=filter_str,
            store=False,
            promisc=True,           # Prueba con False si falla (ver abajo)
            # timeout=10            # descomenta para pruebas cortas
        )
        print("[Sniffer] sniff terminó (timeout o manual stop)")
    except Exception as e:
        import traceback
        print("!!! ERROR EN SNIFFER !!!")
        traceback.print_exc()
        print("!!! FIN DEL ERROR !!!")


# ────────────────────────────────────────────────
#               DASHBOARD PRINCIPAL
# ────────────────────────────────────────────────
def main():
    st.set_page_config(
        page_title="NetSniff Dashboard",
        layout="wide",
        page_icon="🔍"
    )

    # Inicialización SIEMPRE al inicio
    if 'running' not in st.session_state:
        st.session_state.running    = False
        st.session_state.data       = []
        st.session_state.thread     = None
        st.session_state.start_time = None
        st.session_state.model      = None
        st.session_state.scaler     = None

    st.title("🛡️ NetSniff - Dashboard Interactivo + IA Anomaly Detection")
    st.markdown("**Captura en tiempo real + detección automática de anomalías con Isolation Forest**")

    # Sidebar - solo una vez
    st.sidebar.header("Controles")

    interfaces = get_if_list()
    iface = st.sidebar.selectbox("Interfaz de red", options=["(default)"] + interfaces)
    if iface == "(default)":
        iface = None

    filtro = st.sidebar.text_input("Filtro BPF", value="", placeholder="tcp port 80 o dejar vacío")

    start_btn = st.sidebar.button("Iniciar Captura")
    stop_btn  = st.sidebar.button("Detener Captura")

    # Debug interfaces (muy útil ahora)
    st.sidebar.header("🔍 Debug Interfaces")
    st.sidebar.write(f"**Interfaces detectadas**: {len(interfaces)}")
    if interfaces:
        for i, intf in enumerate(interfaces):
            st.sidebar.write(f"- {i}: `{intf}`")
    else:
        st.sidebar.error("¡Ninguna interfaz! → Npcap mal instalado o no hay adaptadores")
    st.sidebar.write(f"**Interfaz por defecto de Scapy**: `{conf.iface}`")

    # Lógica de botones
    if start_btn and not st.session_state.running:
        st.session_state.running = True
        st.session_state.data = []
        st.session_state.start_time = time.time()
        st.session_state.model = None
        iface_to_use = None if not iface else iface.strip()

        st.session_state.thread = threading.Thread(
            target=packet_sniffer,
            args=(iface_to_use, filtro),
            daemon=True
        )
        st.session_state.thread.start()
        st.success("Captura iniciada! Genera tráfico (YouTube, ping, etc.)")

    if stop_btn:
        st.session_state.running = False
        st.warning("Captura detenida (puede tardar unos segundos en parar el hilo)")

    # Debug en vivo
    if st.session_state.running:
        st.sidebar.success("Sniffer corriendo")
        st.sidebar.info(f"Paquetes en cola: {packet_queue.qsize()}")
        st.sidebar.info(f"Paquetes totales procesados: {len(st.session_state.data)}")

    # Procesar cola (esto va siempre, incluso si no running)
    while not packet_queue.empty():
        st.session_state.data.append(packet_queue.get())

    df = pd.DataFrame(st.session_state.data)

    # anomalías, métricas, gráficos
    num_anomalies = 0
    if len(df) >= 30 and not df.empty:
        protocol_map = {'TCP': 0, 'UDP': 1, 'ICMP': 2, 'IP': 3}
        df_features = pd.DataFrame({
            'size': df['size'],
            'protocol_num': df['protocol'].map(protocol_map).fillna(3)
        })
        scaler = StandardScaler()
        X = scaler.fit_transform(df_features)

        if st.session_state.model is None or len(df) % 50 == 0:
            model = IsolationForest(contamination=0.05, random_state=42, n_estimators=100)
            model.fit(X)
            st.session_state.model = model
            st.session_state.scaler = scaler

        if st.session_state.model is not None:
            scores = st.session_state.model.decision_function(st.session_state.scaler.transform(df_features))
            df['anomaly_score'] = scores
            df['is_anomaly'] = df['anomaly_score'] < 0
            num_anomalies = int(df['is_anomaly'].sum())

    duration = int(time.time() - st.session_state.start_time) if st.session_state.start_time else 0
    pps = len(df) / max(1, duration)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Paquetes", len(df))
    col2.metric("Tasa actual", f"{pps:.1f} pkt/s")
    col3.metric("Duración", f"{duration} s")
    col4.metric("Anomalías IA", num_anomalies, delta="¡ALERTA!" if num_anomalies > 0 else None, delta_color="inverse")

    if not df.empty:
        pass

    else:
        st.info("Inicia la captura para ver datos y activar la IA...")

    st.caption("Ejecuta con: **streamlit run dashboard.py** (como admin en Windows)")

if __name__ == "__main__":
    main()