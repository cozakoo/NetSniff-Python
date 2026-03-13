import threading
import time
import datetime
import pandas as pd
import streamlit as st
import plotly.express as px
from scapy.all import sniff, IP, TCP, UDP, ICMP
import queue
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ====================== COLA PARA PAQUETES ======================
packet_queue = queue.Queue()

def packet_sniffer(iface=None, filter_str=None):
    """Hilo de captura (igual que antes)"""
    def process(pkt):
        if IP in pkt:
            data = {
                'timestamp': datetime.datetime.now(),
                'src': pkt[IP].src,
                'dst': pkt[IP].dst,
                'protocol': 'TCP' if TCP in pkt else 'UDP' if UDP in pkt else 'ICMP' if ICMP in pkt else 'IP',
                'size': len(pkt),
                'sport': pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else None),
                'dport': pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)
            }
            packet_queue.put(data)
    
    sniff(iface=iface, prn=process, filter=filter_str, store=False)

# ====================== DASHBOARD ======================
def main():
    st.set_page_config(page_title="NetSniff Dashboard", layout="wide", page_icon="🔍")
    st.title("🛡️ NetSniff - Dashboard Interactivo + IA Anomaly Detection")
    st.markdown("**Captura en tiempo real + detección automática de anomalías con Isolation Forest**")

    # Sidebar
    st.sidebar.header("Controles")
    iface = st.sidebar.text_input("Interfaz", value="eth0")  # cámbialo según tu PC
    filtro = st.sidebar.text_input("Filtro BPF", value="", placeholder="tcp port 80")
    start_btn = st.sidebar.button("▶️ Iniciar Captura")
    stop_btn = st.sidebar.button("⏹️ Detener Captura")

    # Estado de sesión
    if 'running' not in st.session_state:
        st.session_state.running = False
        st.session_state.data = []
        st.session_state.thread = None
        st.session_state.start_time = None
        st.session_state.model = None
        st.session_state.scaler = None

    # Iniciar captura
    if start_btn and not st.session_state.running:
        st.session_state.running = True
        st.session_state.data = []           # reset
        st.session_state.start_time = time.time()
        st.session_state.model = None        # reset modelo IA
        st.session_state.thread = threading.Thread(
            target=packet_sniffer,
            args=(iface if iface else None, filtro),
            daemon=True
        )
        st.session_state.thread.start()
        st.success("✅ Captura + modelo de anomalías iniciado!")

    if stop_btn:
        st.session_state.running = False
        st.warning("⏹️ Captura detenida.")

    # Procesar paquetes de la cola
    while not packet_queue.empty():
        st.session_state.data.append(packet_queue.get())

    df = pd.DataFrame(st.session_state.data)

    # ====================== DETECCIÓN DE ANOMALÍAS (IA) ======================
    num_anomalies = 0
    if len(df) >= 30 and not df.empty:
        # Features (tamaño + protocolo codificado)
        protocol_map = {'TCP': 0, 'UDP': 1, 'ICMP': 2, 'IP': 3}
        df_features = pd.DataFrame({
            'size': df['size'],
            'protocol_num': df['protocol'].map(protocol_map).fillna(3)
        })

        scaler = StandardScaler()
        X = scaler.fit_transform(df_features)

        # Reentrenar modelo cada 50 paquetes (o la primera vez)
        if st.session_state.model is None or len(df) % 50 == 0:
            model = IsolationForest(
                contamination=0.05,      # espera 5% de anomalías
                random_state=42,
                n_estimators=100
            )
            model.fit(X)
            st.session_state.model = model
            st.session_state.scaler = scaler

        # Calcular puntuaciones
        if st.session_state.model is not None:
            scores = st.session_state.model.decision_function(
                st.session_state.scaler.transform(df_features)
            )
            df['anomaly_score'] = scores
            df['is_anomaly'] = df['anomaly_score'] < 0
            num_anomalies = int(df['is_anomaly'].sum())

    # ====================== MÉTRICAS ======================
    duration = int(time.time() - st.session_state.start_time) if st.session_state.start_time else 0
    pps = len(df) / max(1, duration)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Paquetes", len(df))
    col2.metric("Tasa actual", f"{pps:.1f} pkt/s")
    col3.metric("Duración", f"{duration} s")
    col4.metric("Anomalías IA", num_anomalies, 
                delta="¡ALERTA!" if num_anomalies > 0 else None,
                delta_color="inverse")

    # ====================== GRÁFICOS ======================
    if not df.empty:
        c1, c2 = st.columns(2)
        with c1:
            st.plotly_chart(px.pie(df, names='protocol', title="Distribución Protocolos"), use_container_width=True)
        with c2:
            st.plotly_chart(px.line(df.groupby(df['timestamp'].dt.floor('S')).size().reset_index(), 
                                  x='timestamp', y=0, title="Paquetes por segundo"), use_container_width=True)

        # === GRÁFICO DE ANOMALÍAS ===
        st.subheader("📉 Detección de Anomalías en Tiempo Real")
        if 'anomaly_score' in df.columns:
            fig = px.line(df.reset_index(), x='index', y='anomaly_score',
                          title="Anomaly Score (valores < 0 = ANOMALÍA)",
                          color_discrete_sequence=["red"])
            st.plotly_chart(fig, use_container_width=True)

            if num_anomalies > 0:
                st.error(f"🚨 {num_anomalies} ANOMALÍAS DETECTADAS")
                st.dataframe(
                    df[df['is_anomaly']].sort_values('anomaly_score')[['timestamp', 'src', 'dst', 'protocol', 'size', 'anomaly_score']].tail(10),
                    use_container_width=True
                )

        # Top IPs y tabla final
        st.plotly_chart(px.bar(df['src'].value_counts().head(10), title="Top 10 IPs Origen"), use_container_width=True)
        
        st.subheader("Últimos paquetes")
        cols = ['timestamp', 'src', 'dst', 'protocol', 'size']
        if 'anomaly_score' in df.columns:
            cols += ['anomaly_score']
        st.dataframe(df[cols].tail(20), use_container_width=True)

    else:
        st.info("Inicia la captura para ver datos y activar la IA...")

    st.caption("Ejecuta con: **sudo streamlit run dashboard.py** | Modelo Isolation Forest entrenado en vivo")

if __name__ == "__main__":
    main()