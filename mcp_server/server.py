import os
import json
import time
from dotenv import load_dotenv
from typing import Optional
from mcp.server.fastmcp import FastMCP
from sqlalchemy import create_engine, text

load_dotenv()

mcp = FastMCP(
    "DPI-Network-Analyzer"
)

DB_USER = 'root'
DB_PASS = os.environ.get("DB_PASSWORD")  
DB_HOST = 'localhost'
DB_NAME = 'thesis_network'

engine = create_engine(f'mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}')

def arricchisci_protocollo(proto_num: int) -> str:
    mapping = {1: "1 (ICMP)", 6: "6 (TCP)", 17: "17 (UDP)"}
    return mapping.get(proto_num, f"{proto_num} (Sconosciuto)")

def normalizza_data(data_str: str, is_end: bool = False) -> str:
    """
    Se l'LLM omette l'orario (es. 'YYYY-MM-DD'), aggiunge le ore/minuti/secondi
    corretti in base al fatto che sia la data di inizio o di fine.
    """
    data_str = data_str.strip()
    if len(data_str) == 10:
        return data_str + (" 23:59:59" if is_end else " 00:00:00")
    return data_str

# =====================================================================
# CATEGORIA A: ANALISI STRUTTURALE E SINTESI (VPN & General Info)
# =====================================================================

@mcp.tool()
def get_traffic_summary(ip_target: str, start_time: str, end_time: str, limit: str = "50") -> str:
    """
    [ISTRUZIONI LLM]: Usa questo tool come PRIMO PASSO investigativo (Triage iniziale) per ottenere 
    una panoramica globale dei flussi associati all'host target nella finestra temporale richiesta.
    
    COSA ANALIZZARE:
    1. Ispeziona la colonna 'app_hierarchy' alla ricerca di disallineamenti applicativi (es. protocollo classificato 
       come TLS/HTTP ma che viaggia su porte non standard, o applicazioni sconosciute su porte note come 80 o 443).
    2. Identifica la distribuzione dei protocolli di trasporto L4 (protocol) e le anomalie di durata (duration_ms).
    
    VINCOLO TEMPORALE: I parametri start_time ed end_time (YYYY-MM-DD HH:MM:SS.ffffff) delimitano tassativamente 
    l'analisi per escludere flussi benigni storici o successivi all'incidente.
    """
    start_time = normalizza_data(start_time, is_end=False)
    end_time = normalizza_data(end_time, is_end=True)

    try:
        limit_int = int(limit)
    except ValueError:
        limit_int = 50
    
    if limit_int > 100:
        limit_int = 100

    query = text(f"""
        SELECT community_id, src_ip, src_port, dst_ip, dst_port, protocol, 
               duration_ms, total_bytes, packet_rate, app_hierarchy 
        FROM ndpi_flows 
        WHERE (src_ip = :ip OR dst_ip = :ip)
          AND timestamp_start BETWEEN :start AND :end
        ORDER BY timestamp_start DESC 
        LIMIT {limit_int};
    """)
    try:
        t_inizio_sql = time.perf_counter()

        with engine.connect() as connection:
            result = connection.execute(query, {
                "ip": ip_target, 
                "start": start_time, 
                "end": end_time, 
            })
            colonne = result.keys()
            flussi = [dict(zip(colonne, riga)) for riga in result.fetchall()]
            
            t_sql_puro = time.perf_counter() - t_inizio_sql
            
            for f in flussi:
                f["protocol"] = arricchisci_protocollo(int(f["protocol"]))

            risposta_finale = {
                "tempo_sql_reale_sec": round(t_sql_puro, 6),
                "flussi": flussi
            }

            return json.dumps(risposta_finale, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nel recupero della sintesi del traffico: {str(e)}"

@mcp.tool()
def detect_beaconing(ip_target: str, start_time: str, end_time: str, dst_ip: Optional[str] = None) -> str:
    """
    [ISTRUZIONI LLM]: Usa questo tool per identificare comunicazioni cicliche e persistenti (Heartbeat/Beaconing)
    verso infrastrutture Command & Control (C2) o Botnet all'interno della finestra temporale specificata.
    
    COSA ANALIZZARE:
    1. Ordina per 'Anomaly Score' decrescente e focalizzati su record con 'dev_std' (Deviazione Standard) molto bassa.
    2. ATTENZIONE AI MALWARE AVANZATI: Cerca tag 'LOW_FOOTPRINT'. I malware C2 sofisticati effettuano pochissime 
       connessioni dilazionate nel tempo (basso footprint volumetrico) per eludere i controlli standard.
    3. DRILL-DOWN: Se noti un IP esterno sospetto in altri tool, passa quell'IP al parametro opzionale 'dst_ip' 
       per calcolare la regolarità temporale specifica verso quel target isolato.
    """
    start_time = normalizza_data(start_time, is_end=False)
    end_time = normalizza_data(end_time, is_end=True)
    
    if dst_ip in (None, "", "null"):
        dst_ip = None

    min_intervals = 1 if dst_ip else 4
    dst_filter = "AND n.dst_ip = :dst_ip" if dst_ip else ""

    query_str = f"""
        WITH timed_flows AS (
            SELECT
                n.dst_ip,
                n.dst_port,
                TIMESTAMPDIFF(SECOND, LAG(n.timestamp_start) OVER (PARTITION BY n.dst_ip, n.dst_port ORDER BY n.timestamp_start), n.timestamp_start) as delta_time
            FROM ndpi_flows as n
            WHERE n.src_ip = :ip
              AND n.timestamp_start BETWEEN :start AND :end
              {dst_filter}
        ),
        beaconing_stats AS (
            SELECT
                dst_ip,
                dst_port,
                COUNT(*) as intervalli_validi,
                AVG(delta_time) as intervallo_medio,
                STDDEV(delta_time) as dev_std
            FROM timed_flows
            WHERE delta_time IS NOT NULL
            GROUP BY dst_ip, dst_port
            HAVING intervalli_validi >= :min_intervals
        )
        SELECT dst_ip, dst_port, (intervalli_validi + 1) as totale_connessioni, 
               ROUND(intervallo_medio, 1) as avg_sec, 
               ROUND(dev_std, 1) as std_sec
        FROM beaconing_stats
        ORDER BY 
            CASE WHEN dst_ip = :dst_ip_order THEN 0 ELSE 1 END,
            dev_std ASC, 
            totale_connessioni DESC
        LIMIT 15;
    """
    
    query = text(query_str)
   
    try:
        t_inizio_sql = time.perf_counter()

        with engine.connect() as connection:
            params = {
                "ip": ip_target, 
                "start": start_time, 
                "end": end_time, 
                "min_intervals": min_intervals,
                "dst_ip_order": dst_ip if dst_ip else ""
            }
            if dst_ip:
                params["dst_ip"] = dst_ip
                
            result = connection.execute(query, params)
            righe = result.fetchall()
            
            t_sql_puro = time.perf_counter() - t_inizio_sql
        
            if not righe:
                msg = f"[INFO]: Nessun pattern di beaconing rilevato per l'host {ip_target}"
                if dst_ip:
                    msg += f" verso la destinazione specifica {dst_ip}"
                return msg + f" nella finestra specificata. (Tempo SQL: {round(t_sql_puro, 6)} sec)"
           
            output = f"RILEVAMENTO PER TARGET: {ip_target}\n"
            output += f"_Tempo esecuzione query SQL: {round(t_sql_puro, 6)} secondi_\n\n"
            output += "| IP Destinazione | Porta Dest. | Connessioni Totali | Intervallo Medio (sec) | Deviazione Standard (sec) | Anomaly Score (0-100) | Note |\n"
            output += "|-----------------|-------------|--------------------|------------------------|---------------------------|-----------------------|------|\n"

            for riga in righe:
                totale_connessioni = riga.totale_connessioni
                avg_sec = riga.avg_sec
                std_sec = riga.std_sec

                if avg_sec > 0:
                    cv = std_sec / avg_sec  
                    if cv < 0.1 and avg_sec >= 2.0:
                        anomaly_score = 95
                    elif cv < 0.3 and avg_sec >= 1.0:
                        anomaly_score = 75
                    elif avg_sec <= 1.0 and std_sec <= 0.5:
                        anomaly_score = 40  
                    else:
                        anomaly_score = max(10, int((1 - min(cv, 1)) * 50))
                else:
                    anomaly_score = 0
                
                tag_list = []
                if avg_sec <= 1.0:
                    tag_list.append("HIGH_FREQUENCY_RATE")
                if totale_connessioni < 5:
                    tag_list.append("LOW_FOOTPRINT")
                if std_sec <= 1.5 and avg_sec > 2.0:
                    tag_list.append("STABLE_PERIODICITY")
                
                tag_str = ", ".join(tag_list) if tag_list else "-"
                output += f"| {riga.dst_ip} | {riga.dst_port} | {totale_connessioni} | {avg_sec}s | {std_sec}s | {anomaly_score}/100 | {tag_str} |\n"
                
            return output
    except Exception as e:
        return f"[ERRORE TOOL]: Errore durante l'esecuzione dell'analisi di beaconing: {str(e)}"

# =====================================================================
# CATEGORIA B: MONITORAGGIO VOLUMETRICO (Anomalia Rate / DoS)
# =====================================================================

@mcp.tool()
def get_rate_statistics(
    start_time: str, 
    end_time: str, 
    ip_address: Optional[str] = None
) -> str:
    """
    [ISTRUZIONI LLM]: Invocando questo tool otterrai i parametri di Baseline Statistica della rete 
    (Media e Deviazione Standard) calcolati rigorosamente sulla finestra temporale selezionata.
    
    PARAMETRI OPZIONALI:
    - ip_address: Passa un IP se vuoi calcolare la baseline specifica di un singolo host (sia come sorgente che come destinazione).
    
    COSA ANALIZZARE:
    1. Memorizza i valori di 'avg_packet_rate' e 'stddev_packet_rate'.
    2. Usa questi dati matematici per calcolare se i flussi estratti successivamente violano la baseline 
       di oltre 2 o 3 deviazioni standard, confermando matematicamente anomalie volumetriche o attacchi DoS in corso.
    """
    start_time = normalizza_data(start_time, is_end=False)
    end_time = normalizza_data(end_time, is_end=True)

    sql_text = """
        SELECT 
            AVG(packet_rate) as avg_packet_rate, 
            STDDEV(packet_rate) as stddev_packet_rate,
            AVG(byte_rate) as avg_byte_rate,
            STDDEV(byte_rate) as stddev_byte_rate
        FROM ndpi_flows
        WHERE timestamp_start BETWEEN :start AND :end
    """
    
    params = {"start": start_time, "end": end_time}

    if ip_address:
        sql_text += " AND (src_ip = :ip OR dst_ip = :ip)"
        params["ip"] = ip_address.strip()

    sql_text += ";"
    query = text(sql_text)

    try:
        t_inizio_sql = time.perf_counter()

        with engine.connect() as connection:
            result = connection.execute(query, params)
            riga = result.fetchone()

            t_sql_puro = time.perf_counter() - t_inizio_sql

            stats = dict(zip(result.keys(), riga)) if riga else {}
            stats["tempo_sql_reale_sec"] = round(t_sql_puro, 6)

            return json.dumps(stats, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nel calcolo delle statistiche di baseline: {str(e)}"

@mcp.tool()
def query_by_rate(
    threshold: float, 
    start_time: str, 
    end_time: str, 
    metric: str = "packet_rate",
    ip_address: Optional[str] = None
) -> str:
    """
    [ISTRUZIONI LLM]: Usa questo tool per isolare i flussi che stanno violando una soglia quantitativa 
    critica (threshold) per identificare attacchi di tipo DoS, DDoS o esfiltrazioni massive di dati.
    
    PARAMETRI OPZIONALI:
    - ip_address: Passa un IP se vuoi limitare la ricerca delle anomalie a uno specifico host target/sorgente.
    
    COSA ANALIZZARE:
    1. Imposta la metrica su 'packet_rate' per rilevare attacchi Flood/DoS (es. SYN Flood).
    2. Imposta la metrica su 'byte_rate' per tracciare esfiltrazioni massive (Data Exfiltration) o attacchi di saturazione della banda.
    
    VINCOLO TEMPORALE: Isola l'abuso esclusivamente nel range temporale dell'incidente, evitando di analizzare 
    picchi storici legittimi non correlati.
    """
    start_time = normalizza_data(start_time, is_end=False)
    end_time = normalizza_data(end_time, is_end=True)

    if metric not in ["packet_rate", "byte_rate"]:
        return "[ERRORE TOOL]: La metrica inserita deve essere 'packet_rate' o 'byte_rate'."
        
    sql_text = f"""
        SELECT community_id, src_ip, dst_ip, dst_port, protocol, packet_rate, byte_rate, duration_ms
        FROM ndpi_flows
        WHERE {metric} > :threshold
          AND timestamp_start BETWEEN :start AND :end
    """
    
    params = {"threshold": threshold, "start": start_time, "end": end_time}

    if ip_address:
        sql_text += " AND (src_ip = :ip OR dst_ip = :ip)"
        params["ip"] = ip_address.strip()

    sql_text += f" ORDER BY {metric} DESC LIMIT 15;"
    query = text(sql_text)

    try:
        t_inizio_sql = time.perf_counter()
        with engine.connect() as connection:
            result = connection.execute(query, params)
            colonne = result.keys()
            flussi = [dict(zip(colonne, riga)) for riga in result.fetchall()]
            
            t_sql_puro = time.perf_counter() - t_inizio_sql

            for f in flussi:
                f["protocol"] = arricchisci_protocollo(int(f["protocol"]))

            risposta_finale = {
                "tempo_sql_reale_sec": round(t_sql_puro, 6),
                "flussi_volumetrici": flussi
            }

            return json.dumps(risposta_finale, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nell'analisi volumetrica: {str(e)}"

# =====================================================================
# CATEGORIA C: INVESTIGAZIONE ENDPOINT (Top Talker & Host Profiling)
# =====================================================================

@mcp.tool()
def get_top_talkers(start_time: str, end_time: str, top_n: int = 10, criterion: str = "bytes") -> str:
    """
    [ISTRUZIONI LLM]: Identifica gli host dominanti nella rete (Top Talkers) in termini di volume totale 
    espresso in byte ('bytes') o frequenza totale espressa in pacchetti ('packets').
    
    COSA ANALIZZARE:
    1. Trova gli host interni/esterni più attivi durante la finestra dell'incidente.
    2. Nota bene: Un host che genera moltissimi flussi ma pochissimi byte per flusso è sintomo di 
       attività di Network Scanning, Directory Busting o tentativi di Brute Force distribuito.
    """
    start_time = normalizza_data(start_time, is_end=False)
    end_time = normalizza_data(end_time, is_end=True)

    try:
        top_n_int = int(top_n)
    except (ValueError, TypeError):
        top_n_int = 10 

    if criterion not in ["bytes", "packets"]:
        return "[ERRORE TOOL]: il criterio deve essere 'bytes' o 'packets'."
        
    colonna_somma = "total_bytes" if criterion == "bytes" else "total_packets"
    
    query = text(f"""
        SELECT src_ip, 
               SUM({colonna_somma}) as volume_totale, 
               COUNT(*) as flussi_totali
        FROM ndpi_flows
        WHERE timestamp_start BETWEEN :start AND :end
        GROUP BY src_ip
        ORDER BY volume_totale DESC
        LIMIT :top_n;
    """)
    try:
        t_inizio_sql = time.perf_counter()

        with engine.connect() as connection:
            result = connection.execute(query, {"start": start_time, "end": end_time, "top_n": top_n_int})
            colonne = result.keys()
            host = [dict(zip(colonne, riga)) for riga in result.fetchall()]

            t_sql_puro = time.perf_counter() - t_inizio_sql

            risposta_finale = {
                "tempo_sql_reale_sec": round(t_sql_puro, 6),
                "top_talkers": host
            }

            return json.dumps(risposta_finale, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nel calcolo dei Top Talkers: {str(e)}"

@mcp.tool()
def analyze_dpi_details(ip: str, start_time: str, end_time: str) -> str:
    """
    [ISTRUZIONI LLM]: Esegue un'analisi profonda a livello 7 (DPI) sui metadati applicativi estratti 
    esclusivamente nell'arco temporale selezionato. Da invocare per l'analisi approfondita di un host sospetto.
    
    COSA ANALIZZARE:
    1. 'payload_entropy': Valori vicini a 0 indicano payload vuoti o ripetitivi (es. attacchi DoS stupidi). 
       Valori estremamente alti (maggiore di 7.5) indicano payload cifrati o compressi, potenziale segno di esfiltrazione o tunneling nascosto.
    2. 'tls_version' & 'tls_cipher_suite': Rileva l'uso di cifrari deboli o versioni obsolete (TLS 1.0, TLS 1.1) 
       spesso adottate da vecchie varianti malware o sistemi legacy compromessi.
    """
    start_time = normalizza_data(start_time, is_end=False)
    end_time = normalizza_data(end_time, is_end=True)

    query = text("""
        SELECT community_id, src_ip, dst_ip, dst_port, protocol, app_hierarchy, 
               ndpi_hostname, payload_entropy, infra_provider, tls_version, tls_cipher_suite
        FROM ndpi_flows
        WHERE (src_ip = :ip OR dst_ip = :ip)
          AND timestamp_start BETWEEN :start AND :end
        ORDER BY timestamp_start DESC
        LIMIT 15;
    """)
    try:
        t_inizio_sql = time.perf_counter()

        with engine.connect() as connection:
            result = connection.execute(query, {"ip": ip, "start": start_time, "end": end_time})
            colonne = result.keys()
            flussi = [dict(zip(colonne, riga)) for riga in result.fetchall()]

            t_sql_puro = time.perf_counter() - t_inizio_sql
            
            for f in flussi:
                f["protocol"] = arricchisci_protocollo(int(f["protocol"]))
            
            risposta_finale = {
                "tempo_sql_reale_sec": round(t_sql_puro, 6),
                "dpi_details": flussi
            }

            return json.dumps(risposta_finale, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nell'ispezione DPI di dettaglio: {str(e)}"

@mcp.tool()
def resolve_host_info(ip: str, start_time: str, end_time: str) -> str:
    """
    [ISTRUZIONI LLM]: Usa questo tool per ottenere l'arricchimento infrastrutturale dell'IP target (es. provider cloud, 
    hostnames dns rilevati dai pacchetti SNI) all'interno dell'intervallo temporale.
    
    COSA ANALIZZARE:
    1. Aiuta a discriminare tra comunicazioni legittime verso grandi CDN/Cloud Providers (es. AWS, Cloudflare, Akamai) 
       e server VPS autonomi (spesso usati come relay per attacchi o server C2 anonimi).
    """
    start_time = normalizza_data(start_time, is_end=False)
    end_time = normalizza_data(end_time, is_end=True)

    query = text("""
        SELECT DISTINCT ndpi_hostname, infra_provider
        FROM ndpi_flows
        WHERE (src_ip = :ip OR dst_ip = :ip) 
          AND timestamp_start BETWEEN :start AND :end
          AND (ndpi_hostname IS NOT NULL OR infra_provider IS NOT NULL)
        LIMIT 10;
    """)
    try:
        t_inizio_sql = time.perf_counter()

        with engine.connect() as connection:
            result = connection.execute(query, {"ip": ip, "start": start_time, "end": end_time})
            colonne = result.keys()
            info = [dict(zip(colonne, riga)) for riga in result.fetchall()]

            t_sql_puro = time.perf_counter() - t_inizio_sql

            risposta_finale = {
                "tempo_sql_reale_sec": round(t_sql_puro, 6),
                "host_info": info
            }

            return json.dumps(risposta_finale, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nella risoluzione delle info host: {str(e)}"


# =====================================================================
# CATEGORIA D: ANALISI COMPORTAMENTALE (Brute Force / Infiltration)
# =====================================================================

@mcp.tool()
def search_connection_attempts(
    start_time: str, 
    end_time: str, 
    target_port: int, 
    ip_address: Optional[str] = None
) -> str:
    """
    [ISTRUZIONI LLM]: Invocando questo tool otterrai i tentativi di connessione aggregati verso una specifica porta di destinazione.
    Utilizzalo per identificare attacchi di Port Scanning, Brute Force (es. porta 22 SSH o 3389 RDP) o tentativi di exploit.
    
    PARAMETRI OPZIONALI:
    - ip_address: Passa un IP se vuoi restringere la ricerca dei tentativi di connessione a un singolo host target o sorgente.
    """
    start_time = normalizza_data(start_time, is_end=False)
    end_time = normalizza_data(end_time, is_end=True)

    sql_text = """
        SELECT src_ip, dst_ip, dst_port, COUNT(*) as tentativi_totali, AVG(duration_ms) as durata_media_ms
        FROM ndpi_flows
        WHERE timestamp_start BETWEEN :start AND :end
          AND dst_port = :target_port
    """
    
    params = {
        "start": start_time, 
        "end": end_time, 
        "target_port": target_port
    }

    if ip_address:
        sql_text += " AND (src_ip = :ip OR dst_ip = :ip)"
        params["ip"] = ip_address.strip()

    sql_text += " GROUP BY src_ip, dst_ip, dst_port ORDER BY tentativi_totali DESC LIMIT 50;"
    query = text(sql_text)

    try:
        t_inizio_sql = time.perf_counter()
        with engine.connect() as connection:
            result = connection.execute(query, params)
            colonne = result.keys()
            risultati = [dict(zip(colonne, riga)) for riga in result.fetchall()]
            
            t_sql_puro = time.perf_counter() - t_inizio_sql

            risposta_finale = {
                "tempo_sql_reale_sec": round(t_sql_puro, 6),
                "tentativi_connessione": risultati
            }

            return json.dumps(risposta_finale, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nella ricerca dei tentativi di connessione: {str(e)}"

@mcp.tool()
def get_flow_features(ip: str, start_time: str, end_time: str) -> str:
    """
    [ISTRUZIONI LLM]: Estrae i dettagli matematico-temporali avanzati dei flussi generati dall'host inserito 
    come sorgente, circoscritti all'intervallo temporale dell'indagine.
    
    COSA ANALIZZARE:
    1. Confronta 'iat_flow_avg' (Media Inter-Arrival Time) con 'iat_flow_stddev' (Deviazione Standard dello IAT). 
       Se la deviazione standard è vicina a zero, significa che i pacchetti vengono inviati a intervalli matematicamente identici e spaccati al millisecondo, prova inconfutabile di un heartbeat software / botnet attivo.
    2. Esamina 'tcp_flags' per studiare lo stato della connessione (es. valore 2 indica presenza esclusiva di pacchetti SYN, sinonimo di tentativi falliti o scansioni).
    """
    start_time = normalizza_data(start_time, is_end=False)
    end_time = normalizza_data(end_time, is_end=True)

    query = text("""
        SELECT community_id, dst_ip, dst_port, protocol, duration_ms, 
               iat_flow_avg, iat_flow_stddev, payload_entropy, tcp_flags
        FROM ndpi_flows
        WHERE src_ip = :ip
          AND timestamp_start BETWEEN :start AND :end
        ORDER BY timestamp_start DESC
        LIMIT 15;
    """)
    try:
        t_inizio_sql = time.perf_counter()

        with engine.connect() as connection:
            result = connection.execute(query, {"ip": ip, "start": start_time, "end": end_time})
            colonne = result.keys()
            flussi = [dict(zip(colonne, riga)) for riga in result.fetchall()]
            
            t_sql_puro = time.perf_counter() - t_inizio_sql

            for f in flussi:
                f["protocol"] = arricchisci_protocollo(int(f["protocol"]))

            risposta_finale = {
                "tempo_sql_reale_sec": round(t_sql_puro, 6),
                "flussi": flussi
            }

            return json.dumps(risposta_finale, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nell'estrazione delle flow features: {str(e)}"

@mcp.tool()
def analizza_connessione_by_community_id(cid: str) -> str:
    """
    [ISTRUZIONI LLM]: Esegue un'operazione di drill-down atomico su un singolo flusso specifico partendo dal suo 
    identificativo univoco 'community_id' (estratto dai log dei tool precedenti).
    
    QUANDO USARLO: Invocalo quando hai individuato un flusso sospetto specifico e vuoi vederne ogni singola colonna 
    estratta (entropia, provider, hierarchy) senza rumore di fondo. Non necessita di parametri temporali.
    """
    cid_clean = str(cid).strip()

    query = text("""
        SELECT community_id, src_ip, src_port, dst_ip, dst_port, protocol, duration_ms,
               total_bytes, packet_rate, payload_entropy, app_hierarchy, ndpi_hostname, infra_provider
        FROM ndpi_flows 
        WHERE community_id = :cid
        LIMIT 1;
    """)
    try:
        t_inizio_sql = time.perf_counter()

        with engine.connect() as connection:
            result = connection.execute(query, {"cid": cid_clean})
            colonne = result.keys()
            riga = result.fetchone()

            t_sql_puro = time.perf_counter() - t_inizio_sql
            
            if not riga:
                return f"[ERRORE TOOL]: Nessun flusso di dettaglio trovato per il community_id: {cid_clean}."
                
            flusso = dict(zip(colonne, riga))

            if flusso.get("protocol") is not None:
                flusso["protocol"] = arricchisci_protocollo(int(flusso["protocol"]))

            flusso["tempo_sql_reale_sec"] = round(t_sql_puro, 6)

            return json.dumps(flusso, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nel Drill-Down per community_id: {str(e)}"

if __name__ == "__main__":
    mcp.run(transport='stdio')
