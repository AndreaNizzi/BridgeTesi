import os
import json
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from sqlalchemy import create_engine, text

# Carichiamo le variabili dal file .env
load_dotenv()

# Inizializzamo il server MCP
mcp = FastMCP("DPI-Network-Analyzer")

# Configuriamo la connessione al Database MySQL
DB_USER = 'root'
DB_PASS = os.environ.get("DB_PASSWORD")  
DB_HOST = 'localhost'
DB_NAME = 'thesis_network'

engine = create_engine(f'mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}')

# Funzione di arricchimento semantico 
def arricchisci_protocollo(proto_num: int) -> str:
    mapping = {1: "1 (ICMP)", 6: "6 (TCP)", 17: "17 (UDP)"}
    return mapping.get(proto_num, f"{proto_num} (Sconosciuto)")

# =====================================================================
# CATEGORIA A: ANALISI STRUTTURALE E SINTESI (VPN & General Info)
# =====================================================================

@mcp.tool()
def get_traffic_summary(ip_target: str, start_time: str, end_time: str, limit: str = "50", ragionamento_investigativo: str = "Analisi macroscopica strutturale dei flussi") -> str:
    """
    Restituisce una snapshot globale dei flussi di rete analizzati da nDPI per l'host target
    e all'interno della finestra temporale indicata (Formato: YYYY-MM-DD HH:MM:SS).
    Includendo la colonna app_hierarchy, permette all'LLM di rilevare immediatamente 
    discrepanze macroscopiche tra porte e applicazioni (es. traffico non-HTTP su porta 80).
    """
    try:
        limit_int = int(limit)
    except ValueError:
        limit_int = 50

    _ = ragionamento_investigativo
    
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
        with engine.connect() as connection:
            result = connection.execute(query, {
                "ip": ip_target, 
                "start": start_time, 
                "end": end_time, 
            })
            colonne = result.keys()
            flussi = [dict(zip(colonne, riga)) for riga in result.fetchall()]
            
            for f in flussi:
                f["protocol"] = arricchisci_protocollo(int(f["protocol"]))
            return json.dumps(flussi, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nel recupero della sintesi del traffico: {str(e)}"


@mcp.tool()
def detect_beaconing(ip_target: str, start_time: str, end_time: str, ragionamento_investigativo: str= "Analisi dei pattern di beaconing e regolarità temporale") -> str:
    """
    Analizza i flussi in uscita dall'IP target alla ricerca di pattern periodici e ripetitivi
    tipici delle comunicazioni Command & Control (C2) e Botnet (Beaconing).
    Ritorna le destinazioni ordinate per regolarità temporale (bassa deviazione standard).
    """
    _ = ragionamento_investigativo
    
    query = text("""
        WITH timed_flows AS (
            SELECT
                n.dst_ip,
                n.dst_port,
                TIMESTAMPDIFF(SECOND, LAG(n.timestamp_start) OVER (PARTITION BY n.dst_ip, n.dst_port ORDER BY n.timestamp_start), n.timestamp_start) as delta_time
            FROM ndpi_flows as n
            WHERE n.src_ip = :ip
              AND n.timestamp_start BETWEEN :start AND :end
        ),
        beaconing_stats AS (
            SELECT
                dst_ip,
                dst_port,
                COUNT(*) as totale_connessioni,
                AVG(delta_time) as intervallo_medio,
                STDDEV(delta_time) as dev_std
            FROM timed_flows
            WHERE delta_time IS NOT NULL
            GROUP BY dst_ip, dst_port
            HAVING totale_connessioni >= 5
        )
        SELECT dst_ip, dst_port, totale_connessioni, ROUND(intervallo_medio, 1) as avg_sec, ROUND(dev_std, 1) as std_sec
        FROM beaconing_stats
        ORDER BY dev_std ASC, totale_connessioni DESC
        LIMIT 10;
    """)
   
    try:
        with engine.connect() as connection:
            result = connection.execute(query, {"ip": ip_target, "start": start_time, "end": end_time})
            righe = result.fetchall()
           
            if not righe:
                return f"[INFO]: Nessun pattern di beaconing rilevato per l'host {ip_target} nella finestra specificata."
           
            # Formattiamo il risultato in una tabella Markdown leggibile dall'LLM
            output = f"### RILEVAMENTO BEACONING PER TARGET: {ip_target}\n"
            output += "| IP Destinazione | Porta Dest. | Connessioni Totali | Intervallo Medio (sec) | Deviazione Standard (Regolarità) |\n"
            output += "|-----------------|-------------|--------------------|------------------------|---------------------------------|\n"
           
            for riga in righe:
                totale_connessioni = riga.totale_connessioni
                avg_sec = riga.avg_sec
                std_sec = riga.std_sec

                if std_sec <= 2.0 and avg_sec > 1.0 and totale_connessioni >= 10:
                    status_warning = "SOSPETTO BEACONING C2 (Alta Regolarità)"
                elif std_sec <= 1.0 and avg_sec <= 1.0:
                    status_warning = "TRAFFICO BURST STANDARD (Navigazione/Asset Caricati)"
                else:
                    status_warning = ""
                output += f"| {riga.dst_ip} | {riga.dst_port} | {totale_connessioni} | {avg_sec}s | {std_sec}s {status_warning} |\n"
               
            return output
           
    except Exception as e:
        return f"[ERRORE TOOL]: Errore durante l'esecuzione dell'analisi di beaconing: {str(e)}"


# =====================================================================
# CATEGORIA B: MONITORAGGIO VOLUMETRICO (Anomalia Rate / DoS)
# =====================================================================

@mcp.tool()
def get_rate_statistics(start_time: str, end_time: str, ragionamento_investigativo: str = "Calcolo della baseline statistica dei tassi di traffico") -> str:
    """
    Restituisce la baseline statistica della rete (Media e Deviazione Standard) dei tassi 
    di traffico all'interno di una finestra temporale circoscritta (Formato: YYYY-MM-DD HH:MM:SS).
    """
    _ = ragionamento_investigativo

    query = text("""
        SELECT 
            AVG(packet_rate) as avg_packet_rate, 
            STDDEV(packet_rate) as stddev_packet_rate,
            AVG(byte_rate) as avg_byte_rate,
            STDDEV(byte_rate) as stddev_byte_rate
        FROM ndpi_flows
        WHERE timestamp_start BETWEEN :start AND :end;
    """)
    try:
        with engine.connect() as connection:
            result = connection.execute(query, {"start": start_time, "end": end_time})
            riga = result.fetchone()
            stats = dict(zip(result.keys(), riga)) if riga else {}
            return json.dumps(stats, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nel calcolo delle statistiche di baseline: {str(e)}"

@mcp.tool()
def query_by_rate(threshold: float, metric: str = "packet_rate", ragionamento_investigativo: str = "Identificazione anomalie volumetriche e potenziali attacchi DoS/DDoS") -> str:
    """
    Interroga i flussi che violano una soglia matematica (threshold) sulla metrica scelta 
    ('packet_rate' o 'byte_rate'). Consente l'identificazione di attacchi DDoS/DoS (Scenario B).
    """
    _ = ragionamento_investigativo

    if metric not in ["packet_rate", "byte_rate"]:
        return "[ERRORE TOOL]: la metrica inserita deve essere 'packet_rate' o 'byte_rate'."
        
    query = text(f"""
        SELECT community_id, src_ip, dst_ip, dst_port, protocol, packet_rate, byte_rate, duration_ms
        FROM ndpi_flows
        WHERE {metric} > :threshold
        ORDER BY {metric} DESC
        LIMIT 15;
    """)
    try:
        with engine.connect() as connection:
            result = connection.execute(query, {"threshold": threshold})
            colonne = result.keys()
            flussi = [dict(zip(colonne, riga)) for riga in result.fetchall()]
            
            for f in flussi:
                f["protocol"] = arricchisci_protocollo(int(f["protocol"]))
            return json.dumps(flussi, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nell'analisi volumetrica: {str(e)}"


# =====================================================================
# CATEGORIA C: INVESTIGAZIONE ENDPOINT (Top Talker & Host Profiling)
# =====================================================================

@mcp.tool()
def get_top_talkers(start_time: str, end_time: str, top_n: int = 10, criterion: str = "bytes", ragionamento_investigativo: str = "Identificazione degli host dominanti per volume o frequenza") -> str:
    """
    Identifica gli host che hanno dominato il traffico per volume ('bytes') o frequenza ('packets')
    esclusivamente all'interno dell'intervallo temporale specificato (Formato: YYYY-MM-DD HH:MM:SS).
    """
    _ = ragionamento_investigativo

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
        with engine.connect() as connection:
            result = connection.execute(query, {"start": start_time, "end": end_time, "top_n": top_n})
            colonne = result.keys()
            host = [dict(zip(colonne, riga)) for riga in result.fetchall()]
            return json.dumps(host, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nel calcolo dei Top Talkers: {str(e)}"

@mcp.tool()
def analyze_dpi_details(ip: str, ragionamento_investigativo: str = "Ispezione profonda L7 dei metadati e cifratura TLS per l'host") -> str:
    """
    Esegue il drill-down profondo di livello 7 su un host specifico.
    Estrae metadati nDPI quali: ndpi_hostname, payload_entropy, infra_provider e cifratura TLS.
    """
    _ = ragionamento_investigativo

    query = text("""
        SELECT community_id, src_ip, dst_ip, dst_port, protocol, app_hierarchy, 
               ndpi_hostname, payload_entropy, infra_provider, tls_version, tls_cipher_suite
        FROM ndpi_flows
        WHERE src_ip = :ip OR dst_ip = :ip
        ORDER BY timestamp_start DESC
        LIMIT 15;
    """)
    try:
        with engine.connect() as connection:
            result = connection.execute(query, {"ip": ip})
            colonne = result.keys()
            flussi = [dict(zip(colonne, riga)) for riga in result.fetchall()]
            
            for f in flussi:
                f["protocol"] = arricchisci_protocollo(int(f["protocol"]))
            return json.dumps(flussi, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nell'ispezione DPI di dettaglio: {str(e)}"

@mcp.tool()
def resolve_host_info(ip: str, ragionamento_investigativo: str = "Risoluzione metadati infrastrutturali e identificazione provider cloud") -> str:
    """
    Arricchisce il profilo dell'host tramite i metadati infrastrutturali raccolti da nDPI.
    Permette all'LLM di distinguere tra servizi cloud legittimi e domini generici.
    """
    _ = ragionamento_investigativo

    query = text("""
        SELECT DISTINCT ndpi_hostname, infra_provider
        FROM ndpi_flows
        WHERE (src_ip = :ip OR dst_ip = :ip) 
          AND (ndpi_hostname IS NOT NULL OR infra_provider IS NOT NULL)
        LIMIT 10;
    """)
    try:
        with engine.connect() as connection:
            result = connection.execute(query, {"ip": ip})
            colonne = result.keys()
            info = [dict(zip(colonne, riga)) for riga in result.fetchall()]
            return json.dumps(info, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nella risoluzione delle info host: {str(e)}"


# =====================================================================
# CATEGORIA D: ANALISI COMPORTAMENTALE (Brute Force / Infiltration)
# =====================================================================

@mcp.tool()
def search_connection_attempts(target_port: int, start_time: str, end_time: str, ragionamento_investigativo: str = "Isolamento pattern sequenziali ad alta frequenza (Brute Force / Scansioni)") -> str:
    """
    Isola i pattern sequenziali ad alta frequenza verso porte sensibili (Brute Force / Beaconing)
    avvenuti nell'intervallo temporale indicato (Formato: YYYY-MM-DD HH:MM:SS).
    """
    _ = ragionamento_investigativo

    query = text("""
        SELECT src_ip, dst_ip, dst_port, COUNT(*) as tentativi_totali, 
               AVG(duration_ms) as durata_media_ms,
               AVG(iat_flow_avg) as inter_arrival_time_medio
        FROM ndpi_flows
        WHERE dst_port = :port 
          AND timestamp_start BETWEEN :start AND :end
        GROUP BY src_ip, dst_ip, dst_port
        HAVING tentativi_totali > 5
        ORDER BY tentativi_totali DESC
        LIMIT 15;
    """)
    try:
        with engine.connect() as connection:
            result = connection.execute(query, {"port": target_port, "start": start_time, "end": end_time})
            colonne = result.keys()
            flussi = [dict(zip(colonne, riga)) for riga in result.fetchall()]
            return json.dumps(flussi, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nell'analisi dei tentativi sequenziali: {str(e)}"

@mcp.tool()
def get_flow_features(ip: str, ragionamento_investigativo: str = "Estrazione feature statistiche temporali profonde (IAT) per temporal reasoning") -> str:
    """
    Estrae le feature statistiche temporali profonde (come l'Inter-Arrival Time IAT) per un IP.
    Permette all'LLM di eseguire Temporal Reasoning su pattern ciclici costanti (es. Heartbeat Botnet).
    """
    _ = ragionamento_investigativo

    query = text("""
        SELECT community_id, dst_ip, dst_port, protocol, duration_ms, 
               iat_flow_avg, iat_flow_stddev, payload_entropy, tcp_flags
        FROM ndpi_flows
        WHERE src_ip = :ip
        ORDER BY timestamp_start DESC
        LIMIT 15;
    """)
    try:
        with engine.connect() as connection:
            result = connection.execute(query, {"ip": ip})
            colonne = result.keys()
            flussi = [dict(zip(colonne, riga)) for riga in result.fetchall()]
            
            for f in flussi:
                f["protocol"] = arricchisci_protocollo(int(f["protocol"]))
            return json.dumps(flussi, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nell'estrazione delle flow features: {str(e)}"

# Connettore per il drill-down trasversale 
@mcp.tool()
def analizza_connessione_by_community_id(cid: str, ragionamento_investigativo: str = "Drill-down granulare su singolo flusso logico tramite Community ID") -> str:
    """
    Esegue un'operazione di Drill-Down granulare estraendo i dettagli logici di un singolo 
    flusso a partire dal suo identificativo unico community_id.
    """
    _ = ragionamento_investigativo

    query = text("""
        SELECT community_id, src_ip, src_port, dst_ip, dst_port, protocol, duration_ms,
               total_bytes, packet_rate, payload_entropy, app_hierarchy, ndpi_hostname, infra_provider
        FROM ndpi_flows 
        WHERE community_id = :cid
        LIMIT 1;
    """)
    try:
        with engine.connect() as connection:
            result = connection.execute(query, {"cid": cid})
            colonne = result.keys()
            riga = result.fetchone()
            
            if not riga:
                return f"[ERRORE TOOL]:Nessun flusso di dettaglio trovato per il community_id: {cid}."
                
            flusso = dict(zip(colonne, riga))
            flusso["protocol"] = arricchisci_protocollo(int(flusso["protocol"]))
            return json.dumps(flusso, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nel Drill-Down per community_id: {str(e)}"

if __name__ == "__main__":
    mcp.run(transport='stdio')
