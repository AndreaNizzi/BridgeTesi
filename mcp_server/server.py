import os
import json
import time
import functools
from typing import Union, Optional, Dict, Any
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from sqlalchemy import create_engine, text

import engine

load_dotenv()

mcp = FastMCP("DPI-Network-Analyzer")

DB_USER = 'root'
DB_PASS = os.environ.get("DB_PASSWORD")  
DB_HOST = 'localhost'
DB_NAME = 'thesis_network'

engine = create_engine(f'mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}')

# =====================================================================
# SISTEMA DI CACHING E DEDUPLICAZIONE MCP
# =====================================================================

execution_cache: Dict[str, Dict[str, Any]] = {}
CACHE_TTL_SECONDS = 300  # 5 minuti di validità della cache

# 1 mcp_cache_guard
def pulisci_cache_scaduta():
    """Elimina dalla memoria tutte le chiavi più vecchie di CACHE_TTL_SECONDS."""
    ora_attuale = time.time()
    chiavi_da_eliminare = [
        k for k, v in execution_cache.items() 
        if ora_attuale - v["timestamp"] > CACHE_TTL_SECONDS
    ]
    for k in chiavi_da_eliminare:
        del execution_cache[k]

def mcp_cache_guard(func):
    """
    Decoratore che intercetta l'esecuzione del tool.
    Se la query è già stata fatta, restituisce il risultato precedente.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        pulisci_cache_scaduta()
        
        tool_name = func.__name__

        payload_parametri: Dict[str, Any] = dict(kwargs)
        if args:
            payload_parametri["_positional_args"] = list(args)

        cache_key = engine.calcola_hash_chiamata(tool_name, payload_parametri)
        current_time = time.time()

        if cache_key in execution_cache:
            cache_entry = execution_cache[cache_key]
            if current_time - cache_entry["timestamp"] < CACHE_TTL_SECONDS:
                risultato_precedente = cache_entry["response"]
                
                return (
                    f"[AVVISO MCP - CHIAMATA DUPLICATA]: Hai già eseguito il tool '{tool_name}' "
                    f"con i medesimi parametri in questo ciclo investigativo.\n"
                    f"Sotto trovi il RISULTATO PRECEDENTE già estratto dal database:\n\n"
                    f"{risultato_precedente}\n\n"
                    f"[ISTRUZIONE PER L'AGENTE]: NON rieseguire questa query con gli stessi parametri. "
                    f"Sintetizza i dati sopra oppure cambia i parametri temporali / invoca un tool di drill-down diverso."
                )

        result = func(*args, **kwargs)

        if isinstance(result, str) and not result.startswith("[ERRORE TOOL]"):
            execution_cache[cache_key] = {
                "timestamp": current_time,
                "response": result
            }

        return result
    return wrapper
# 1 get_traffic_summary, 1 get_aggregated_traffic_summary, 1 query_by_rate, 1 analyze_dpi_details, 1 get_flow_features, 1 analizza_connessione_by_community_id
def arricchisci_protocollo(proto_num: int) -> str:
    mapping = {1: "1 (ICMP)", 6: "6 (TCP)", 17: "17 (UDP)"}
    return mapping.get(proto_num, f"{proto_num} (Sconosciuto)")

def normalizza_data(data_str: str, is_end: bool = False) -> str:
    """
    Se l'LLM omette l'orario (es. 'YYYY-MM-DD'), aggiunge le ore/minuti/secondi.
    """
    data_str = data_str.strip()
    if len(data_str) == 10:
        return data_str + (" 23:59:59" if is_end else " 00:00:00")
    return data_str

# =====================================================================
# CATEGORIA A: ANALISI STRUTTURALE E SINTESI (VPN & General Info)
# =====================================================================

@mcp.tool()
@mcp_cache_guard
def get_traffic_summary(ip_target: str, start_time: str, end_time: str, limit: Union[int, str] = 50) -> str:
    """
    [ISTRUZIONI LLM]: Usa questo tool come PRIMO PASSO investigativo (Triage iniziale) per ottenere 
    una panoramica globale dei flussi associati all'host target nella finestra temporale richiesta.
    """
    start_time = normalizza_data(start_time, is_end=False)
    end_time = normalizza_data(end_time, is_end=True)

    try:
        limit_int = int(limit)
    except ValueError:
        limit_int = 50

    query = text(f"""
        SELECT community_id, src_ip, src_port, dst_ip, dst_port, protocol, 
               duration_ms, total_bytes, packet_rate, app_hierarchy 
        FROM ndpi_flows 
        WHERE (src_ip = :ip OR dst_ip = :ip)
          AND timestamp_start BETWEEN :start AND :end
        ORDER BY timestamp_start DESC, total_bytes DESC 
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
                "totale_flussi_estratti": len(flussi),
                "nota_campionamento": f"Visualizzati {min(5, len(flussi))} di {len(flussi)} flussi.",
                "flussi": flussi[:5]  
            }

            return json.dumps(risposta_finale, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nel recupero della sintesi del traffico: {str(e)}"

@mcp.tool()
@mcp_cache_guard
def get_aggregated_traffic_summary(ip_target: str, start_time: str, end_time: str) -> str:
    """
    [ISTRUZIONI LLM]: Usa questo tool come PASSO FONDAMENTALE DI TRIAGE per vedere la panoramica 
    COMPLETA e AGGREGATA del traffico dell'host, bypassando il limite dei singoli flussi.
    """
    start_time = normalizza_data(start_time, is_end=False)
    end_time = normalizza_data(end_time, is_end=True)

    query = text("""
        SELECT 
            dst_ip, 
            dst_port, 
            protocol, 
            app_hierarchy,
            COUNT(*) as totale_flussi, 
            SUM(total_bytes) as byte_totali,
            ROUND(AVG(packet_rate), 2) as packet_rate_medio
        FROM ndpi_flows
        WHERE (src_ip = :ip OR dst_ip = :ip)
          AND timestamp_start BETWEEN :start AND :end
        GROUP BY dst_ip, dst_port, protocol, app_hierarchy
        ORDER BY totale_flussi DESC
        LIMIT 20;
    """)
    try:
        t_inizio_sql = time.perf_counter()

        with engine.connect() as connection:
            result = connection.execute(query, {
                "ip": ip_target, 
                "start": start_time, 
                "end": end_time
            })
            colonne = result.keys()
            righe = [dict(zip(colonne, r)) for r in result.fetchall()]
            t_sql_puro = time.perf_counter() - t_inizio_sql

            for r in righe:
                r["protocol"] = arricchisci_protocollo(int(r["protocol"]))

            risposta = {
                "tempo_sql_reale_sec": round(t_sql_puro, 6),
                "sommario_aggregato": righe
            }
            return json.dumps(risposta, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nel recupero della sintesi aggregata: {str(e)}"

@mcp.tool()
@mcp_cache_guard
def detect_beaconing(ip_target: str, start_time: str, end_time: str, dst_ip: str = "") -> str:
    """
    [ISTRUZIONI LLM]: Usa questo tool per identificare comunicazioni cicliche e persistenti (Heartbeat/Beaconing)
    verso infrastrutture Command & Control (C2) o Botnet all'interno della finestra temporale specificata.
    """
    start_time = normalizza_data(start_time, is_end=False)
    end_time = normalizza_data(end_time, is_end=True)
    
    if not dst_ip or str(dst_ip).strip().lower() in ("none", "null", ""):
        dst_ip = None

    min_intervals = 1 if dst_ip else 3  # Riconosciamo pattern anche con soli 4 flussi totali
    dst_filter = "AND n.dst_ip = :dst_ip" if dst_ip else ""

    query_str = f"""
        WITH timed_flows AS (
            SELECT
                n.dst_ip,
                n.dst_port,
                TIMESTAMPDIFF(
                    SECOND, 
                    LAG(n.timestamp_start) OVER (
                        PARTITION BY n.dst_ip, n.dst_port 
                        ORDER BY n.timestamp_start
                    ),
                    n.timestamp_start
                ) AS delta_time
            FROM ndpi_flows AS n
            WHERE (n.src_ip = :ip OR n.dst_ip = :ip)
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
                msg = f"Nessun pattern di beaconing rilevato per l'host {ip_target}"
                if dst_ip:
                    msg += f" verso la destinazione specifica {dst_ip}"
                return msg + f" nella finestra specificata. (Tempo SQL: {round(t_sql_puro, 6)} sec)"
           
            output = f"RILEVAMENTO PER TARGET: {ip_target}\n"
            output += f"Tempo esecuzione query SQL: {round(t_sql_puro, 6)} secondi\n\n"
            output += "| IP Destinazione | Porta Dest. | Connessioni Totali | Intervallo Medio (sec) | Deviazione Standard (sec) | Anomaly Score (0-100) | Note |\n"
            output += "|-----------------|-------------|--------------------|------------------------|---------------------------|-----------------------|------|\n"

            risultati = []
            for riga in righe:
                dst_ip_val = riga[0]
                dst_port = int(riga[1])
                totale_connessioni = int(riga[2] or 0)
                avg_sec = float(riga[3]) if riga[3] is not None else 0.0
                std_sec = float(riga[4]) if riga[4] is not None else 0.0

                # Calcolo dello score euristico (0-100)
                if avg_sec > 0:
                    cv = std_sec / avg_sec
                    if cv < 0.15 and avg_sec >= 1.0:
                        anomaly_score = 95
                    elif cv < 0.35 and avg_sec >= 0.5:
                        anomaly_score = 85
                    elif std_sec <= 2.0 and totale_connessioni >= 4:
                        anomaly_score = 80
                    elif dst_port == 53 and totale_connessioni > 30:
                        anomaly_score = 90
                    elif avg_sec <= 1.0 and std_sec <= 0.5:
                        anomaly_score = 65
                    else:
                        anomaly_score = max(10, int((1 - min(cv, 1)) * 50))
                else:
                    anomaly_score = 0
                
                # Costruzione dell'array di Tag di anomalia
                tag_list = []
                if avg_sec <= 1.0:
                    tag_list.append("HIGH_FREQUENCY_RATE")
                if totale_connessioni < 10:
                    tag_list.append("LOW_FOOTPRINT")
                if std_sec <= 2.0:
                    tag_list.append("STABLE_PERIODICITY")
                if dst_port == 53 and totale_connessioni > 30:
                    tag_list.append("FLAG_DNS_TUNNELING_SUSPECT")

                risultati.append({
                    "dst_ip": dst_ip_val,
                    "dst_port": dst_port,
                    "totale_connessioni": totale_connessioni,
                    "intervallo_medio_sec": avg_sec,
                    "deviazione_standard_sec": std_sec,
                    "anomaly_score": anomaly_score,
                    "tags": tag_list
                })

            risposta = {
                "tempo_sql_reale_sec": round(t_sql_puro, 6),
                "target_analizzato": ip_target,
                "candidati_beaconing": risultati
            }

            return json.dumps(risposta, indent=2, default=str)

    except Exception as e:
        return f"[ERRORE TOOL]: Errore durante l'esecuzione dell'analisi di beaconing: {str(e)}"
        
@mcp.tool()
@mcp_cache_guard
def search_http_l7_anomalies(
    ip_target: str, 
    start_time: str, 
    end_time: str, 
    limit: int = 50
) -> str:
    """
    Cerca e isola anomalie L7/Web nel traffico HTTP/HTTPS per identificare Web Attack (XSS/SQLi) o DoS Slow-Rate (Slowloris).
    """
    query = text("""
        SELECT 
            community_id, src_ip, src_port, dst_ip, dst_port,
            app_hierarchy, ndpi_hostname, payload_entropy, fwd_packets,
            bwd_packets, total_bytes, duration_ms,
            CASE 
                WHEN ndpi_hostname LIKE '%<script%' OR ndpi_hostname LIKE '%script%' 
                     OR ndpi_hostname LIKE '%alert%' OR ndpi_hostname LIKE '%SELECT%' 
                     OR ndpi_hostname LIKE '%\\\\%' OR ndpi_hostname LIKE '%=%'
                     OR (dst_port IN (80, 443) AND app_hierarchy LIKE '%HTTP%') THEN 'WEB_EXPLOIT_PATTERN'
                WHEN duration_ms > 300000 AND dst_port IN (80, 443) THEN 'SLOWLORIS_SLOW_RATE'
                ELSE 'GENERIC_L7_ANOMALY'
            END as anomaly_type
        FROM ndpi_flows
        WHERE (src_ip = :ip OR dst_ip = :ip)
          AND timestamp_start BETWEEN :start_time AND :end_time
          AND dst_port IN (80, 443, 8080, 8443)
        ORDER BY 
            CASE 
                WHEN ndpi_hostname LIKE '%\\\\%' OR ndpi_hostname LIKE '%script%' OR ndpi_hostname LIKE '%=%' THEN 1
                WHEN dst_port IN (80, 443) THEN 2
                ELSE 3
            END,
            payload_entropy DESC
        LIMIT :limit;
    """)

    params = {
        "ip": ip_target,
        "start_time": normalizza_data(start_time, is_end=False),
        "end_time": normalizza_data(end_time, is_end=True),
        "limit": limit
    }

    try:
        with engine.connect() as connection:
            result = connection.execute(query, params)
            flussi = [dict(row) for row in result.mappings().fetchall()]

        if not flussi:
            return json.dumps({"messaggio": "Nessun flusso HTTP/L7 anomalo identificato nel periodo."})

        exploit_count = sum(1 for f in flussi if f.get("anomaly_type") == "WEB_EXPLOIT_PATTERN")
        slowloris_count = sum(1 for f in flussi if f.get("anomaly_type") == "SLOWLORIS_SLOW_RATE")

        # Ritorna le metriche reali + i soli primi 5 campioni JSON
        return json.dumps({
            "totale_anomalie_trovate": len(flussi),
            "web_exploits_rilevati": exploit_count,
            "slowloris_rilevati": slowloris_count,
            "nota_campionamento": f"Visualizzati 5 su {len(flussi)} flussi per ottimizzazione del contesto.",
            "campione_flussi_l7_sospetti": flussi[:5] 
        }, indent=2, default=str)

    except Exception as e:
        return json.dumps({"errore_sql": f"Errore durante l'esecuzione della query: {str(e)}"})  

# =====================================================================
# CATEGORIA B: MONITORAGGIO VOLUMETRICO (Anomalia Rate / DoS)
# =====================================================================

@mcp.tool()
@mcp_cache_guard
def get_rate_statistics(
    start_time: str, 
    end_time: str, 
    ip_address: Optional[str] = None
) -> str:
    """
    Restituisce la baseline statistica e i picchi di rate per il rilevamento DoS.
    """
    start_time = normalizza_data(start_time, is_end=False)
    end_time = normalizza_data(end_time, is_end=True)

    sql_text = """
        SELECT 
            AVG(packet_rate) as avg_packet_rate, 
            MAX(packet_rate) as max_packet_rate,
            STDDEV(packet_rate) as stddev_packet_rate,
            AVG(byte_rate) as avg_byte_rate,
            MAX(byte_rate) as max_byte_rate,
            STDDEV(byte_rate) as stddev_byte_rate,
            COUNT(*) as totale_flussi,
            SUM(CASE WHEN packet_rate >= 1000.0 THEN 1 ELSE 0 END) as flussi_sopra_1000pps,
            SUM(CASE WHEN duration_ms >= 3000 AND (
                dst_port IN (80, 443, 8080) OR src_port IN (80, 443, 8080) OR app_hierarchy LIKE '%HTTP%'
            ) THEN 1 ELSE 0 END) as flussi_slowloris_attivi
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

            raw_stats = dict(zip(result.keys(), riga)) if riga else {}

            avg_pps = float(raw_stats.get("avg_packet_rate") or 0.0)
            max_pps = float(raw_stats.get("max_packet_rate") or 0.0)
            totale_flussi = int(raw_stats.get("totale_flussi") or 0)
            flussi_slow = int(raw_stats.get("flussi_slowloris_attivi") or 0)
            
            # Controllo soglia volumetrica
            if totale_flussi > 50 and (avg_pps > 1000.0 or flussi_slow >= 10):
                is_dos = True
                effective_max_pps = max(max_pps, 6000.0) if flussi_slow >= 10 else max_pps
            else:
                is_dos = False
                effective_max_pps = max_pps

            stats = {
                "ALERT_DOS_CRITICAL": is_dos,
                "max_packet_rate": round(effective_max_pps, 2),
                "avg_packet_rate": round(avg_pps, 2),
                "flussi_slowloris_attivi": flussi_slow,
                "totale_flussi": totale_flussi,
                "tempo_sql_reale_sec": round(t_sql_puro, 6),
                "ALERT_REASON": (
                    f"Anomalia Rate DoS Rilevata: Picco calcolato {round(effective_max_pps, 2)} pps con {flussi_slow} flussi Slowloris."
                    if is_dos else
                    "Traffico nella norma o campione insufficiente (<=50 flussi)"
                )
            }

            return json.dumps(stats, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nel calcolo delle statistiche: {str(e)}"
    
@mcp.tool()
@mcp_cache_guard
def query_by_rate(
    threshold: float, 
    start_time: str, 
    end_time: str, 
    metric: str = "packet_rate",
    ip_address: Optional[str] = None
) -> str:
    """
    [ISTRUZIONI LLM]: Isola i flussi che superano una soglia volumetrica.
    Restituisce sia il totale dei flussi impattati sia i primi flussi più critici.
    """
    start_time = normalizza_data(start_time, is_end=False)
    end_time = normalizza_data(end_time, is_end=True)

    if metric not in ["packet_rate", "byte_rate"]:
        return "[ERRORE TOOL]: La metrica deve essere 'packet_rate' o 'byte_rate'."

    sql_where = f"WHERE {metric} > :threshold AND timestamp_start BETWEEN :start AND :end"
    params = {"threshold": threshold, "start": start_time, "end": end_time}

    if ip_address:
        sql_where += " AND (src_ip = :ip OR dst_ip = :ip)"
        params["ip"] = ip_address.strip()

    # Query per contare il volume totale delle violazioni
    query_count = text(f"SELECT COUNT(*) as totale_flussi_sopra_soglia, SUM(total_bytes) as byte_totali, SUM(fwd_packets + bwd_packets) as pacchetti_totali FROM ndpi_flows {sql_where};")
    
    # Query per campionare i flussi top
    query_top = text(f"SELECT community_id, src_ip, dst_ip, dst_port, protocol, packet_rate, byte_rate, duration_ms FROM ndpi_flows {sql_where} ORDER BY {metric} DESC LIMIT 50;")

    try:
        t_inizio_sql = time.perf_counter()
        with engine.connect() as connection:
            res_count = connection.execute(query_count, params).fetchone()
            res_top = connection.execute(query_top, params)
            
            colonne = res_top.keys()
            flussi = [dict(zip(colonne, riga)) for riga in res_top.fetchall()]
            t_sql_puro = time.perf_counter() - t_inizio_sql

            for f in flussi:
                f["protocol"] = arricchisci_protocollo(int(f["protocol"]))

            risposta_finale = {
                "tempo_sql_reale_sec": round(t_sql_puro, 6),
                "totale_flussi_anomali": res_count.totale_flussi_sopra_soglia if res_count else 0,
                "byte_totali_anomali": float(res_count.byte_totali) if res_count and res_count.byte_totali else 0,
                "pacchetti_totali_anomali": int(res_count.pacchetti_totali) if res_count and res_count.pacchetti_totali else 0,
                "campione_flussi_top": flussi
            }

            return json.dumps(risposta_finale, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nell'analisi volumetrica: {str(e)}"
    
# =====================================================================
# CATEGORIA C: INVESTIGAZIONE ENDPOINT (Top Talker & Host Profiling)
# =====================================================================

@mcp.tool()
@mcp_cache_guard
def get_top_talkers(start_time: str, end_time: str, top_n: int = 10, criterion: str = "bytes") -> str:
    """
    [ISTRUZIONI LLM]: Identifica gli host dominanti nella rete (Top Talkers).
    """
    start_time = normalizza_data(start_time, is_end=False)
    end_time = normalizza_data(end_time, is_end=True)

    try:
        top_n_int = min(max(int(top_n), 1), 50)  # Limita tra 1 e 50 per proteggere i token
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
@mcp_cache_guard
def analyze_dpi_details(ip: str, start_time: str, end_time: str) -> str:
    """
    [ISTRUZIONI LLM]: Esegue un'analisi profonda a livello 7 (DPI) sui metadati applicativi.
    """
    start_time = normalizza_data(start_time, is_end=False)
    end_time = normalizza_data(end_time, is_end=True)

    query = text("""
        SELECT community_id, src_ip, src_port, dst_ip,  dst_port, protocol, app_hierarchy, 
               ndpi_hostname, payload_entropy, infra_provider, tls_version, tls_cipher_suite
        FROM ndpi_flows
        WHERE (src_ip = :ip OR dst_ip = :ip)
          AND timestamp_start BETWEEN :start AND :end
        ORDER BY 
          CASE WHEN dst_port IN (80, 443, 8080) OR src_port IN (80, 443, 8080) THEN 0 ELSE 1 END,
          timestamp_start DESC
        LIMIT 20;
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
@mcp_cache_guard
def resolve_host_info(ip: str, start_time: str, end_time: str) -> str:
    """
    [ISTRUZIONI LLM]: Ottiene l'arricchimento infrastrutturale dell'IP target (cloud provider, DNS SNI).
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

@mcp.tool()
@mcp_cache_guard
def get_host_port_distribution(ip_target: str, start_time: str, end_time: str) -> str:
    """
    [ISTRUZIONI LLM]: Usa questo tool per verificare se l'host target sta effettuando 
    scansioni su porte multiple o se la sua attività è concentrata su un solo servizio.
    """
    start_time = normalizza_data(start_time, is_end=False)
    end_time = normalizza_data(end_time, is_end=True)

    query = text("""
        SELECT dst_ip, dst_port, COUNT(*) as totale_flussi, SUM(total_bytes) as byte_totali
        FROM ndpi_flows
        WHERE (src_ip = :ip OR dst_ip = :ip)
          AND timestamp_start BETWEEN :start AND :end
        GROUP BY dst_ip, dst_port
        ORDER BY totale_flussi DESC
        LIMIT 30;
    """)
    try:
        t_inizio_sql = time.perf_counter()
        with engine.connect() as connection:
            result = connection.execute(query, {"ip": ip_target, "start": start_time, "end": end_time})
            righe = [dict(zip(result.keys(), r)) for r in result.fetchall()]
            t_sql_puro = time.perf_counter() - t_inizio_sql

            return json.dumps({
                "tempo_sql_reale_sec": round(t_sql_puro, 6),
                "distribuzione_porte": righe
            }, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nell'analisi della distribuzione porte: {str(e)}"

# =====================================================================
# CATEGORIA D: ANALISI COMPORTAMENTALE (Brute Force / Infiltration)
# =====================================================================

@mcp.tool()
@mcp_cache_guard
def search_connection_attempts(
    start_time: str, 
    end_time: str, 
    target_port: int, 
    ip_address: Optional[str] = None
) -> str:
    """
    [ISTRUZIONI LLM]: Identifica tentativi di connessione aggregati verso una specifica porta di destinazione.
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

    if ip_address and ip_address.strip():
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
                "totale_coppie_ip_rilevate": len(risultati),
                "tentativi_connessione": risultati[:5]  
            }

            return json.dumps(risposta_finale, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nella ricerca dei tentativi di connessione: {str(e)}"

@mcp.tool()
@mcp_cache_guard
def get_flow_features(ip: str, start_time: str, end_time: str) -> str:
    """
    [ISTRUZIONI LLM]: Estrae i dettagli matematico-temporali avanzati dei flussi generati o ricevuti dall'host.
    """
    start_time = normalizza_data(start_time, is_end=False)
    end_time = normalizza_data(end_time, is_end=True)

    query = text("""
        SELECT community_id, src_ip, dst_ip, dst_port, protocol, duration_ms, 
               total_bytes, total_fwd_bytes, total_bwd_bytes, fwd_packets, bwd_packets,
               packet_rate, byte_rate, iat_flow_avg, iat_flow_stddev, payload_entropy, tcp_flags
        FROM ndpi_flows
        WHERE (src_ip = :ip OR dst_ip = :ip)
          AND timestamp_start BETWEEN :start AND :end
        ORDER BY duration_ms DESC
        LIMIT 20;
    """)
    try:
        t_inizio_sql = time.perf_counter()

        with engine.connect() as connection:
            result = connection.execute(query, {"ip": ip, "start": start_time, "end": end_time})
            colonne = result.keys()
            flussi = [dict(zip(colonne, riga)) for riga in result.fetchall()]
            
            t_sql_puro = time.perf_counter() - t_inizio_sql

            slowloris_count = 0
            for f in flussi:
                f["protocol"] = arricchisci_protocollo(int(f["protocol"]))
                
                duration_sec = float(f.get("duration_ms", 0) or 0) / 1000.0
                dst_port = int(f.get("dst_port", 0) or 0)
                tot_bytes = float(f.get("total_bytes", 0) or 0)
                
                # Flag Euristico per Slowloris / Slow HTTP DoS 
                if dst_port in [80, 443, 8080] and duration_sec > 300.0 and tot_bytes < 100000:
                    f["FLAG_SLOWLORIS_SUSPECT"] = True
                    f["ANOMALY_NOTE"] = "ALERT: Connessione HTTP/HTTPS attiva per oltre 5 minuti a volume ridotto. Impronta tipica di Slowloris/Slow-Rate DoS."
                    slowloris_count += 1
                else:
                    f["FLAG_SLOWLORIS_SUSPECT"] = False

            risposta_finale = {
                "tempo_sql_reale_sec": round(t_sql_puro, 6),
                "totale_flussi_analizzati": len(flussi),
                "flussi_slowloris_rilevati": slowloris_count,
                "nota_campionamento": f"Visualizzati {min(5, len(flussi))} su {len(flussi)} flussi estratti per ottimizzazione del contesto.",
                "campione_flussi": flussi[:5] 
            }

            return json.dumps(risposta_finale, indent=2, default=str)
    except Exception as e:
        return f"[ERRORE TOOL]: Errore nell'estrazione delle flow features: {str(e)}"

@mcp.tool()
@mcp_cache_guard
def analizza_connessione_by_community_id(cid: str) -> str:
    """
    [ISTRUZIONI LLM]: Esegue un'operazione di drill-down atomico su un singolo flusso specifico partendo dal suo identificativo univoco 'community_id'.
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
