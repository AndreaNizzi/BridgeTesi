import sys
import os
import json
import hashlib
import pandas as pd
import numpy as np
from sqlalchemy import create_engine
from sqlalchemy import types
from sqlalchemy import text
from datetime import datetime

# funzione per caricare i dati a blocchi 
def insert_ignore(df, table_name, engine, chunksize=10000):
    columns = ", ".join(df.columns)
    placeholders = ", ".join([f":{col}" for col in df.columns])
    query = text(f"INSERT IGNORE INTO {table_name} ({columns}) VALUES ({placeholders})")
    
    # dividiamo il dataframe in blocchi per non saturare la memoria
    with engine.begin() as connection:
        for i in range(0, len(df), chunksize):
            chunk = df.iloc[i:i + chunksize]
            data = chunk.to_dict(orient='records')
            connection.execute(query, data)

def genera_custom_flow_id(src_ip, dst_ip, src_port, dst_port, protocol):
    # generiamo un ID univoco basato sulla 5-tupla e usiamo l'MD5 per creare una stringa fissa di 32 caratteri.
    stringa_chiave = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{protocol}"
    return hashlib.md5(stringa_chiave.encode('utf-8')).hexdigest()

def main():
    if len(sys.argv) != 2:
        print("Uso: py Popola_DB_json_ndpiReader.py <input_file.json>")
        sys.exit(1)

    input_file = sys.argv[1]

    print(f"Lettura del file {input_file} in corso...")
    if not os.path.exists(input_file):
        print(f"[ERRORE] Il file '{input_file}' non esiste.")
        sys.exit(1)

    # configurazione db
    db_user = 'root'
    db_pass = 'b/GKS07-sh&6'  
    db_host = 'localhost'
    db_name = 'thesis_network'
    
    print("Connessione al database MySQL...")
    engine = create_engine(f'mysql+pymysql://{db_user}:{db_pass}@{db_host}/{db_name}')

    print(f"Caricamento e analisi dati da {input_file}...")
    righe_flat = []

    # lettura del file JSON Lines riga per riga
    with open(input_file, 'r') as f:
        for linea in f:
            try:
                linea_pulita = linea.strip()
                if not linea_pulita:
                    continue
                    
                dati = json.loads(linea_pulita)

                ndpi_obj = dati.get('ndpi', {})

                contiene_entropia_sospetta = 0
                flow_risk = ndpi_obj.get('flow_risk', {})

                if isinstance(flow_risk, dict):
                    for _, risk_info in flow_risk.items():
                        if isinstance(risk_info, dict) and risk_info.get('risk') == 'Susp Entropy':
                            contiene_entropia_sospetta = 1      # flag a 1 se l'entropia è anomala

                src_ip = dati.get('src_ip')
                dst_ip = dati.get('dest_ip') 
                src_port = dati.get('src_port')
                dst_port = dati.get('dst_port')
                
                proto_raw = str(dati.get('proto', '')).upper()
                if 'TCP' in proto_raw:
                    protocol = 6
                elif 'UDP' in proto_raw:
                    protocol = 17
                elif 'ICMP' in proto_raw:
                    protocol = 1
                else:
                    # se è già un numero o è un protocollo strano, proviamo a convertirlo in int, altrimenti usiamo 0
                    try:
                        protocol = int(dati.get('proto', 0))
                    except:
                        protocol = 0

                # assicuriamoci che le porte siano numeri interi puliti 
                try:
                    src_port_clean = int(float(src_port))
                except:
                    src_port_clean = 0
                    
                try:
                    dst_port_clean = int(float(dst_port))
                except:
                    dst_port_clean = 0

                # convertiamo i timestamp in formato DATETIME ISO
                first_seen_epoch = dati.get('first_seen')
                if first_seen_epoch:
                    try:
                        timestamp_iso = datetime.fromtimestamp(float(first_seen_epoch)).strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        timestamp_iso = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                else:
                    timestamp_iso = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                # generiamo del flow_id 
                flow_id_custom = genera_custom_flow_id(src_ip, dst_ip, src_port_clean, dst_port_clean, protocol)
                
                xfer_obj = dati.get('xfer', {})
                iat_obj = dati.get('iat', {})
                tls_obj = ndpi_obj.get('tls', {})
                tcp_flags_obj = dati.get('tcp_flags', {})

                # calcoliamo bitmap dei flags TCP
                fin = 1 if tcp_flags_obj.get('fin_count', 0) > 0 else 0
                syn = 1 if tcp_flags_obj.get('syn_count', 0) > 0 else 0
                rst = 1 if tcp_flags_obj.get('rst_count', 0) > 0 else 0
                psh = 1 if tcp_flags_obj.get('psh_count', 0) > 0 else 0
                ack = 1 if tcp_flags_obj.get('ack_count', 0) > 0 else 0
                urg = 1 if tcp_flags_obj.get('urg_count', 0) > 0 else 0
                ece = 1 if tcp_flags_obj.get('ece_count', 0) > 0 else 0
                cwr = 1 if tcp_flags_obj.get('cwr_count', 0) > 0 else 0
                
                # bitwise standard di rete
                tcp_flags_bitmap = (fin * 1 + syn * 2 + rst * 4 + psh * 8 + ack * 16 + urg * 32 + ece * 64 + cwr * 128)

                fwd_bytes = xfer_obj.get('src2dst_bytes', 0)
                bwd_bytes = xfer_obj.get('dst2src_bytes', 0)
                total_bytes = fwd_bytes + bwd_bytes

                fwd_pkts = xfer_obj.get('src2dst_packets', 0)
                bwd_pkts = xfer_obj.get('dst2src_packets', 0)
                total_pkts = fwd_pkts + bwd_pkts

                duration_sec = dati.get('duration', 0)
                duration_ms = duration_sec * 1000

                packet_rate = (total_pkts / duration_sec) if duration_sec > 0 else 0
                byte_rate = (total_bytes / duration_sec) if duration_sec > 0 else 0

                # mappiamo i dati corretti
                flusso_mappato = {
                    'flow_id': flow_id_custom,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port_clean,
                    'dst_port': dst_port_clean,
                    'protocol': protocol,
                    'timestamp_start': timestamp_iso,
                    'duration_ms': int(duration_ms),
                    'total_bytes': total_bytes,
                    'fwd_packets': fwd_pkts,
                    'bwd_packets': bwd_pkts,
                    'total_fwd_bytes': fwd_bytes,
                    'total_bwd_bytes': bwd_bytes,
                    'packet_rate': packet_rate,
                    'byte_rate': byte_rate,
                    'iat_flow_avg': iat_obj.get('flow_avg', 0),
                    'iat_flow_stddev': iat_obj.get('flow_stddev', 0),
                    'tcp_flags': tcp_flags_bitmap,
                    'ndpi_hostname': ndpi_obj.get('hostname', ''),
                    'payload_entropy': contiene_entropia_sospetta,
                    'app_hierarchy': ndpi_obj.get('proto', dati.get('proto', '')),
                    'infra_provider': ndpi_obj.get('proto_by_ip', ''),
                    'tls_version': tls_obj.get('version') if tls_obj else None,
                    'tls_cipher_suite': tls_obj.get('cipher') if tls_obj else None,
                    'tls_ja4': tls_obj.get('ja4') if tls_obj else None,
                    'tls_issuer_dn': tls_obj.get('issuerDN') if tls_obj else None
                }

                righe_flat.append(flusso_mappato)
                
            except Exception as e:
                continue

    # creiamo il DataFrame Pandas dalle righe strutturate
    df_finale = pd.DataFrame(righe_flat)

    if df_finale.empty:
        print("Nessun dato valido estratto dal file JSON. Controllo interrotto.")
        return
    
    print(f"Rimozione flussi duplicati nel DataFrame... Righe iniziali: {len(df_finale)}")
    df_finale.drop_duplicates(subset=['flow_id'], keep='first', inplace=True)
    print(f"Righe residue dopo la rimozione duplicati: {len(df_finale)}")

    print("Pulizia del dataset: rimozione dei valori infiniti (inf) e NaN...")
    df_finale.replace([np.inf, -np.inf], np.nan, inplace=True)
    colonne_numeriche = df_finale.select_dtypes(include=[np.number]).columns
    df_finale[colonne_numeriche] = df_finale[colonne_numeriche].fillna(0)
    colonne_testo = df_finale.select_dtypes(include=['object', 'string']).columns
    df_finale[colonne_testo] = df_finale[colonne_testo].fillna(np.nan).replace({np.nan: None})

    # assicuriamoci che la colonna data sia gestita correttamente come tipo datetime in Pandas
    df_finale['timestamp_start'] = pd.to_datetime(df_finale['timestamp_start'])

    print(f"Inizio caricamento bulk di {len(df_finale)} flussi nella tabella 'ndpi_flows'...")
    try:
        insert_ignore(df_finale, 'ndpi_flows', engine, chunksize=20000)
        print("Db popolato con successo!")
    except Exception as e:
        print(f"[ERRORE] Durante l'importazione dei dati di ndpiReader: {e}")

if __name__ == "__main__":
    main()
