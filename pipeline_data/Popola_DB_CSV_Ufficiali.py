import sys
import os
import pandas as pd
import numpy as np
from sqlalchemy import create_engine
from sqlalchemy import text
from communityid import CommunityID, FlowTuple

# Inizializziamo il generatore Community ID standard
cid = CommunityID()

# funzione per caricare i dati a blocchi 
def insert(df, table_name, engine, chunksize=10000):
    columns = ", ".join([f"`{col}`" for col in df.columns])
    placeholders = ", ".join([f":{col}" for col in df.columns])
    query = text(f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})")
    
    # dividiamo il dataframe in blocchi per non saturare la memoria
    with engine.begin() as connection:
        for i in range(0, len(df), chunksize):
            chunk = df.iloc[i:i + chunksize]
            data = chunk.to_dict(orient='records')
            connection.execute(query, data)

def genera_community_id(src_ip, dst_ip, src_port, dst_port, protocol):
    """
    Generiamo il Community ID standard usando la libreria ufficiale.
    Garantisce la bi-direzionalità automatica indipendentemente dall'ordine dei pacchetti.
    """
    try:
        s_ip = str(src_ip).strip()
        d_ip = str(dst_ip).strip()
        sp = int(float(src_port))
        dp = int(float(dst_port))
        p = int(float(protocol))
        
        # Creiamo l'oggetto FlowTuple 
        flow = FlowTuple(p, s_ip, d_ip, sp, dp)
        # Calcoliamo il Community ID 
        return cid.calc(flow)
    except Exception:
        return None

def parse_cic_timestamp_iso(series):
    """
    Parser specifico per i timestamp del dataset CIC. 
    Gestisce i formati a 12 ore privi dell'indicatore AM/PM.
    """
    s = series.astype(str).str.strip()
    
    res = pd.to_datetime(s, format='%d/%m/%Y %H:%M:%S', errors='coerce')
    mask = res.isna()
    if mask.any():
        res.loc[mask] = pd.to_datetime(s.loc[mask], format='%d/%m/%Y %H:%M', errors='coerce')
    
    mask_ancora_na = res.isna()
    if mask_ancora_na.any():
        res.loc[mask_ancora_na] = pd.to_datetime(s.loc[mask_ancora_na], errors='coerce', dayfirst=True)

    # Algorittmo di riconoscimento del pomeriggio
    ore_grezze = res.dt.hour

    # Se l'ora è tra 1 e 5 (pomeriggio), sommiamo 12 ore per portarla a 13-17.
    pomeriggio_attivato = (ore_grezze >= 1) & (ore_grezze <= 5)
    
    res.loc[pomeriggio_attivato] = res.loc[pomeriggio_attivato] + pd.to_timedelta('12 hours')
    
    return res

def main():

    # Definiamo la lista dei file puliti generati nella pipeline precedente
    files_da_elaborare = [
        'Lunedi-Pulito-Definitivo.csv',
        'Martedi-Pulito-Definitivo.csv',
        'Mercoledi-Pulito-Definitivo.csv',
        'Giovedi-Pulito-Definitivo.csv',
        'Venerdi-Pulito-Definitivo.csv'
    ]
    
    # Configurazione db
    db_user = 'root'
    db_pass = 'b/GKS07-sh&6'  
    db_host = 'localhost'
    db_name = 'thesis_network'
    
    print("Connessione al database MySQL...")
    engine = create_engine(f'mysql+pymysql://{db_user}:{db_pass}@{db_host}/{db_name}')

    # Iteriamo in modo automatico su ogni file della lista
    for csv_file in files_da_elaborare:
        print("\n" + "="*50)
        print(f"INIZIO ELABORAZIONE AUTOMATICA: {csv_file}")
        print("="*50)
        
        if not os.path.exists(csv_file):
            print(f"[ERRORE] Il file '{csv_file}' non esiste nella cartella corrente.")
            sys.exit(1) 
        
        print(f"Lettura di {csv_file} in corso...")
        try:
            df = pd.read_csv(csv_file, low_memory=False, on_bad_lines='skip')
            # Rimuoviamo spazi bianchi dai nomi delle colonne
            df.columns = df.columns.str.strip()
        except Exception as e:
            print(f"[ERRORE] Durante la lettura di {csv_file}: {e}")
            sys.exit(1)

        # Mappatura CSV -> db (Resta invariata rispetto al tuo codice)
        mappa_colonne = {
            'Source IP': 'src_ip',        
            'Destination IP': 'dst_ip',   
            'Source Port': 'src_port',
            'Destination Port': 'dst_port',
            'Protocol': 'protocol',
            'Timestamp': 'timestamp_start',
            'Flow Duration': 'duration_ms',
            'Flow Bytes/s': 'byte_rate', 
            'Flow Packets/s': 'packet_rate',
            'Flow IAT Mean': 'iat_flow_avg',
            'Flow IAT Std': 'iat_flow_stddev',
            'Total Fwd Packets': 'fwd_packets',
            'Total Backward Packets': 'bwd_packets',
            'Total Length of Fwd Packets': 'total_fwd_bytes',
            'Total Length of Bwd Packets': 'total_bwd_bytes',
            'Label': 'label'
        }

        # Rinominiamo le colonne nel DataFrame 
        colonne_presenti = {k: v for k, v in mappa_colonne.items() if k in df.columns}
        df.rename(columns=colonne_presenti, inplace=True)
        print(f"[DEBUG COLONNE] Colonne effettive nel DF dopo il rename: {list(df.columns)}")

        if 'timestamp_start' in df.columns:
            df['timestamp_start'] = parse_cic_timestamp_iso(df['timestamp_start'])
            df.sort_values(by='timestamp_start', inplace=True, ignore_index=True)

        df['duration_ms'] = (pd.to_numeric(df['duration_ms'], errors='coerce').fillna(0) / 1000).astype(int)
        df['total_fwd_bytes'] = pd.to_numeric(df['total_fwd_bytes'], errors='coerce').fillna(0)
        df['total_bwd_bytes'] = pd.to_numeric(df['total_bwd_bytes'], errors='coerce').fillna(0)
        df['total_bytes'] = df['total_fwd_bytes'] + df['total_bwd_bytes']

        # Standardizziamo i campi della 5-tupla per il Community ID
        df['src_port'] = pd.to_numeric(df['src_port'], errors='coerce').fillna(0).astype(int)
        df['dst_port'] = pd.to_numeric(df['dst_port'], errors='coerce').fillna(0).astype(int)
        df['protocol'] = pd.to_numeric(df['protocol'], errors='coerce').fillna(0).astype(int)

        print("[INFO] Generazione Community ID per i dati ufficiali...")
        df['community_id'] = [
            genera_community_id(src, dst, sp, dp, pr)
            for src, dst, sp, dp, pr in zip(
                df['src_ip'], df['dst_ip'], df['src_port'], df['dst_port'], df['protocol']
            )
        ]

        # Rimuoviamo i flussi dove il calcolo del community_id è fallito 
        df = df.dropna(subset=['community_id'])

        # Selezioniamo i campi destinazione mappati nel db
        colonne_db_target = [
            'community_id', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 
            'timestamp_start', 'duration_ms', 'total_bytes', 'fwd_packets', 
            'bwd_packets', 'total_fwd_bytes', 'total_bwd_bytes', 'packet_rate', 
            'byte_rate', 'iat_flow_avg', 'iat_flow_stddev', 'label'
        ]

        colonne_da_caricare = [c for c in colonne_db_target if c in df.columns]
        df_finale = df[colonne_da_caricare].copy()

        print("Pulizia del dataset: rimozione dei valori infiniti (inf) e NaN...")
        df_finale.replace([np.inf, -np.inf], np.nan, inplace=True)

        colonne_numeriche = df_finale.select_dtypes(include=[np.number]).columns
        df_finale[colonne_numeriche] = df_finale[colonne_numeriche].fillna(0)

        df_finale['timestamp_start'] = pd.to_datetime(df_finale['timestamp_start'], errors='coerce')
        df_finale['timestamp_start'] = df_finale['timestamp_start'].fillna(pd.Timestamp.now())
        df_finale['timestamp_start'] = df_finale['timestamp_start'].dt.tz_localize(None)
        
        colonne_testo = df_finale.select_dtypes(include=['object', 'string']).columns
        colonne_testo = [c for c in colonne_testo if c != 'timestamp_start']
        df_finale[colonne_testo] = df_finale[colonne_testo].fillna(np.nan).replace({np.nan: None})
        
        # Convertiamo la colonna nel formato ISO string esatto 'YYYY-MM-DD HH:MM:SS.ffffff'
        df_finale['timestamp_start'] = df_finale['timestamp_start'].dt.strftime('%Y-%m-%d %H:%M:%S.%f')

        print(f"Campi pronti al push: {list(df_finale.columns)}")
        print(f"Inizio caricamento bulk di {len(df_finale)} flussi nella tabella 'cic_flows'...")
        
        try:
            insert(df_finale, 'cic_flows', engine, chunksize=20000)
            print(f"{csv_file} caricato nel DB con successo!")
        except Exception as e:
            print(f"[ERRORE] Durante l'importazione di {csv_file}: {e}")
        
    print("\n All clear! Tutti i file disponibili sono stati inseriti nel Database.")

if __name__ == "__main__":
    main()
