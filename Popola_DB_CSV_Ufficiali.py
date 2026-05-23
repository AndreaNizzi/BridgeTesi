import pandas as pd
import sys
import os
import numpy as np
import hashlib
from sqlalchemy import create_engine
from sqlalchemy import types

def main():
    if len(sys.argv) < 2:
        print("Uso: py Popola_DB_CSV_Ufficiali.py <nome_file.csv>")
        return

    csv_file = sys.argv[1]
    
    # configurazione db
    db_user = 'root'
    db_pass = 'b/GKS07-sh&6'  
    db_host = 'localhost'
    db_name = 'thesis_network'
    
    print("Connessione al database MySQL...")
    engine = create_engine(f'mysql+pymysql://{db_user}:{db_pass}@{db_host}/{db_name}')

    print(f"Lettura del file {csv_file} in corso...")
    if not os.path.exists(csv_file):
        print(f"[ERRORE] Il file '{csv_file}' non esiste.")
        return  
    
    try:
        df = pd.read_csv(
            csv_file, 
            low_memory=False,
            on_bad_lines='skip'
        )
        # rimuoviamo spazi bianchi nascosti all'inizio/fine dei nomi delle colonne 
        df.columns = df.columns.str.strip()
    except Exception as e:
        print(f"[ERRORE] Durante la lettura del CSV: {e}")
        return

    # mappatura CSV -> db
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

    # rinominiamo le colonne nel DataFrame
    df.rename(columns=mappa_colonne, inplace=True)

    df['total_bytes'] = df['total_fwd_bytes'].astype(float) + df['total_bwd_bytes']

    print("Conversione dei timestamp in formato DATETIME ISO...")
    df['timestamp_start'] = pd.to_datetime(df['timestamp_start'], errors='coerce')
    df['timestamp_start'] = df['timestamp_start'].fillna(pd.Timestamp.now())

    # standardizziamo i campi della 5-tupla per garantire la compatibilità delle stringhe
    df['src_port'] = df['src_port'].astype(float).fillna(0).astype(int)
    df['dst_port'] = df['dst_port'].astype(float).fillna(0).astype(int)
    df['protocol'] = df['protocol'].astype(float).fillna(0).astype(int)

    # creiamo la stringa chiave 
    stringa_chiave = (
        df['src_ip'].astype(str) + '-' +
        df['dst_ip'].astype(str) + '-' +
        df['src_port'].apply(lambda x: f"{x}") + '-' +
        df['dst_port'].apply(lambda x: f"{x}") + '-' +
        df['protocol'].apply(lambda x: f"{x}")
    )

    # applichiamo l'hash MD5 su ogni riga
    df['flow_id'] = stringa_chiave.apply(lambda x: hashlib.md5(x.encode('utf-8')).hexdigest())

    print(f"Rimozione flussi duplicati nel DataFrame... Righe iniziali: {len(df)}")
    df.drop_duplicates(subset=['flow_id'], keep='first', inplace=True)
    print(f"Righe residue dopo la rimozione duplicati: {len(df)}")

    # selezioniamo i campi destinazione mappati nel db
    colonne_db_target = [
        'flow_id', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 
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

    print(f"Campi pronti al push: {list(df_finale.columns)}")
    print(f"Inizio caricamento bulk di {len(df_finale)} flussi nella tabella 'cic_flows'...")
    
    try:
        df_finale.to_sql(
            name='cic_flows', 
            con=engine, 
            if_exists='append', 
            index=False, 
            dtype={'timestamp_start': types.DateTime()},
            chunksize=10000
        )
        print("Db popolato con successo!")
    except Exception as e:
        print(f"[ERRORE] Durante l'importazione CIC: {e}")

if __name__ == "__main__":
    main()
