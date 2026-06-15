import sys
import pandas as pd
from ipaddress import ip_address
import communityid  

# Inizializziamo il generatore Community ID
CID = communityid.CommunityID()

def calc_community_id(sip, dip, sport, dport, proto):
    """
    Calcoliamo il Community ID per un flusso di rete.
    Gestendo le inversioni natie della libreria per i flussi bidirezionali.
    """
    try:
        src_ip = ip_address(str(sip).strip())
        dst_ip = ip_address(str(dip).strip())
        proto_num = int(str(proto).strip())

        s = int(str(sport).strip())
        d = int(str(dport).strip())

        if proto_num == 6:
            tpl = communityid.FlowTuple.make_tcp(src_ip, dst_ip, s, d)
        elif proto_num == 17:
            tpl = communityid.FlowTuple.make_udp(src_ip, dst_ip, s, d)
        elif proto_num == 1:
            tpl = communityid.FlowTuple.make_icmp(src_ip, dst_ip, s, d)
        elif proto_num == 58:
            tpl = communityid.FlowTuple.make_icmp6(src_ip, dst_ip, s, d)
        else:
            return "error"

        return CID.calc(tpl)
    except Exception:
        return "error"

def auto_detect_columns(columns):
    """Rileviamo automaticamente i nomi delle colonne cruciali basandosi su keyword."""
    cols = {}
    for c in columns:
        cl = str(c).lower().strip()
        if ('src' in cl or 'source' in cl) and 'ip' in cl: cols['src'] = c
        elif ('dst' in cl or 'dest' in cl) and 'ip' in cl: cols['dst'] = c
        elif ('src' in cl or 'source' in cl) and 'port' in cl: cols['sp'] = c
        elif ('dst' in cl or 'dest' in cl) and 'port' in cl: cols['dp'] = c
        elif 'protocol' in cl or cl == 'proto': cols['pr'] = c
        elif 'label' in cl or 'class' in cl: cols['label'] = c
        elif 'timestamp' in cl: cols['ts'] = c
        elif 'flow duration' in cl or cl == 'duration': cols['dur'] = c
    return cols

def normalize_proto(series):
    """Mappiamo i protocolli testuali nei rispettivi ID numerici in formato stringa."""
    proto_map = {"TCP": "6", "UDP": "17", "ICMP": "1", "ICMPV6": "58"}
    s = series.astype(str).str.strip().str.upper().replace(proto_map)
    return pd.to_numeric(s, errors="coerce").astype("Int64").astype(str)

def prepare_ports(df, sp_col, dp_col):
    """Normalizziamo le porte convertendole in stringhe pulite."""
    df["s_port"] = pd.to_numeric(df[sp_col], errors="coerce").astype("Int64").astype(str)
    df["d_port"] = pd.to_numeric(df[dp_col], errors="coerce").astype("Int64").astype(str)
    return df

def build_community_ids(df, cols_map):
    """Generiamo la colonna Community_ID per l'intero dataframe."""
    df["Community_ID"] = [
        calc_community_id(sip, dip, sport, dport, proto)
        for sip, dip, sport, dport, proto in zip(
            df[cols_map["src"]],
            df[cols_map["dst"]],
            df["s_port"],
            df["d_port"],
            df["proto_clean"],
        )
    ]
    return df

def parse_timestamp_column(df, colname, tz="Europe/Rome"):
    """Parsiamo in modo robusto i timestamp forzando i formati noti per evitare inversioni mese/giorno."""
    # Proviamo prima il formato 12h con AM/PM (miei file)
    ts = pd.to_datetime(df[colname], format='%d/%m/%Y %I:%M:%S %p', errors="coerce")
    # Se fallisce o restituisce NaT, proviamo il formato 24h (file ufficiali)
    if ts.isna().all():
        ts = pd.to_datetime(df[colname], format='%d/%m/%Y %H:%M:%S', errors='coerce')
    # Fallback generico se nessuno dei formati ha funzionato
    if ts.isna().all():
        ts = pd.to_datetime(df[colname], dayfirst=True, errors='coerce')

    if getattr(ts.dt, "tz", None) is None:
        ts = ts.dt.tz_localize(tz, nonexistent="shift_forward", ambiguous="NaT")
    else:
        ts = ts.dt.tz_convert(tz)
    return ts

def main():
    if len(sys.argv) != 4:
        print("Uso: python join_CSV.py <file_miei.csv> <file_ufficiali.csv> <output.csv>")
        sys.exit(1)

    path_miei, path_off, path_out = sys.argv[1], sys.argv[2], sys.argv[3]

    print(f"[INFO] Caricamento {path_miei} (I tuoi dati)...")
    df_miei = pd.read_csv(path_miei, low_memory=False)

    print(f"[INFO] Caricamento {path_off} (Dati ufficiali)...")
    df_ufficiale = pd.read_csv(path_off, encoding='cp1252', low_memory=False)

    # Puliamo spazi bianchi dagli header
    df_miei.columns = df_miei.columns.str.strip()
    df_ufficiale.columns = df_ufficiale.columns.str.strip()

    # Mapping automatico delle colonne indispensabili
    miei_cols = auto_detect_columns(df_miei.columns)
    off_cols = auto_detect_columns(df_ufficiale.columns)

    # Verifichiamo la presenza delle colonne minime obbligatorie
    required = ['src', 'dst', 'sp', 'dp', 'pr', 'ts']
    for req in required:
        if req not in miei_cols:
            print(f"[ERRORE] Mappatura fallita per la colonna {req} nei tuoi dati.")
            sys.exit(1)
        if req not in off_cols:
            print(f"[ERRORE] Mappatura fallita per la colonna {req} nei dati ufficiali.")
            sys.exit(1)

    # Normalizzaziamo Protocollo e Rimuoviamo righe con valori nulli nei campi chiave
    df_miei["proto_clean"] = normalize_proto(df_miei[miei_cols["pr"]])
    df_ufficiale["proto_clean"] = normalize_proto(df_ufficiale[off_cols["pr"]])

    df_miei = df_miei.dropna(subset=[miei_cols["src"], miei_cols["dst"], miei_cols["sp"], miei_cols["dp"], miei_cols["ts"]])
    df_ufficiale = df_ufficiale.dropna(subset=[off_cols["src"], off_cols["dst"], off_cols["sp"], off_cols["dp"], off_cols["ts"]])

    # Normalizziamo porte
    df_miei = prepare_ports(df_miei, miei_cols["sp"], miei_cols["dp"])
    df_ufficiale = prepare_ports(df_ufficiale, off_cols["sp"], off_cols["dp"])

    # Calcoliamo i Community ID
    print("[INFO] Generazione Community ID per i tuoi dati...")
    df_miei = build_community_ids(df_miei, miei_cols)

    print("[INFO] Generazione Community ID per i dati ufficiali...")
    df_ufficiale = build_community_ids(df_ufficiale, off_cols)

    # Filtriamo gli errori di hashing
    df_miei = df_miei[df_miei["Community_ID"] != "error"].copy()
    df_ufficiale = df_ufficiale[df_ufficiale["Community_ID"] != "error"].copy()

    actual_label_col = off_cols.get("label", "Label")
    if actual_label_col not in df_ufficiale.columns:
        print("[ERRORE] Colonna Label non trovata nei dati ufficiali.")
        sys.exit(1)

    # Parsing dei Timestamp
    tz = "Europe/Rome"
    df_miei["ts_parsed"] = parse_timestamp_column(df_miei, miei_cols["ts"], tz)
    df_ufficiale["ts_parsed"] = parse_timestamp_column(df_ufficiale, off_cols["ts"], tz)

    print("[INFO] Calcolo dell'offset temporale in corso...")
    sample = pd.merge(
        df_miei[["Community_ID", "ts_parsed"]],
        df_ufficiale[["Community_ID", "ts_parsed"]],
        on="Community_ID",
        how="inner"
    ).dropna()

    if not sample.empty:
        delta = (sample["ts_parsed_y"] - sample["ts_parsed_x"]).median()
        print(f"[INFO] Offset calcolato automaticamente: {delta}")
    else:
        delta = pd.Timedelta(hours=0)
        print(f"[ATTENZIONE] Impossibile stimare l'offset (zero match). Fallback a {delta}")

    # Allineamo i tempi al secondo
    df_ufficiale["ts_align"] = (df_ufficiale["ts_parsed"] - delta).dt.floor("S")
    df_miei["ts_align"] = df_miei["ts_parsed"].dt.floor("S")

    # Chiavi di Join
    join_left_keys = ["Community_ID", "ts_align"]
    join_right_keys = ["Community_ID", "ts_align"]

    # Disambiguazione con la durata del flusso
    if "dur" in miei_cols and "dur" in off_cols:
        df_miei["dur_s"] = pd.to_numeric(df_miei[miei_cols["dur"]], errors="coerce").round().astype("Int64")
        df_ufficiale["dur_s"] = pd.to_numeric(df_ufficiale[off_cols["dur"]], errors="coerce").round().astype("Int64")
        #join_left_keys.append("dur_s")
        #join_right_keys.append("dur_s")

    print("[INFO] Esecuzione del merge finale...")
    # Seleziamo solo le chiavi e la colonna Label dal df ufficiale per evitare duplicati di colonne di metriche
    df_ufficiale_sub = df_ufficiale[join_right_keys + [actual_label_col]].copy()
    
    # Rinominiamo la label ufficiale direttamente prima del merge per pulizia
    if actual_label_col != "Label":
        df_ufficiale_sub.rename(columns={actual_label_col: "Label"}, inplace=True)

    df_finale = pd.merge(
        df_miei,
        df_ufficiale_sub,
        left_on=join_left_keys,
        right_on=join_right_keys,
        how="left",
        validate="m:1"  # Un flusso nei tuoi dati corrisponde ad un solo record ufficiale allineato temporalmente
    )

    # Puliamo le colonne di join duplicate nate dal merge
    for c in join_right_keys:
        if f"{c}_y" in df_finale.columns:
            df_finale.drop(columns=[f"{c}_y"], inplace=True)
        if f"{c}_x" in df_finale.columns:
            df_finale.rename(columns={f"{c}_x": c}, inplace=True)

    # Puliamo e normalizziamo i valori nulli o "No Label" nella colonna finale
    df_finale["Label"] = (
        df_finale["Label"]
        .astype("string")
        .replace(["No Label", "", "nan", "None", "NaN"], "Unknown")
        .fillna("Unknown")
    )

    cols_to_drop = ["proto_clean", "s_port", "d_port", "Community_ID", "ts_parsed", "ts_align", "dur_s"]
    df_finale.drop(columns=cols_to_drop, inplace=True, errors="ignore")

    print(f"[INFO] Salvataggio del file finale in {path_out}...")
    df_finale.to_csv(path_out, index=False)

    print("\n[INFO] Matching Completato con successo! Distribuzione delle Label:")
    print(df_finale["Label"].value_counts(dropna=False))

if __name__ == "__main__":
    main()
