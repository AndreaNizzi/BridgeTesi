import pandas as pd
import sys

def create_sorted_id(row, src_col, dst_col, src_port_col, dst_port_col, proto_col):
    try:
        if pd.isna(row[src_col]) or pd.isna(row[dst_col]):
            return "error"
            
        s_ip = str(row[src_col]).strip()
        d_ip = str(row[dst_col]).strip()
        
        # rimuoviamo decimali dalle porte se letti come float
        s_p = str(int(float(row[src_port_col])))
        d_p = str(int(float(row[dst_port_col])))
        
        p_raw = str(row[proto_col]).strip().upper()
        if p_raw.endswith('.0'):
            p_raw = p_raw[:-2]
            
        proto_map = {"TCP": "6", "UDP": "17", "ICMP": "1"}
        p = proto_map.get(p_raw, p_raw) 

        ips = sorted([s_ip, d_ip])
        ports = sorted([s_p, d_p])
        
        return f"{ips[0]}-{ips[1]}-{ports[0]}-{ports[1]}-{p}"
    except Exception:
        return "error"

def auto_detect_columns(columns):
    cols = {}
    for c in columns:
        cl = c.lower().strip()
        if ('src' in cl or 'source' in cl) and 'ip' in cl: cols['src'] = c
        elif ('dst' in cl or 'dest' in cl) and 'ip' in cl: cols['dst'] = c
        elif ('src' in cl or 'source' in cl) and 'port' in cl: cols['sp'] = c
        elif ('dst' in cl or 'dest' in cl) and 'port' in cl: cols['dp'] = c
        elif 'protocol' in cl or cl == 'proto': cols['pr'] = c
        elif 'label' in cl or 'class' in cl: cols['label'] = c
    return cols

def main():
    if len(sys.argv) != 4:
        print("Uso: py Join_CSV.py <file_miei.csv> <file_ufficiale.csv> <output.csv>")
        return

    print(f"Caricamento {sys.argv[1]} (dati estratti con CICFlowMeter)...")
    df_miei = pd.read_csv(sys.argv[1], low_memory=False)
    
    print(f"Caricamento {sys.argv[2]} (dati ufficiali)...")
    df_ufficiale = pd.read_csv(sys.argv[2], encoding='cp1252', low_memory=False)

    df_miei.columns = df_miei.columns.str.strip()
    df_ufficiale.columns = df_ufficiale.columns.str.strip()

    miei_cols = auto_detect_columns(df_miei.columns)
    off_cols = auto_detect_columns(df_ufficiale.columns)

    required = ['src', 'dst', 'sp', 'dp', 'pr']
    for req in required:
        if req not in miei_cols or req not in off_cols:
            print(f"[ERRORE] Mappatura fallita per la colonna {req}")
            return

    print("Generazione chiavi di matching per i dati estratti con CICFlowMeter...")
    df_miei['Sorted_Flow_ID'] = df_miei.apply(
        lambda r: create_sorted_id(r, miei_cols['src'], miei_cols['dst'], miei_cols['sp'], miei_cols['dp'], miei_cols['pr']), axis=1)
    df_miei = df_miei.copy()

    print("Generazione chiavi di matching per il dati ufficiali...")
    df_ufficiale['Sorted_Flow_ID'] = df_ufficiale.apply(
        lambda r: create_sorted_id(r, off_cols['src'], off_cols['dst'], off_cols['sp'], off_cols['dp'], off_cols['pr']), axis=1)

    validi_miei = len(df_miei[df_miei.Sorted_Flow_ID != "error"])
    validi_off = len(df_ufficiale[df_ufficiale.Sorted_Flow_ID != "error"])
    print(f"Chiavi valide generate - CICFlowMeter: {validi_miei}, Ufficiali: {validi_off}")

    df_miei = df_miei[df_miei.Sorted_Flow_ID != "error"]
    df_ufficiale = df_ufficiale[df_ufficiale.Sorted_Flow_ID != "error"]

    if 'Label' in df_miei.columns:
        df_miei = df_miei.drop(columns=['Label'])

    actual_label_col = off_cols.get('label', 'Label')
    df_labels = df_ufficiale[['Sorted_Flow_ID', actual_label_col]].drop_duplicates(subset=['Sorted_Flow_ID'])

    print("Esecuzione merge finale...")
    df_finale = pd.merge(df_miei, df_labels, on='Sorted_Flow_ID', how='left')
    
    if actual_label_col != 'Label' and actual_label_col in df_finale.columns:
        df_finale.rename(columns={actual_label_col: 'Label'}, inplace=True)
    
    df_finale['Label'] = df_finale['Label'].fillna('Unknown')
    df_finale['Label'] = df_finale['Label'].apply(lambda x: 'Unknown' if str(x).strip() in ['No Label', '', 'nan'] else x)

    print(f"Salvataggio in {sys.argv[3]}...")
    df_finale.to_csv(sys.argv[3], index=False)
    
    print("\nMatching completato:")
    print(df_finale['Label'].value_counts())

if __name__ == "__main__":
    main()
