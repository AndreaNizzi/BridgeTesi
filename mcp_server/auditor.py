import os
import re
from sqlalchemy import create_engine, text
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

DB_USER = 'root'
DB_PASS = os.environ.get("DB_PASSWORD")  
DB_HOST = 'localhost'
DB_NAME = 'thesis_network'

engine = create_engine(f'mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}')

OUTPUT_DIR = "outputs"

def ripristina_formato_data(stringa_data):
    """Convertiamo '20170703_101333' nel formato SQL '2017-07-03 10:13:33'."""
    dt = datetime.strptime(stringa_data, "%Y%m%d_%H%M%S")
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def estrai_dati_report(file_path):
    """Estraiamo l'IP, i timestamp dal nome del file e il verdetto dal testo del report."""
    nome_file = os.path.basename(file_path)
    
    match_nome = re.search(r"report_(.+)_(\d{8}_\d{6})_(\d{8}_\d{6})_cat_(.+)\.md", nome_file)
    if not match_nome:
        return None
    
    ip_target = match_nome.group(1)
    start_raw = match_nome.group(2)
    end_raw = match_nome.group(3)
    categoria = match_nome.group(4)
    
    with open(file_path, "r", encoding="utf-8") as f:
        contenuto = f.read()
        
    # Cerchiamo la riga del verdetto (es: VERDETTO: TRAFFICO BENIGNO)
    match_verdetto = re.search(r"VERDETTO:\s*(.+)", contenuto, re.IGNORECASE)

    if match_verdetto:
        verdetto_llm = match_verdetto.group(1).strip(" []_.")
    else:
        verdetto_llm = "NON TROVATO"
    
    return {
        "ip": ip_target,
        "start_time": ripristina_formato_data(start_raw),  
        "end_time": ripristina_formato_data(end_raw),      
        "categoria": categoria,
        "verdetto_llm": verdetto_llm
    }

def controlla_ground_truth(ip_target, start_time, end_time):
    """Interroghiamo il DB per vedere quante righe BENIGN o ATTACCO ci sono per quell'IP."""
    query = text("""
        SELECT c.label, COUNT(*) as conteggio
        FROM ndpi_flows as n JOIN cic_flows as c ON n.community_id = c.community_id
        WHERE (n.src_ip = :ip OR n.dst_ip = :ip) AND n.timestamp_start BETWEEN :start AND :end
        GROUP BY c.label;
    """)
    
    risultati_db = {}
    with engine.connect() as connection:
        result = connection.execute(query, {"ip": ip_target, "start": start_time, "end": end_time})
        for riga in result.fetchall():
            risultati_db[riga[0]] = riga[1]
            
    return risultati_db

def stampa_matrice_e_metriche(stats):
    """Calcoliamo le metriche di performance e stampiamo la matrice di confusione."""
    tp = stats["TP"]
    fp = stats["FP"]
    tn = stats["TN"]
    fn = stats["FN"]
    non_parsa = stats["NON_PARSABILE"]
    totale = tp + fp + tn + fn

    print("\n" + "="*70)
    print("MATRICE DI CONFUSIONE RECAP")
    print("="*70)
    print(f"            Reale: MINACCIA    Reale: BENIGNO")
    print(f"Pred: MINACCIA     TP: {tp:<12} FP: {fp:<12}")
    print(f"Pred: BENIGNO      FN: {fn:<12} TN: {tn:<12}")
    print("-"*70)
    print(f"Report non parsabili / scartati: {non_parsa}")
    print(f"Totale casi validati: {totale}")
    print("-"*70)

    if totale == 0:
        print("[ERRORE]: Nessun dato sufficiente per calcolare le metriche.")
        return

    accuracy = (tp + tn) / totale
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    print(f"Accuratezza (Accuracy): {accuracy:.2%}")
    print(f"Precisione (Precision): {precision:.2%}")
    print(f"Richiamo (Recall):      {recall:.2%}")
    print(f"F1-Score:               {f1_score:.2%}")
    print("="*70)

def esegui_auditing():
    print(f"\n" + "="*70)
    print(f"AVVIO REPORT DI AUDITING E VALIDAZIONE")
    print(f"="*70)
    
    if not os.path.exists(OUTPUT_DIR):
        print("[ERRORE]: Nessun report trovato nella cartella outputs.")
        return

    file_reports = [os.path.join(OUTPUT_DIR, f) for f in os.listdir(OUTPUT_DIR) if f.endswith(".md")]
    
    stats = {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "NON_PARSABILE": 0}

    for f_path in file_reports:
        dati = estrai_dati_report(f_path)
        if not dati:
            continue
            
        print(f"\nAnalisi file: {os.path.basename(f_path)}")
        print(f"IP Target   : {dati['ip']} (Cat: {dati['categoria'].upper()})")
        print(f"Verdetto LLM: {dati['verdetto_llm']}")
        
        ground_truth = controlla_ground_truth(dati["ip"], dati["start_time"], dati["end_time"])
        print(f"Ground Truth nel DB: {ground_truth}")
        
        ha_attacchi_reali = any(label != 'BENIGN' for label in ground_truth.keys())
        
        print("ESITO AUDITING: ", end="")
        if "BENIGNO" in dati["verdetto_llm"].upper():
            if not ha_attacchi_reali:
                print("TRUE NEGATIVE (TN) - L'LLM ha classificato correttamente il traffico sicuro.")
                stats["TN"] += 1
            else:
                print("FALSE NEGATIVE (FN) - L'LLM ha mancato una minaccia presente nel DB!")
                stats["FN"] += 1
        elif "MINACCIA" in dati["verdetto_llm"].upper():
            if ha_attacchi_reali:
                print("TRUE POSITIVE (TP) - L'LLM ha intercettato correttamente l'attacco!")
                stats["TP"] += 1
            else:
                print("FALSE POSITIVE (FP) - Falso Allarme! L'LLM ha visto una minaccia dove non c'era.")
                stats["FP"] += 1
        else:
            print("VERDETTO LLM NON PARSABILE")
            stats["NON_PARSABILE"] += 1
            
    print(f"\n" + "="*70)
    print("FINE ANALISI DEI FILE")
    print("="*70)

    stampa_matrice_e_metriche(stats)

if __name__ == "__main__":
    esegui_auditing()
