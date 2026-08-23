import os
from sqlalchemy import create_engine
from dotenv import load_dotenv

load_dotenv()

MAX_DRILLDOWN_TURNS = 10
MIN_CHAR_LIMIT = 80  
MAX_TENTATIVI_CORREZIONE = 3
MAX_ERRORI_GLOBALI = 5
MAX_RETRY_REPORT = 3

# Configurazione Connessione Database 
DB_USER = 'root'
DB_PASS = os.environ.get("DB_PASSWORD")  
DB_HOST = 'localhost'
DB_NAME = 'thesis_network'

try:
    engine = create_engine(f'mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}')
except Exception as e:
    print(f"Errore nella creazione dell'engine SQLAlchemy: {e}")
    engine = None

VERDETTI_AMMESSI = [
    "DOS_VOLUMETRIC",
    "SCAN_BRUTEFORCE",
    "BEACONING_C2",
    "WEB_ATTACK_EXPLOIT",
    "BENIGN"
]

FOCUS_CATEGORIE = {
    "cat_a": (
        "REGOLE SPECIFICHE: CATEGORIA A (Analisi Strutturale e Applicativa L7)\n"
        "Segui rigorosamente questa gerarchia di valutazione:\n\n"
        "1. PRIORITÀ 1 (EXPLOIT WEB / XSS / SQLi) [EARLY STOP MANDATORIO]:\n"
        "   - Ispeziona i flussi HTTP con 'search_http_l7_anomalies' o DPI.\n"
        "   - IF 'web_exploits_rilevati' > 0 OPPURE sono presenti anomalie L7 (XSS, SQLi, Path Traversal) -> THEN VERDETTO = 'WEB_ATTACK_EXPLOIT'.\n"
        "   - REGOLA TASSATIVA DI STOP: Se la condizione sopra è VERIFICATA, DEVI immediatamente interrompere l'analisi ed emettere il verdetto 'WEB_ATTACK_EXPLOIT'. NON interrogare tool di rate o di scansione. IGNORA qualsiasi successivo segnale di DoS o Scan.\n\n"
        "2. PRIORITÀ 2 (SCAN / BRUTE FORCE):\n"
        "   - Solo se NON vi è ALCUN exploit Web L7, E vi sono tentativi falliti o ripetuti su SSH/FTP (porta 22/21) o port scan conclamato -> THEN VERDETTO = 'SCAN_BRUTEFORCE'.\n\n"
        "3. DEFAULT: Se le richieste HTTP sono legittime e privissime di anomalie applicative -> VERDETTO = 'BENIGN'."
    ),
    "cat_b": (
        "REGOLE SPECIFICHE: CATEGORIA B (Monitoraggio Volumetrico e DoS / Flood)\n"
        "- RULE #1 (DoS Volumetrico): IF 'avg_packet_rate' > 1000.0 pps OPPURE 'max_packet_rate' >= 5000.0 pps -> THEN VERDETTO = 'DOS_VOLUMETRIC'.\n"
        "- RULE #2 (Banda Saturata): IF 'avg_byte_rate' > 10000000.0 (10MB/s) OPPURE 'max_byte_rate' >= 20000000.0 -> THEN VERDETTO = 'DOS_VOLUMETRIC'.\n"
        "- DEFAULT: Se sia i valori medi che i valori massimi restano sotto le soglie critiche -> VERDETTO = 'BENIGN'."
    ),
    "cat_c": (
        "REGOLE SPECIFICHE: CATEGORIA C (Profiling Endpoint / Scanning / Slow-Rate DoS)\n"
        "- RULE #1 (PortScan / BruteForce): IF mappa porte mostra PortScan (>=2 porte distinte con tentativi multipli) OPPURE tentativi di autenticazione falliti su SSH/FTP -> THEN VERDETTO = 'SCAN_BRUTEFORCE'.\n"
        "- RULE #2 (Slow-Rate L7 DoS / Slowloris): IF la durata di un flusso HTTP/HTTPS supera i 300 secondi (duration_ms > 300000) E i byte totali sono bassi (<100KB) OPPURE presente flag 'FLAG_SLOWLORIS_SUSPECT' -> THEN VERDETTO = 'SCAN_BRUTEFORCE'.\n"
        "- DEFAULT: Se non sono presenti PortScan, Brute Force o Slowloris -> VERDETTO = 'BENIGN'."
    ),
    "cat_d": (
        "REGOLE SPECIFICHE: CATEGORIA D (Analisi Comportamentale / Beaconing C2 / Persistence / Botnet)\n"
        "- RULE #1 (Beaconing C2 / Botnet): IF 'detect_beaconing' individua Anomaly Score >= 75 OR tag 'STABLE_PERIODICITY' "
        "OR è presente ANCHE UN SOLO FLUSSO classificato come 'Bot' / 'C2' -> THEN VERDETTO = 'BEACONING_C2'.\n"
        "- RULE #1B (Porte C2 / Proxy e Anomaly Score Basso): Qualsiasi comunicazione ripetuta o persistente verso porte C2/Proxy "
        "non standard (es. 8080, 8443) diretta a IP esterni costituisce MALEVOLENZA. NON ignorare questi flussi anche se l'Anomaly Score è basso (es. < 30).\n"
        "  * REGOLA DI SQUILIBRIO: Non considerare la percentuale sul totale dei flussi. Anche la presenza minatoria di soli 2 flussi Bot/C2 rende l'intero host MALEVOLO (BEACONING_C2).\n"
        "- RULE #2 (DNS Tunneling / High Vol DNS): IF il numero di flussi DNS (porta 53) è > 30 verso la stessa destinazione anomala OPPURE presente tag 'FLAG_DNS_TUNNELING_SUSPECT' -> THEN VERDETTO = 'BEACONING_C2'.\n"
        "- PRIORITÀ E FOCUS D: Concentra l'analisi sul comportamento temporale e sulla persistenza. Se sono presenti traccia anche minime di C2, Botnet o DNS Tunneling, il verdetto DEVE essere 'BEACONING_C2'. Assegna verdetti di DoS o Scan solo in assenza totale di C2 e di fronte a prove volumetrice conclamate. Se il traffico è privo di anomalie cicliche o malevole -> VERDETTO = 'BENIGN'."
    ),
    "cat_e": (
        "REGOLE SPECIFICHE: ANALISI GENERICA LIBERA (CASCATA DETERMINISTICA RIGIDA)\n"
        "Valuta il traffico seguendo QUESTO ORDINE TASSATIVO DI PRIORITÀ:\n\n"
        "1. PRIORITÀ 1 (BEACONING C2 / BOTNET):\n"
        "   - IF presente QUALSIASI flusso etichettato come 'Bot', 'C2', 'Beacon' (ANCHE SOLI 1-5 FLUSSI su migliaia BENIGNI) OR Anomaly Score Beaconing >= 75 -> THEN VERDETTO = 'BEACONING_C2'.\n"
        "   - Non applicare soglie minime di volume per questa minaccia.\n\n"
        "2. PRIORITÀ 2 (EXPLOIT WEB / L7):\n"
        "   - IF presenti exploit web conclamati (SQLi, XSS, Path Traversal) o payload malevoli HTTP -> THEN VERDETTO = 'WEB_ATTACK_EXPLOIT'.\n\n"
        "3. PRIORITÀ 3 (DOS VOLUMETRICO):\n"
        "   - REQUISITO MINIMO: Il totale dei flussi dell'host deve essere > 50 AND 'avg_packet_rate' > 1000.0 pps. Se l'host ha <= 50 flussi totali, la valutazione DoS è AUTOMATICAMENTE FALSE.\n"
        "   - Picchi isolati e temporanei su un numero limitato di flussi DEVONO ESSERE IGNORATI.\n\n"
        "4. PRIORITÀ 4 (SCAN / BRUTE FORCE):\n"
        "   - IF presente PortScan strutturato (>=2 porte scansionate con connessioni multiple fallite) OR tentativi reiterati Brute Force SSH/FTP -> THEN VERDETTO = 'SCAN_BRUTEFORCE'.\n"
        "   - Connessioni singole e isolato rumore di fondo NON costituiscono uno Scan.\n\n"
        "5. DEFAULT ASSOLUTO (PROTEZIONE FALSI POSITIVI):\n"
        "   - Se non sono verificate le priorità 1, 2, 3 e 4 -> VERDETTO = 'BENIGN'.\n"
        "   - In presenza di traffico ordinario o flussi privi di violazioni esplicite delle regole sopra riportate, l'unica risposta valida è 'BENIGN'."
    )
}

def genera_prompt_iniziale(ip_target: str, start_time_iso: str, end_time_iso: str, cat_tag: str) -> str:
    """Genera il prompt di sistema uniforme per client.py e test_suite.py."""
    istruzioni_focus = FOCUS_CATEGORIE.get(
        cat_tag, 
        "ANALISI GENERICA: Non applicare bias o vincoli preimpostati. Esplora i dati liberamente e determina la natura del traffico basandoti sulle evidenze forensi riscontrate."
    )
    return (
        "Sei un motore di classificazione deterministico per traffico di rete.\n"
        f"Target: {ip_target}\n\n"
        "PARAMETRI TEMPORALI OBBLIGATORI PER OGNI CHIAMATA TOOL:\n"
        f"  - start_time: '{start_time_iso}'\n"
        f"  - end_time: '{end_time_iso}'\n"
        "DIVIETO ASSOLUTO: È severamente vietato inventare o alterare gli anni o le date (es. NON usare 2023, 2024, 2025). "
        "In TUTTE le chiamate ai tool devi passare esattamente queste stringhe per start_time e end_time.\n\n"
        "PROTOCOLLO DI ESECUZIONE (RIGIDO):\n"
        "1. VALUTAZIONE DETERMINISTICA: Segui esclusivamente le REGOLE SPECIFICHE della categoria selezionata senza applicare scorciatoie esterne.\n"
        "2. REGOLE DI EFFICIENZA ED EARLY STOP:\n"
        "   - EFFICIENZA TOOL: Utilizza preferibilmente i tool di sintesi globale ('search_http_l7_anomalies', 'get_rate_statistics', 'analyze_dpi_details', 'detect_beaconing').\n"
        "   - DIVIETO DUPLICATI: È tassativamente vietato richiamare uno stesso tool con i medesimi parametri se hai già ottenuto la risposta.\n"
        "   - EARLY STOP (FONDAMENTALE): Non appena verifichi che le condizioni di una regola di attacco sono soddisfatte (es. BEACONING_C2), STOP! NON chiamare altri tool. Dichiaralo subito con la riga 'VERDETTO: <NOME_VERDETTO>'.\n"
        "3. USO DEI COMMUNITY ID:\n"
        "   - Non inventare mai i valori di 'community_id' (es. non unire IP e porte manualmente).\n"
        "   - Utilizza ESCLUSIVAMENTE le stringhe 'community_id' reali e identiche a quelle restituite nei JSON dei tool di primo livello.\n"
        "4. ISOLAMENTO CATEGORIA: Rispetta tassativamente la gerarchia decisionale indicata di seguito.\n\n"
        f"{istruzioni_focus}"
    )
