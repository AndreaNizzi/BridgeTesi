# Pipeline di Data Processing & Ingestion (CIC-IDS-2017 & nDPI)

Questo repository contiene un framework modulare in Python progettato per l'estrazione, la bonifica, la correlazione e il popolamento su database relazionale MySQL dei flussi di rete estratti dal dataset pubblico **CIC-IDS-2017**, combinando i flussi statistici ufficiali arricchiti con metriche applicative avanzate tramite Deep Packet Inspection (*nDPI*).

---

## Architettura del Workflow

L'intera pipeline è strutturata in macro-fasi sequenziali per garantire l'interoperabilità di tool eterogenei, gestendo le anomalie temporali native e ottimizzando l'ingestion bulk su storage engine InnoDB.

```text
  [File CSV Grezzi ISCX]                     [Traffico PCAP]
            │                                       │
            ▼                                       ▼
 [ FASE 0: PRE-PROCESSING ]                     ndpiReader
 (preprocessing.py)                                 │
            │                                       │
            ▼                                       ▼
 [CSV Giornalieri Puliti]                      [JSON Lines]
            │                                       │
            ▼                                       ▼
 [ FASE 1: MERGE & LABEL ]           [ FASE 2: DPI EXTRACTION ]
 (join_CSV.py)                       (Popola_DB_json_ndpiReader.py)
            │                                       │
            └───┬───────────────────────────────────┘
                │
                ▼
    [ FASE 3: TIME ALIGNMENT ] ──► Correzione Offset (-5h CIC / -3h nDPI)
                │
                ▼
    [ FASE 4: BULK INGESTION ] ──► Transazioni Atomiche (Chunksize: 20k)
                │
                ▼
    [ FASE 5: CROSS-JOIN ]    ──► Sliding Window (±5s) & Indici Compositi
```

## Requisiti e Dipendenze

Assicurarsi di aver installato le librerie Python necessarie prima di avviare la pipeline:

```bash
pip install pandas numpy sqlalchemy pymysql communityid
```

*Nota: Per la generazione dei dati in locale è richiesta la presenza di **CICFlowMeter** e **ndpiReader** installati nel sistema*

## Il Dataset

Il progetto utilizza i dati del dataset pubblico **CIC-IDS-2017** fornito dal *Canadian Institute for Cybersecurity (CIC)*. 
I 5 file PCAP originali (corrispondenti ai giorni della settimana da Lunedì a Venerdì) e i relativi CSV ufficiali frammentati possono essere scaricati dal sito ufficiale:

**Link al Dataset:** [CIC-IDS-2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html)

*Nota: A causa delle dimensioni elevate dei file PCAP (circa 50 GB complessivi), questi non sono inclusi nella repository e vanno scaricati autonomamente posizionandoli nelle cartelle di lavoro.*

## Configurazione Database

Prima di avviare gli script di popolamento, è necessario preparare l'istanza MySQL creando il database e le tabelle dedicate.

### 1. Inizializzazione Schema

Accedi al tuo terminale MySQL ed esegui:

```sql
CREATE DATABASE cic_ndpi_analysis;
USE cic_ndpi_analysis;
```

### 2. Generazione Tabelle

Esegui le seguenti query SQL per generare le due tabelle normalizzate. Entrambe utilizzano come chiave primaria surrogata (id) di tipo intero sequenziale per prevenire la frammentazione dei blocchi di memoria su disco (page splitting) causata dalla casualità degli hash stringa. Il community_id viene preservato come chiave di correlazione multi-istanza.

Tabella *ndpi_flows* (Dati estratti con ndpiReader)

```sql
CREATE TABLE ndpi_flows (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    community_id VARCHAR(50) NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    src_port INT UNSIGNED NOT NULL,
    dst_port INT UNSIGNED NOT NULL,
    protocol INT UNSIGNED NOT NULL,
    timestamp_start TIMESTAMP(6) NOT NULL,
    duration_ms DOUBLE NOT NULL,      
    total_bytes BIGINT UNSIGNED NOT NULL,
    fwd_packets BIGINT UNSIGNED NOT NULL,
    bwd_packets BIGINT UNSIGNED NOT NULL,
    total_fwd_bytes BIGINT UNSIGNED NOT NULL,
    total_bwd_bytes BIGINT UNSIGNED NOT NULL,
    packet_rate DOUBLE NOT NULL,
    byte_rate DOUBLE NOT NULL,
    iat_flow_avg DOUBLE NOT NULL,
    iat_flow_stddev DOUBLE NOT NULL,
    tcp_flags INT NULL,                -- Memorizzato come bitmask intera
    ndpi_hostname VARCHAR(255) NULL,       
    payload_entropy DOUBLE NULL,           
    app_hierarchy VARCHAR(100) NULL,       
    infra_provider VARCHAR(100) NULL,      
    tls_version VARCHAR(10) NULL,          
    tls_cipher_suite VARCHAR(100) NULL,    
    tls_ja4 VARCHAR(36) NULL,                    
    tls_issuer_dn VARCHAR(255) NULL,
    INDEX idx_ndpi_comm_time (community_id(50), timestamp_start),
    INDEX idx_src_ip (src_ip)
);
```

Tabella *cic_flows* (Dati arricchiti CICFlowMeter + Label)

```sql
CREATE TABLE cic_flows (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    community_id VARCHAR(50) NOT NULL,
    src_ip VARCHAR(45) NOT NULL,      
    dst_ip VARCHAR(45) NOT NULL,
    src_port INT UNSIGNED NOT NULL,    
    dst_port INT UNSIGNED NOT NULL,
    protocol INT UNSIGNED NOT NULL,   
    timestamp_start TIMESTAMP(6) NOT NULL, 
    duration_ms DOUBLE NOT NULL,      
    total_bytes BIGINT UNSIGNED NOT NULL,  
    fwd_packets BIGINT UNSIGNED NOT NULL,
    bwd_packets BIGINT UNSIGNED NOT NULL,
    total_fwd_bytes BIGINT UNSIGNED NOT NULL,
    total_bwd_bytes BIGINT UNSIGNED NOT NULL,
    packet_rate DOUBLE NOT NULL,
    byte_rate DOUBLE NOT NULL,
    iat_flow_avg DOUBLE NOT NULL,
    iat_flow_stddev DOUBLE NOT NULL,
    label VARCHAR(50) NULL DEFAULT 'BENIGN',
    INDEX idx_cic_comm_time (community_id(50), timestamp_start),
    INDEX idx_label (label)
);
```

### 3. Configurazione Credenziali Script

All'interno dei file *Popola_DB_CSV_Ufficiali.py* e *Popola_DB_json_ndpiReader.py* è presente un blocco di configurazione per la connessione al database tramite SQLAlchemy e il driver PyMySQL.

Prima di eseguire gli script, assicurarsi di modificare le seguenti variabili con i propri dati di accesso locali:

```python
# Sostituisci questi valori con le credenziali del tuo MySQL locale:
db_user = 'root'            # Il tuo nome utente MySQL
db_pass = 'password'    # La tua password di MySQL
db_host = 'localhost'       # L'indirizzo del server (es. localhost)
db_name = 'cic_ndpi_analysis'  # Il nome del database creato precedentemente
```

## Pipeline d'Esecuzione

Eseguire gli script rispettando l'ordine cronologico descritto per garantire l'integrità referenziale dei dati.

Passo 0: Consolidamento e Pre-processing

Pulisce i file CSV originali ISCX rimuovendo le righe di header duplicate, normalizzando gli spazi bianchi e gestendo le eccezioni matematiche (Infinity e NaN).

```bash
python preprocessing.py
```

Output: Generazione dei file purificati e unificati `*--Pulito-Definitivo.csv`.

Passo 1: Matching e Labeling 

Eseguire in locale CICFlowMeter sui 5 file PCAP per ottenere i CSV locali.

Esegue il calcolo del Community ID bidirezionale e applica il pd.merge_asof (tolleranza ± 15s) per associare i flussi generati in locale alle rispettive etichette del dataset ufficiale, correggendo lo shift del formato orario pomeridiano (Fix AM/PM).

```bash
python join_CSV.py <File_CICFlowMeter_Locale.csv> <File_Ufficiale_Pulito.csv> <Output_Join_Giorno.csv>
```

Passo 2: Estrazione Metadati Avanzati (nDPI)

Elaborazione del traffico PCAP nativo tramite il motore di Deep Packet Inspection

```bash
./ndpiReader --cfg "tls,max_num_blocks_to_analyze,8" -i <file_cattura.pcap> -K json -k <output_ndpi.json>
```

Passo 3 & 4: Ingestion Massiva nel DBMS

l popolamento dei record strutturati avviene tramite transazioni atomiche a blocchi concorrenti (chunksize=20000).

Per i dati CIC (CSV):

```bash
python Popola_DB_CSV_Ufficiali.py 
```
Per i dati nDPI (JSON):

Caricamento Automatizzato:
Sfrutta l'approccio stream-based riga per riga per file JSONLines di grandi dimensioni tramite un ciclo in ambiente PowerShell:

```powershell
Get-ChildItem *-WorkingHours_ndpiReader.json | ForEach-Object { python Popola_DB_json_ndpiReader.py $_.FullName }
```

## Validazione e Cross-Correlazione

A causa del troncamento dei microsecondi operato nativamente da CICFlowMeter e delle logiche di timeout eterogenee dei software, le interrogazioni sul database richiedono l'applicazione di una finestra temporale mobile (Sliding Window) impostata a ± 5 secondi combinata con la corrispondenza del Community ID:

```sql
SELECT DATE(c.timestamp_start) AS giorno, COUNT(*)
FROM cic_flows AS c JOIN ndpi_flows AS n ON c.community_id = n.community_id AND ABS(TIMESTAMPDIFF(SECOND, c.timestamp_start, n.timestamp_start)) <= 5
GROUP BY DATE(c.timestamp_start);
```
