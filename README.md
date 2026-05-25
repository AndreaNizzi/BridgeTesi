# Pipeline di Elaborazione dei dati del dataset CIC-IDS-2017 e Popolamento del db MySQL

Questo repository contiene gli script Python per la gestione, l'unione e il popolamento su database MySQL dei dati estratti dai 5 file PCAP del dataset, combinando i flussi ufficiali di CIC con le estrazioni locali (CICFlowMeter e nDPI).

## Requisiti

Prima di eseguire gli script, assicurarsi di avere installato le librerie Python necessarie:

```bash
pip install pandas numpy sqlalchemy pymysql
```

*Nota: Per la generazione dei dati in locale è richiesta la presenza di **CICFlowMeter** e **ndpiReader** installati nel sistema*

## Il Dataset

Il progetto utilizza i dati del dataset pubblico **CIC-IDS-2017** fornito dal *Canadian Institute for Cybersecurity (CIC)*. 
I 5 file PCAP originali (corrispondenti ai giorni della settimana da Lunedì a Venerdì) e i relativi CSV ufficiali frammentati possono essere scaricati dal sito ufficiale:

**Link al Dataset:** [CIC-IDS-2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html)

*Nota: A causa delle dimensioni elevate dei file PCAP (circa 50 GB complessivi), questi non sono inclusi nella repository e vanno scaricati autonomamente posizionandoli nelle cartelle di lavoro.*

## Configurazione Database

Prima di avviare gli script di popolamento, è necessario preparare l'istanza MySQL creando il database e le tabelle dedicate.

### 1. Creazione del Database 

Accedi al tuo terminale MySQL ed esegui:

```sql
CREATE DATABASE cic_ndpi_analysis;
USE cic_ndpi_analysis;
```

### 2. Creazione delle Tabelle

Esegui le seguenti query SQL per generare le due tabelle normalizzate. Entrambe utilizzano come chiave primaria il *flow_id* calcolato per l'uniformazione dei dati.

Tabella *ndpi_flows* (Dati estratti con ndpiReader)

```sql
CREATE TABLE ndpi_flows (
    flow_id VARCHAR(64) PRIMARY KEY,
    
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
    
    tcp_flags VARCHAR(32),            -- Memorizzato come bitmask 
    ndpi_hostname VARCHAR(255),       
    payload_entropy DOUBLE,           
    app_hierarchy VARCHAR(100),       
    infra_provider VARCHAR(100),      
    
    tls_version VARCHAR(10),          
    tls_cipher_suite VARCHAR(100),    
    tls_ja4 VARCHAR(36),                    
    tls_issuer_dn VARCHAR(255)              
);
```

Tabella *cic_flows* (Dati arricchiti CICFlowMeter)

```sql
CREATE TABLE cic_flows (
    flow_id VARCHAR(64) PRIMARY KEY,   
    
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
    
    label VARCHAR(50) DEFAULT 'BENIGN'
);
```

### 3. Configurazione delle Credenziali negli Script

All'interno dei file *Popola_DB_CSV_Ufficiali.py* e *Popola_DB_json_ndpiReader.py* è presente un blocco di configurazione per la connessione al database tramite SQLAlchemy e il driver PyMySQL.

Prima di eseguire gli script, assicurarsi di modificare le seguenti variabili con i propri dati di accesso locali:

```python
# Sostituisci questi valori con le credenziali del tuo MySQL locale:
db_user = 'root'            # Il tuo nome utente MySQL
db_pass = 'password'    # La tua password di MySQL
db_host = 'localhost'       # L'indirizzo del server (es. localhost)
db_name = 'cic_ndpi_analysis'  # Il nome del database creato precedentemente
```

## Pipeline

Gli script vanno eseguiti nell'ordine descritto di seguito per processare correttamente i dati prima del caricamento nel database.

1. Aggregazione dei CSV Ufficiali

Il dataset iniziale fornisce 5 file PCAP e i relativi CSV ufficiali (alcuni PCAP presentano più file CSV frammentati).

```bash
py .\\Merge_Ufficiali.py
```

Cosa fa: Aggrega i vari CSV frammentati nei 5 file CSV principali, facendoli corrispondere esattamente ai 5 file PCAP originari.

2. Join delle Label (CICFlowMeter)

Dopo aver eseguito in locale CICFlowMeter sui 5 file PCAP per ottenere i CSV locali:

```bash
py .\\Join_CSV.py \<File_CICFlowMeter.csv\> \<File_Ufficiale.csv\> \<Output_Join_CSV_x.csv\>
```

Cosa fa: Esegue un join tra i CSV estratti localmente e i CSV ufficiali precedentemente aggregati. Questo passaggio permette di arricchire i dati generati in locale con le rispettive *Label* presenti nel dataset ufficiale.

3. Estrazione JSON con nDPI

In parallelo, gli stessi 5 file PCAP sono stati passati a *ndpiReader* per ottenere i file di output in formato *.json*.

4. Popolamento del Database MySQL

Lo schema MySQL è strutturato in due tabelle distinte per accogliere i due diversi output (con i campi timestamp e flow_id normalizzati per uniformare i dati). Per popolare il database si utilizzano i seguenti script:

Per i dati CIC (CSV):

```bash
py .\\Popola_DB_CSV_Ufficiali.py \<Output_Join_CSV_x.csv\>
```
Per i dati nDPI (JSON):

```bash
py .\\Popola_DB_json_ndpiReader.py \<Output_ndpiReader_x.json\>
```
