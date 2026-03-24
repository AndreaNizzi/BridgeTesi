#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // Per access() e F_OK
#include <math.h> // Per fmod() per il timestamp
#include <sys/wait.h> // Per WIFEXITED e WEXITSTATUS
#include <cjson/cJSON.h> // Assicurati di averla installata
#include <libgen.h> // Per basename()

#define BLOCK_WINDOW_SIZE 0.5  // Durata della finestra in secondi

// Struttura per gestire i blocchi di flussi
typedef struct {
    double start_timestamp;
    int flow_count;
    char pcap_name[128];
    cJSON *batch_json;    // Array per l'LLM
    cJSON *y_true_json;   // Oggetto per la verifica (y_true)
} FlowBlock;

// Funzione per estrarre i bin non a zero
cJSON* get_sparse_bins(cJSON* bins_string_item) {
    cJSON* sparse_bins = cJSON_CreateObject();
    if (!sparse_bins) return NULL;
    if (!bins_string_item || !bins_string_item->valuestring) return sparse_bins;

    char* data = strdup(bins_string_item->valuestring);
    if (!data) return sparse_bins;
    char* token = strtok(data, ",");
    int bin_idx = 0;

    while (token != NULL) {
        int value = atoi(token);
        if (value > 0) {
            char key[16];
            snprintf(key, sizeof(key), "b%d", bin_idx);
            cJSON_AddNumberToObject(sparse_bins, key, value);
        }
        token = strtok(NULL, ",");
        bin_idx++;
    }

    free(data);
    return sparse_bins;
}

// Inizializza o resetta un blocco
void reset_block(FlowBlock *block, double first_seen) {
    if (block->batch_json) {
        cJSON_Delete(block->batch_json);
        block->batch_json = NULL; 
    }
    if (block->y_true_json) {
        cJSON_Delete(block->y_true_json);
        block->y_true_json = NULL; 
    }
    
    block->start_timestamp = first_seen;
    block->flow_count = 0;
    block->batch_json = cJSON_CreateArray();
    block->y_true_json = cJSON_CreateObject();
}

// Salva i file su disco
void save_block(FlowBlock *block, int block_id) {
    char filename[512];
    FILE *fpf;

    // 1. Salva Input per LLM
    snprintf(filename, sizeof(filename), "%s_llm_input_block_%03d.json", block->pcap_name, block_id);
    fpf = fopen(filename, "w");
    if (fpf) {
        char *out = cJSON_PrintUnformatted(block->batch_json);
        fprintf(fpf, "%s", out);
        free(out);
        fclose(fpf);
    }

    // 2. Salva y_true
    snprintf(filename, sizeof(filename), "%s_y_true_block_%03d.json", block->pcap_name, block_id);
    fpf = fopen(filename, "w");
    if (fpf) {
        char *out = cJSON_PrintUnformatted(block->y_true_json);
        fprintf(fpf, "%s", out);
        free(out);
        fclose(fpf);
    }

    printf("Blocco %03d salvato: %d flussi.\n", block_id, block->flow_count);
}

// Funzione per estrarre numeri in sicurezza
double get_safe_num(cJSON *root, const char *key) {
    cJSON *item = cJSON_GetObjectItem(root, key);
    return (item) ? item->valuedouble : 0.0;
}

// Processa il singolo flusso e lo aggiunge al blocco
void process_flow(cJSON* root, FlowBlock *block) {
    // Estraiamo gli oggetti nidificati di nDPI
    cJSON *ndpi_obj  = cJSON_GetObjectItem(root, "ndpi");
    cJSON *xfer_obj  = cJSON_GetObjectItem(root, "xfer");
    cJSON *iat_obj   = cJSON_GetObjectItem(root, "iat");
    cJSON *pktl_obj  = cJSON_GetObjectItem(root, "pktlen");
    cJSON *pbins_obj = cJSON_GetObjectItem(root, "plen_bins");
    cJSON *tcp_flags_obj  = cJSON_GetObjectItem(root, "tcp_flags");

    cJSON *id_item = cJSON_GetObjectItem(root, "flow_id");
    char flow_id[32];
    if (id_item) {
        snprintf(flow_id, sizeof(flow_id), "%d", id_item->valueint);
    } else {
        strncpy(flow_id, "0", sizeof(flow_id));
    }
    
    cJSON *proto_item = cJSON_GetObjectItem(root, "proto");
    char *proto_l4 = (proto_item && proto_item->valuestring) ? proto_item->valuestring : "UNK";

    // --- PARTE 1: INPUT LLM ---
    cJSON* f_llm = cJSON_CreateObject();
    cJSON_AddStringToObject(f_llm, "id", flow_id);
    
    // 1. OGGETTO NETWORK
    cJSON* network = cJSON_CreateObject();
    cJSON *s_ip = cJSON_GetObjectItem(root, "src_ip");
    cJSON *d_ip = cJSON_GetObjectItem(root, "dest_ip");
    cJSON_AddStringToObject(network, "src", (s_ip && s_ip->valuestring) ? s_ip->valuestring : "0.0.0.0");
    cJSON_AddStringToObject(network, "dst", (d_ip && d_ip->valuestring) ? d_ip->valuestring : "0.0.0.0");
    cJSON_AddNumberToObject(network, "sp", get_safe_num(root, "src_port"));
    cJSON_AddNumberToObject(network, "dp", get_safe_num(root, "dst_port"));
    cJSON_AddStringToObject(network, "proto", proto_l4);
    cJSON_AddNumberToObject(network, "enc", get_safe_num(ndpi_obj, "encrypted"));
    cJSON_AddItemToObject(f_llm, "network", network);

    // 2. OGGETTO CONTEXT
    cJSON* context = cJSON_CreateObject();
    cJSON *host = cJSON_GetObjectItem(ndpi_obj, "hostname");
    cJSON_AddStringToObject(context, "host", (host && host->valuestring) ? host->valuestring : "none");

    double fs = get_safe_num(root, "first_seen");
    cJSON_AddNumberToObject(context, "start", (int)fs % 10000 + (fs - (long)fs));     // Passiamo solo le ultime 4 cifre + decimali
    cJSON_AddNumberToObject(context, "dur", get_safe_num(root, "duration"));
    cJSON_AddItemToObject(f_llm, "context", context);

    // 3. OGGETTO VOLUMES
    cJSON* volumes = cJSON_CreateObject();
    cJSON_AddNumberToObject(volumes, "ratio", get_safe_num(xfer_obj, "data_ratio"));
    cJSON_AddNumberToObject(volumes, "s2d_pkts", get_safe_num(xfer_obj, "src2dst_packets"));
    cJSON_AddNumberToObject(volumes, "s2d_bytes", get_safe_num(xfer_obj, "src2dst_bytes"));
    cJSON_AddNumberToObject(volumes, "d2s_pkts", get_safe_num(xfer_obj, "dst2src_packets"));
    cJSON_AddNumberToObject(volumes, "d2s_bytes", get_safe_num(xfer_obj, "dst2src_bytes"));
    cJSON_AddNumberToObject(volumes, "d2s_gp", get_safe_num(xfer_obj, "dst2src_goodput_bytes"));
    cJSON_AddItemToObject(f_llm, "volumes", volumes);
    
    // 4. OGGETTO TIMINGS (IAT)
    cJSON* timings = cJSON_CreateObject();
    cJSON_AddNumberToObject(timings, "f_avg", get_safe_num(iat_obj, "flow_avg"));
    cJSON_AddNumberToObject(timings, "f_std", get_safe_num(iat_obj, "flow_stddev"));
    
    cJSON* c2s_iat = cJSON_CreateObject();
    cJSON_AddNumberToObject(c2s_iat, "avg", get_safe_num(iat_obj, "c_to_s_avg"));
    cJSON_AddNumberToObject(c2s_iat, "max", get_safe_num(iat_obj, "c_to_s_max"));
    cJSON_AddItemToObject(timings, "c2s", c2s_iat);
    
    cJSON* s2c_iat = cJSON_CreateObject();
    cJSON_AddNumberToObject(s2c_iat, "avg", get_safe_num(iat_obj, "s_to_c_avg"));
    cJSON_AddItemToObject(timings, "s2c", s2c_iat);
    cJSON_AddItemToObject(f_llm, "timings", timings);

    // 5. OGGETTO PKTS_STATS (Packet Length + Bins)
    cJSON* pkts = cJSON_CreateObject();
    cJSON* c2s_len = cJSON_CreateObject();
    cJSON_AddNumberToObject(c2s_len, "avg", get_safe_num(pktl_obj, "c_to_s_avg"));
    cJSON_AddNumberToObject(c2s_len, "std", get_safe_num(pktl_obj, "c_to_s_stddev"));
    cJSON_AddItemToObject(pkts, "c2s", c2s_len);

    cJSON* s2c_len = cJSON_CreateObject();
    cJSON_AddNumberToObject(s2c_len, "avg", get_safe_num(pktl_obj, "s_to_c_avg"));
    cJSON_AddNumberToObject(s2c_len, "std", get_safe_num(pktl_obj, "s_to_c_stddev"));
    cJSON_AddItemToObject(pkts, "s2c", s2c_len);

    cJSON* bins_norm = cJSON_GetObjectItem(pbins_obj, "normalized");
    if(bins_norm) cJSON_AddItemToObject(pkts, "bins", get_sparse_bins(bins_norm));
    cJSON_AddItemToObject(f_llm, "pkts_stats", pkts);

    // 6. TCP MECHANICS (Solo se TCP) 
    if (strcmp(proto_l4, "TCP") == 0) {
        cJSON* tcp = cJSON_CreateObject();
        cJSON* wins = cJSON_CreateObject();
        cJSON_AddNumberToObject(wins, "c2s", get_safe_num(root, "c_to_s_init_win"));    
        cJSON_AddNumberToObject(wins, "s2c", get_safe_num(root, "s_to_c_init_win"));
        cJSON_AddItemToObject(tcp, "wins", wins);

        cJSON* f_total = cJSON_CreateObject();
        cJSON_AddNumberToObject(f_total, "ack", get_safe_num(tcp_flags_obj, "ack_count"));
        cJSON_AddNumberToObject(f_total, "psh", get_safe_num(tcp_flags_obj, "psh_count"));
        cJSON_AddNumberToObject(f_total, "syn", get_safe_num(tcp_flags_obj, "syn_count"));
        cJSON_AddItemToObject(tcp, "f_total",  f_total);

        cJSON* f_s2d = cJSON_CreateObject();
        cJSON_AddNumberToObject(f_s2d, "ack", get_safe_num(tcp_flags_obj, "src2dst_ack_count"));  
        cJSON_AddNumberToObject(f_s2d, "psh", get_safe_num(tcp_flags_obj, "src2dst_psh_count"));
        cJSON_AddNumberToObject(f_s2d, "syn", get_safe_num(tcp_flags_obj, "src2dst_syn_count"));
        cJSON_AddItemToObject(tcp, "f_s2d", f_s2d);

        cJSON* f_d2s = cJSON_CreateObject();
        cJSON_AddNumberToObject(f_d2s, "ack", get_safe_num(tcp_flags_obj, "dst2src_ack_count"));
        cJSON_AddNumberToObject(f_d2s, "psh", get_safe_num(tcp_flags_obj, "dst2src_psh_count"));
        cJSON_AddNumberToObject(f_d2s, "syn", get_safe_num(tcp_flags_obj, "dst2src_syn_count"));
        cJSON_AddItemToObject(tcp, "f_d2s", f_d2s);
        
        cJSON_AddItemToObject(f_llm, "tcp", tcp);
    } else {
        cJSON_AddNullToObject(f_llm, "tcp");
    }

    cJSON_AddItemToArray(block->batch_json, f_llm);

    // --- PARTE 2: Y_TRUE ---
    cJSON* truth = cJSON_CreateObject();
    cJSON *t_proto = cJSON_GetObjectItem(ndpi_obj, "proto");
    cJSON *t_cat   = cJSON_GetObjectItem(ndpi_obj, "category");
    cJSON_AddStringToObject(truth, "proto", (t_proto && t_proto->valuestring) ? t_proto->valuestring : "unknown");
    cJSON_AddStringToObject(truth, "cat", (t_cat && t_cat->valuestring) ? t_cat->valuestring : "unknown");
    
    // Mappa l'ID del flusso alla sua verità
    cJSON_AddItemToObject(block->y_true_json, flow_id, truth);

    block->flow_count++;
}

int main(int argc, char *argv[]) {
    
    // Controllo se l'utente ha inserito i parametri necessari
    if (argc != 2) {
        fprintf(stderr, "[ERRORE]: Utilizzo: %s <file_pcap>\n", argv[0]);
        return 1;
    }

    // Assegnazione dei puntatori ai parametri (argv[0] è il nome del programma)
    char *pcap_file = argv[1];

    char *filename_ext = basename(pcap_file);
    char pcap_clean_name[128];
    strncpy(pcap_clean_name, filename_ext, sizeof(pcap_clean_name)-1);
    char *dot = strrchr(pcap_clean_name, '.');
    if (dot) *dot = '\0'; // Toglie .pcap

    char json_output[256];
    snprintf(json_output, sizeof(json_output), "%s_ndpiReader.json", pcap_clean_name);

    // Controllo se il file PCAP esiste davvero prima di chiamare nDPI
    if (access(pcap_file, F_OK) == -1) {
        fprintf(stderr, "[ERRORE]: Il file PCAP '%s' non esiste.\n", pcap_file);
        return 1;
    }

    // Rimuoviamo un eventuale file con lo stesso nome 
    remove(json_output); 

    // Costruzione del comando con snprintf
    // Usiamo le virgolette \"%s\" per gestire nomi di file con spazi
    char command[1024];
    int n = snprintf(command, sizeof(command), "./ndpiReader --cfg \"tls,max_num_blocks_to_analyze,8\" -K json -k \"%s\" -i \"%s\"", json_output, pcap_file);

    // Controllo se il comando è troppo lungo per il buffer
    if (n >= sizeof(command)) {
        fprintf(stderr, "[ERRORE]: i nomi dei file sono troppo lunghi.\n");
        return 1;
    }

    printf("[INFO]: Avvio analisi nDPI su: %s...\n", pcap_file);
    
    // Esecuzione del comando
    int status = system(command);

    // Controllo errori
    if (status == -1 ) {
        perror("Errore nell'avvio di system()");    // dopo il fallimento di una funzione di sistema
        return 1;
    } 

    // Il processo è terminato?
    // WEXITSTATUS estrae il codice di uscita reale del processo (0 = successo)
    if (WIFEXITED(status)) {
        int return_code = WEXITSTATUS(status);
        if (return_code != 0) {
            fprintf(stderr, "[ERRORE]: ndpiReader è terminato con errore (codice %d)\n", return_code);
            return 1;
        } 
        printf("[INFO]: Analisi completata con successo. Creato file: %s\n", json_output);
    } else {
        fprintf(stderr, "[ERRORE]: Il processo è stato interrotto bruscamente.\n");
        return 1;
    }
    
    FILE *fp = fopen(json_output, "r");
    if (!fp) {
        perror("[ERRORE]: Impossibile aprire il file JSON di nDPI");
        return 1;
    }

    char *line = NULL;
    size_t len = 0;

    FlowBlock current_block = {0, 0, "", NULL, NULL};
    strncpy(current_block.pcap_name, pcap_clean_name, sizeof(current_block.pcap_name)-1);

    int block_counter = 0;
    
    printf("[INFO]: Inizio raggruppamento flussi (finestra %f)...\n", BLOCK_WINDOW_SIZE);

    while (getline(&line, &len, fp) != -1) {
        cJSON *root = cJSON_Parse(line);
        if (!root) continue;

        // Se non c'è l'IP sorgente, non è un flusso valido
        if (!cJSON_HasObjectItem(root, "src_ip")) {
            cJSON_Delete(root);
            continue;
        }

        cJSON *fs_item = cJSON_GetObjectItem(root, "first_seen");
        if (!fs_item) {
            cJSON_Delete(root);
            continue;
        }
        double fs = fs_item->valuedouble;

        // Logica della finestra temporale
        if (current_block.flow_count == 0 || (fs - current_block.start_timestamp > BLOCK_WINDOW_SIZE)) {
            if (current_block.flow_count > 0) {
                save_block(&current_block, block_counter++);
            }
            reset_block(&current_block, fs);
        }

        // Processa il flusso e aggiungilo al blocco corrente
        process_flow(root, &current_block); 

        cJSON_Delete(root);
    }

    // Salva l'ultimo blocco se presente
    if (current_block.flow_count > 0) {
        save_block(&current_block, block_counter++);
    } 

    // Se l'ultimo blocco è rimasto vuoto, liberiamo la memoria
    if (current_block.batch_json) cJSON_Delete(current_block.batch_json);
    if (current_block.y_true_json) cJSON_Delete(current_block.y_true_json);
    

    free(line);
    fclose(fp);
    
    printf("[INFO]: Elaborazione terminata con successo. Creati %d blocchi.\n", block_counter);

    // Continua...

    return 0;
}
