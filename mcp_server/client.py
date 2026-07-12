import os
import json
import asyncio
from datetime import datetime
import sys
import ipaddress
from dotenv import load_dotenv

from groq import AsyncGroq
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

load_dotenv()

MAX_DRILLDOWN_TURNS = 8

if not os.environ.get("GROQ_API_KEY"):
    print("[ERRORE]: GROQ_API_KEY non trovata nel file .env!")
    sys.exit(1)

client = AsyncGroq(
    api_key=os.environ.get("GROQ_API_KEY")
)

server_params = StdioServerParameters(
    command="python",
    args=["server.py"]
)

async def esegui_analisi_mcp(client, server_params, ip_target, start_time, end_time, modello_scelto, scenario_prompt, cat_tag, max_tool_chars, sleep_time):
    print(f"\n" + "="*60)
    print(f"INIZIALIZZAZIONE SESSIONE MCP")
    print(f"Target IP : {ip_target}")
    print(f"Finestra  : {start_time} -> {end_time}")
    print(f"Modello   : {modello_scelto}")
    print("="*60)
    
    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            
            tools_disponibili = await session.list_tools()
            openai_tools = []
            
            for tool in tools_disponibili.tools:
                if hasattr(tool, "inputSchema"):
                    schema = tool.inputSchema
                else:
                    dump = tool.model_dump()
                    schema = dump.get("inputSchema") or dump.get("input_schema")

                openai_tools.append({
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": schema
                    }
                })

            prompt_generico = (
                f"Esegui l'ispezione mirata sui flussi di rete nDPI dell'host {ip_target} "
                f"nell'intervallo temporale '{start_time}' - '{end_time}'.\n"
                f"Focus Investigativo: {scenario_prompt}"
            )
            
            focus_categorie = {
                "cat_a": """### REGOLE SPECIFICHE: CATEGORIA A (Anomalie L7 / Disallineamenti)
                - Le min threats (Bot/Infiltration) sono numericamente infinitesimali rispetto al traffico benigno. NON limitarti a campionare i primi flussi generali.
                - Interroga i tool cercando esplicitamente disallineamenti macroscopici, protocolli classificati como 'Unknown', applicazioni non standard su porte note (es. non-HTTP su porta 80) o protocolli rari nella rete.
                - Se interroghi 'detect_beaconing' in questa categoria, usalo solo per verificare se i flussi strutturalmente disallineati (es. non-HTTP su porta 80) presentano anche persistenza ciclica.
                - Se trovi del beaconing su porte corrette (es. TLS su 443 o DNS su 53) e senza anomalie di payload, NON considerarlo una violazione della Categoria A.""",

                "cat_b": """### REGOLE SPECIFICHE: CATEGORIA B (Monitoraggio Volumetrico / DoS)
                - Inizia calcolando la baseline statistica e i volumi aggregati per identificare deviazioni standard anomale o attacchi DoS/Slow-Rate attivi.""",

                "cat_c": """### REGOLE SPECIFICHE: CATEGORIA C (Profiling Endpoint / TLS)
                - I bot malevoli si nascondono nel rumore di fondo (~0.01% del traffico). NON analizzare solo i flussi a volume maggiore (Top Talker).
                - Ordina o filtra actively i flussi crittografati a caccia di anomalie strutturali: cerca valori anomali di entropia del payload, versioni TLS obsolete (TLS 1.0/1.1) o Cipher Suite non standard.""",

                "cat_d": """### REGOLE SPECIFICHE: CATEGORIA D (Analisi Comportamentale / Beaconing)
                - Inizia SEMPRE invocando 'get_traffic_summary' o 'analyze_dpi_details' al Turno 1 per mappare gli IP esterni comunicanti. Usa 'detect_beaconing' nei turni successivi.
                - Ricorda che i malware C2 avanzati effettuano pochissime connessioni dilazionate nel tempo (basso footprint): NON ignorare gli IP esterni solo perché compaiono poche volte o non appiono nei primi posti dei tool automatici."""
            }

            prompt_categoria_specifico = focus_categorie.get(
                cat_tag.lower(), 
                "### REGOLE SPECIFICHE:\n- Analizza attentamente tutte le metriche relative sullo scenario richiesto."
            )

            system_prompt = f"""
            Sei il motore di correlazione forense di un Next-Generation IDS basato on nDPI.
            Lavori in modalità Blind Test sulla tabella 'ndpi_flows' (senza etichette).
            Analizza i dati estratti dai tool e genera un report dettagliato in formato Markdown.

            LINEE GUIDA RIGIDE SUI TOOL:
            - Sfrutta i tool messi a disposizione per raccogliere le metriche richieste dallo scenario scelto.

            - LINEA GUIDA SULLA PRIORITÀ DEI TOOL & THREAT HUNTING (Triage Adattivo anti-False Negative):
            {prompt_categoria_specifico}

            - REGOLA DI TRASPARENZA INVESTIGATIVA NATURALE (TASSATIVA PER TUTTI I TURNI):
            1. Prima di emettere qualsiasi chiamata a un tool (`tool_calls`), devi OBBLIGATORIAMENTE scrivere la tuaDoc analisi forense e i tuoi sospetti direttamente nel corpo del testo del messaggio corrente (proprietà 'content').
            2. In questo testo devi analizzare criticamente i dati restituiti dal database nel turno precedente, evidenziare eventuali anomalie (anche minime o flussi isolati sospetti) o anomalie assenti, e spiegare la logica investigativa dietro la nuova invocazione (perché quel tool è necessario proprio ora?).
            3. NOTA BENE: Non esiste più un parametro chiamato 'ragionamento_investigativo' nei tool. Pertanto, TUTTI i tuoi pensieri e la tua Chain of Thought devono essere scritti come testo normale PRIMA di lanciare il tool. È SEVERAMENTE VIETATO inviare una chiamata a un tool lasciando il testo del messaggio vuoto.

            - REGOLA ANTI-LOOP (RIGIDA):
            1. Non invocare MAI lo stesso tool con gli stessi identici parametri per due turni consecutivi.
            2. Se un tool (como 'get_traffic_summary') non evidenzia anomalie macroscopiche o restituisce dati vuoti/ripetitivi, passa IMMEDIATAMENTE a un tool alternativo di ispezione (es. 'analyze_dpi_details', 'resolve_host_info', 'detect_beaconing') per cercare minacce nascoste o flussi isolati.
            3. Se hai esaurito i tool utili e non riscontri anomalie, non insistere: interrompi il ciclo e genera direttamente il report finale dichiarando il traffico come benigno.

            - REGOLA DI CORRELAZIONE CROSS-TURN (ANTI-CECITÀ):
            Se un IP esterno, un dominio o un flusso specifico attira la tua attenzione nel Turno 1 o 2 (ad esempio un Proxy HTTP esterno o una porta non standard), hai l'obbligo di seguirne le tracce nei turni successivi. Estrai le sue feature temporali profonde (IAT) e i dettagli DPI anche se i tool di rilevamento automatico del beaconing non lo menzionano esplicitamente nella loro Top 10. Non resettare la memoria logica intra-turno.

            - REGOLA DI DRILL-DOWN OBBLIGATORIO:
            Se individui anche un solo record anomalo, sospetto o discordante (es. connessioni persistenti verso un IP esterno con payload nullo o flag TCP anomali), esegui SEMPRE il drill-down sul singolo flusso invocando 'analizza_connessione_by_community_id' con il relativo community_id.

            - REGOLA DI CHIUSURA: Prima di emettere un verdetto di 'TRAFFICO BENIGNO', assicurati di aver verificato i canali di potenziale prima persistenza (es. beaconing o flussi anomali isolati).

            REGOLE DI VALUTAZIONE EURISTICA E TRATTAMENTO DEI OUTPUT DEI TOOL (TASSATIVE):
            1. DIFESA DAL BIAS DI AUTOMAZIONE (CRITICA):
            I tool automatici (come 'detect_beaconing') generano output di testo contenenti valutazioni preconfezionate (es. "TRAFFICO BURST STANDARD"). NON prendere queste stringhe come oro colato. Il tool potrebbe classificare un flusso como standard basandosi su una media parziale o ignorare un IP pericoloso perché ha un volume di connessioni troppo basso per i suoi algoritmi di soglia. Tu devi validare i DATI NUMERICI GREZZI (intervallo IAT, entropia, flag TCP) e smentire il giudizio del tool se i dati numerici mostrano anomalie forensi.

            2. MATRICE DI SQUALIFICA QUANTITATIVA DEL PROTOCOLLO (REGOLA ANTI-FALSE NEGATIVE):
            Un'etichetta applicativa L7 (es. HTTP_Proxy, HTTP, TLS, DNS) assegnata da nDPI è basata spesso solo sulla porta o su euristiche parziali. Questa classificazione è SQUALIFICATA e considerata ATTACCO/MALWARE se si verificano le seguenti condizioni numeriche combinate:
            - Il flusso è diretto verso un IP esterno non aziendale.
            - L'app_hierarchy indica un protocollo applicativo (es. HTTP_Proxy o HTTP) ma l'entropia del payload è rigorosamente 0.0 o inferiore a 0.5 (segno di assenza totale di header di testo o di payload nullo).
            - I total_bytes sono incredibilmente bassi (meno di 300 byte) a fronte di una duration_ms elevata (maggiore di 5000ms), indicando un canale tenuto aperto artificialmente.
            - Il tcp_flags è uguale a 2 (che indica esclusivamente pacchetti SYN inviati), confermando un handshake TCP mai completato verso un servizio irraggiungibile o un C2 silente/offline.
            In presenza di flussi con queste metriche, l'etichetta benigna è un falso positivo del parser L7. Verdetto tassativo: MINACCIA RILEVATA.

            3. ANOMALIE DI FLUSSO SILENTI (C2 BEACONING SOTTO SOGLIA):
            Un'ottima regolarità nei tempi di inter-arrivo (IAT flow avg e stddev costanti tra flussi diversi), entropia del payload pari a 0.0 (o vicina a 0) e flag TCP fissi a 2 (solo pacchetti SYN inviati senza risposta o handshake incompleto) NON è traffico web fisiologico. È il sintomo di un beaconing persistente o di un malware che tenta ciclicamente di contattare un C2 offline. Questo scenario richiede tassativamente il verdetto di minaccia.

            4. SCENARIO ATTACCO (Slow-Rate DoS o C2/Botnet): Presenza di pattern periodici stabili (Deviazione Standard molto bassa, es. < 2s), anomalie applicative (es. porta 80, payload_entropy = 1, duration_ms elevata e packet_rate prossimo allo 0) o flussi anomali isolati verso l'esterno non giustificabili. 
            Verdetto: [VERDETTO: MINACCIA RILEVATA].

            5. SCENARIO FISIOLOGICO (Traffico Sicuro): Assenza dimostrata di beaconing periodico non autorizzato verso l'esterno, flussi coerenti con i servizi core di dominio interno (DNS su porta 53 locale, LDAP, SMB, Kerberos) e payload_entropy coerente su porte crittografate standard.
            Verdetto: [VERDETTO: TRAFFICO BENIGNO].

            6. DISTINZIONE DEI FALSI POSITIVI (TASSATIVA):
            - Prima di dichiarare una MINACCIA RILEVATA basandoti sul beaconing, VALUTA L'APPLICAZIONE (app_hierarchy) e la DESTINAZIONE:
                * Se il traffico regolare avviene verso servizi core locali (DNS su porta 53 interna, LDAP, Kerberos, SMB) o CDN note/Servizi cloud stabili e verified (es. Microsoft365, Akamai), si trata di un COMPORTAMENTO FISIOLOGICO dell'infrastruttura.
                * Se il traffico ha un intervallo medio prossimo a 0.0s (avg_sec <= 1s) ed è diretto verso siti web leciti, identifica un "burst" di pacchetti simultanei (es. caricamento pagina web o transazione API) e NON un heartbeat C2.
            - Emetti [VERDETTO: MINACCIA RILEVATA] se il beaconing/anomalia (anche a basso volume o a handshake incompleto) è diretto verso IP esterni non giustificabili, con protocolli sconosciuti, proxy non autorizzati, o se viola esplicitamente la conformità della categoria analizzata.

            REQUISITI DI OUTPUT:
            - Concludi inserendo il Verdetto finale nell'ultima riga del testo in lettere maiuscole.
            """

            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt_generico}
            ]
            
            log_investigativo = f"=== AUDIT LOG ===\n"
            log_investigativo += f"Target IP        : {ip_target}\n"
            log_investigativo += f"Categoria Analisi: {cat_tag.upper()} ({scenario_prompt})\n"
            log_investigativo += f"Finestra Traffico: {start_time} -> {end_time}\n"
            log_investigativo += f"Modello Engine   : {modello_scelto}\n"
            log_investigativo += f"Data Esecuzione  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            log_investigativo += f"=========================================\n\n"

            set_chiamate_precedenti = set()
            
            for turno in range(MAX_DRILLDOWN_TURNS):

                if turno > 0:
                    print(f"[INFO]: Attesa di sicurezza per reset rate-limiting ({sleep_time}s)...")
                    await asyncio.sleep(sleep_time)

                try:
                    kwargs = {
                        "model": modello_scelto, 
                        "messages": messages, 
                        "temperature": 0.3,
                        "max_tokens": 1024
                    }

                    if openai_tools:
                        kwargs["tools"] = openai_tools
                        kwargs["tool_choice"] = "auto"

                    response = await client.chat.completions.create(**kwargs)

                except Exception as e:
                    print(f"[ERRORE API]: {str(e)}")
                    return

                scelta_risposta = response.choices[0].message
                ragionamento_turno = scelta_risposta.content if scelta_risposta.content else ""
                
                if ragionamento_turno.strip():
                    print(f"\n[LOG LLM - Turno {turno+1}]:\n-> {ragionamento_turno}\n")
                
                if scelta_risposta.tool_calls:
                    messaggio_assistente_dict = scelta_risposta.model_dump()

                    if not ragionamento_turno.strip():
                        messaggio_assistente_dict["content"] = None

                    campi_da_rimuovere = ["function_call", "annotations", "audio"]
                    for campo in campi_da_rimuovere:
                        if campo in messaggio_assistente_dict:
                            del messaggio_assistente_dict[campo]
                    
                    messaggio_assistente_dict = {k: v for k, v in messaggio_assistente_dict.items() if v is not None}
                    
                    log_investigativo += f"[TURNO {turno+1}]\n"
                    log_investigativo += f"RAGIONAMENTO LLM: {ragionamento_turno if ragionamento_turno.strip() else 'Nessun testo generato.'}\n"
                    
                    set_chiamate_turno_corrente = set()
                    abort_loop = False

                    for i, tool_call_oggetto in enumerate(scelta_risposta.tool_calls):
                        argomenti_completi = json.loads(tool_call_oggetto.function.arguments)

                        if "start_time" in argomenti_completi:
                            argomenti_completi["start_time"] = start_time
                        if "end_time" in argomenti_completi:
                            argomenti_completi["end_time"] = end_time
                          
                        messaggio_assistente_dict["tool_calls"][i]["function"]["arguments"] = json.dumps(argomenti_completi)
                        
                        # Definiamo un impronta univoca per il controllo anti-loop
                        impronta_chiamata = f"{tool_call_oggetto.function.name}_{json.dumps(argomenti_completi, sort_keys=True)}"
                        set_chiamate_turno_corrente.add(impronta_chiamata)

                    # Verifichiamo sovrapposizione esatta con il turno precedente
                    if set_chiamate_turno_corrente and set_chiamate_turno_corrente == set_chiamate_precedenti:
                        print(f"\n[ERRORE]: Rilevato loop identico di invocazioni rispetto al turno precedente. Interrompo.")
                        abort_loop = True

                    set_chiamate_precedenti = set_chiamate_turno_corrente
                    messages.append(messaggio_assistente_dict)
                    
                    for idx, tool_call_oggetto in enumerate(scelta_risposta.tool_calls):
                        nome_funzione = tool_call_oggetto.function.name
                        argomenti_completi = json.loads(messaggio_assistente_dict["tool_calls"][idx]["function"]["arguments"])

                        if abort_loop:
                            messages.append({
                                "role": "tool",
                                "tool_call_id": tool_call_oggetto.id,
                                "name": nome_funzione,
                                "content": "[ERRORE]: Invocazione consecutiva vietata con gli stessi parametri. Genera immediatamente il report finale di sintesi."
                            })
                            continue

                        print(f"[Turno {turno+1}] LLM invoca '{nome_funzione}' con parametri {argomenti_completi}")
                        log_investigativo += f"AZIONE: Invocazione del tool '{nome_funzione}' con argomenti {json.dumps(argomenti_completi)}\n"

                        try:
                            risultato_db = await session.call_tool(nome_funzione, argomenti_completi)
                            testo_risultato = risultato_db.content[0].text
                            
                            if len(testo_risultato) > max_tool_chars:
                                testo_risultato = testo_risultato[:max_tool_chars] + f"\n... [TRUNCATED AT {max_tool_chars} CHARS FOR CONTEXT LIMITS] ..."

                            messages.append({
                                "role": "tool",
                                "tool_call_id": tool_call_oggetto.id,
                                "name": nome_funzione,
                                "content": testo_risultato
                            })
                            
                            log_investigativo += f"RISPOSTA DATABASE (Tool {nome_funzione}):\n{testo_risultato}\n"
                            log_investigativo += f"{'-'*50}\n\n"

                        except Exception as e:
                            print(f"[ERRORE TOOL]: {str(e)}")
                            messages.append({
                                "role": "tool",
                                "tool_call_id": tool_call_oggetto.id,
                                "name": nome_funzione,
                                "content": f"[ERRORE SUL SERVER MCP]: {str(e)}"
                            })
                    
                else:      
                    messages.append(scelta_risposta.model_dump())
                    report_content = scelta_risposta.content if scelta_risposta.content else ragionamento_turno
                    print(f"\nREPORT GENERATO")

                    start_clean = start_time.replace("-", "").replace(" ", "_").replace(":", "").split(".")[0]
                    end_clean = end_time.replace("-", "").replace(" ", "_").replace(":", "").split(".")[0]
                        
                    os.makedirs("outputs", exist_ok=True)
                        
                    file_path_md = f"outputs/report_{ip_target}_{start_clean}_{end_clean}_{cat_tag}.md"
                    file_path_txt = f"outputs/log_{ip_target}_{start_clean}_{end_clean}_{cat_tag}.txt"

                    with open(file_path_md, "w", encoding="utf-8") as f:
                        f.write(report_content)
                    print(f"[INFO]: Report finale salvato in: {file_path_md}")
                        
                    log_investigativo += f"ANALISI FINALE & VERDETTO:\n{report_content}\n"
                    log_investigativo += f"=== FINE DEL LOG ===\n"

                    with open(file_path_txt, "w", encoding="utf-8") as f:
                        f.write(log_investigativo)
                    print(f"[INFO]: Chain of Thought salvata in: {file_path_txt}")
                        
                    return

def mostra_menu_cli():
    print("\n" + "="*60)
    print("Seleziona la categoria analitica da sottoporre all'LLM:")
    print("1) [CATEGORIA A] - Analisi Strutturale e Sintesi Globale Applicativa")
    print("2) [CATEGORIA B] - Monitoraggio Volumetrico (Rilevamento Anomalia Rate / DoS)")
    print("3) [CATEGORIA C] - Investigazione Endpoint (Top Talker, Profiling L7 & TLS)")
    print("4) [CATEGORIA D] - Analisi Comportamentale (Brute Force / Temporal Beaconing)")
    print("5) Torna alla selezione del Modello (LLM)")
    print("6) Esci")
    print("="*60 + "\n")

def richiedi_ip():
    while True:
        ip_input = input("Inserisci l'IP target da analizzare: ").strip()
        try:
            return str(ipaddress.ip_address(ip_input))
        except ValueError:
            print("[ERRORE]: Formato IP non valido (es. corretto: 192.168.10.14). Riprova.")

def richiedi_data(prompt_testo):
    formato = "%Y-%m-%d %H:%M:%S.%f"
    while True:
        data_input = input(prompt_testo).strip()
        try:
            datetime.strptime(data_input, formato)
            return data_input
        except ValueError:
            print("[ERRORE]: Formato non valido. Devi includere anche i microsecondi.")
            print("Esempio corretto: 2017-07-03 09:06:00.000000")
            print("-" * 40)

async def main():
    config_modelli = {
        "1": {
            "name": "llama-3.1-8b-instant", 
            "max_chars": 4000,      
            "sleep_time": 4
        },
        "2": {
            "name": "llama-3.3-70b-versatile", 
            "max_chars": 5000,
            "sleep_time": 1
        }
    }
    
    while True:  
        print("\n" + "="*60)
        print("CONFIGURAZIONE INIZIALE MODELLO")
        print("1) Llama 3.1 (8B Instant)    [Context Limit: 4000 char/tool]")
        print("2) Llama 3.3 (70B Versatile) [Context Limit: 5000 char/tool]")
        print("6) Esci")
        print("="*60)
        
        scelta_modello = input("Scegli il modello engine (default: 2): ").strip()
        
        if scelta_modello == "6":
            print("\nChiusura interfaccia di analisi.\n")
            break
            
        if not scelta_modello:
            scelta_modello = "2"
            
        if scelta_modello not in ["1", "2"]:
            print("[ERRORE]: Opzione modello non valida. Riprova.")
            continue

        config_scelta = config_modelli[scelta_modello]
        modello_scelto = config_scelta["name"]
        max_tool_chars = config_scelta["max_chars"]
        sleep_time = config_scelta["sleep_time"]
        print("[INFO]: Modello scelto: ", modello_scelto)

        while True: 
            mostra_menu_cli()
            scelta = input("Scegli un'opzione (1-6): ").strip()
            
            if scelta == "6":
                print("\nChiusura interfaccia di analisi.\n")
                return  
                
            if scelta == "5":
                print("\nRitorno alla selezione dell'LLM...\n")
                break  
                
            if scelta not in ["1", "2", "3", "4"]:
                print("[ERRORE]: Opzione non valida. Riprova.")
                continue

            if scelta == "1":
                cat_tag = "cat_a"
                scenario_prompt = "Focalizzati sulla sintesi macroscopica strutturale. Identifica disallineamenti significativi tra porte standard e applicazioni L7 effettivamente rilevate (es. protocolli non HTTP su porta 80)."
            elif scelta == "2":
                cat_tag = "cat_b"
                scenario_prompt = "Esegui un monitoraggio volumetrico approfondito. Estrai la baseline statistica di rete tramite i tool e calcola le deviazioni standard per verificare la presenza di attacchi DoS o Slow-Rate attivi."
            elif scelta == "3":
                cat_tag = "cat_c"
                scenario_prompt = "Isola il profilo di questo endpoint. Verifica se figura come Top Talker for volumi o pacchetti, analizza l'entropia del payload dei flussi crittografati ed estrai i dettagli su cipher suite e versioni TLS."
            elif scelta == "4":
                cat_tag = "cat_d"
                scenario_prompt = "Isola pattern ciclici o sequenziali. Cerca tentativi ad alta frequenza verso porte specifiche (Brute Force) o analizza l'Inter-Arrival Time (IAT) dei flussi per smascherare heartbeat o beaconing di botnet."

            print(f"\n[CONFIGURAZIONE PARAMETRI PER SCENARIO {scelta}]")
            
            ip_target = richiedi_ip()

            while True:
                start_time = richiedi_data("Inserisci START TIME (es. YYYY-MM-DD HH:MM:SS.000000): ")
                end_time = richiedi_data("Inserisci END TIME   (es. YYYY-MM-DD HH:MM:SS.000000): ")
                
                if start_time >= end_time:
                    print("[ERRORE]: Lo START TIME non può essere successivo o uguale all'END TIME! Reimposta le date.")
                    print("-" * 40)
                    continue
                break

            await esegui_analisi_mcp(client, server_params, ip_target, start_time, end_time, modello_scelto, scenario_prompt, cat_tag, max_tool_chars, sleep_time)

if __name__ == "__main__":
    asyncio.run(main())
