import copy
import re
import hashlib
import json
from typing import Any, Dict, List, Tuple, Optional
import config

# ==============================================================================
# Gestione e Pulizia Memoria Context
# ==============================================================================

# 1 calcola_hash_chiamata, 1 esegui_analisi_mcp
def normalizza_parametri_tool(valore: Any) -> Any:
    """
    Ricorsivamente rimuove chiavi con valori None/stringhe vuote e assicura la pulizia di dizionari e liste annidate.
    """
    if isinstance(valore, dict):
        return {
            k: normalizza_parametri_tool(v)
            for k, v in sorted(valore.items())
            if v is not None and v != ""
        }
    elif isinstance(valore, list):
        return [
            normalizza_parametri_tool(item) 
            for item in valore 
            if item is not None and item != ""
        ]
    return valore

# 2 validate_and_process_turn, 1 esegui_analisi_mcp, 1 server
def calcola_hash_chiamata(nome_funzione: str, argomenti: Dict[str, Any]) -> str:
    """
    Genera un hash SHA-256 unico e deterministico per una chiamata a un tool.
    """
    if not isinstance(argomenti, dict):
        argomenti = {}

    argomenti_puliti = normalizza_parametri_tool(argomenti)

    # Serializzazione deterministica
    json_canonico = json.dumps(
        {"tool": nome_funzione, "args": argomenti_puliti},
        sort_keys=True,
        ensure_ascii=True,
        default=str
    )
    
    return hashlib.sha256(json_canonico.encode('utf-8')).hexdigest()

# 1 esegui_analisi_mcp
def sanitizza_storico_per_report(
    messaggi: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
        Rimuove dallo storico:
        1. I messaggi di feedback temporanei ([SISTEMA DEGLI ERRORI], NOTA DI PROGRESO).
        2. I messaggi assistant con 'tool_calls' orfani (senza i rispettivi messaggi 'tool' di risposta).
        Garantisce la conformità con le specifiche di OpenAI/Groq API.
    """
    messaggi_puliti = []
    i = 0
    n = len(messaggi)

    while i < n:
        msg = messaggi[i]
        role = msg.get("role")
        content = msg.get("content") or ""

        # Scarta i messaggi di controllo/feedback temporanei inviati dal sistema
        if role == "user" and (
            content.startswith("[SISTEMA DEGLI ERRORI]")
            or content.startswith("SISTEMA - NOTA DI PROGRESO:")
        ):
            i += 1
            continue

        # Controllo sui messaggi assistant con tool_calls
        if role == "assistant" and msg.get("tool_calls"):
            tool_calls = msg.get("tool_calls", [])
            num_calls = len(tool_calls)

            # Verifica quante risposte 'tool' consecutive seguono questo messaggio
            j = i + 1
            risposte_trovate = 0
            while (
                j < n
                and messaggi[j].get("role") == "tool"
                and risposte_trovate < num_calls
            ):
                risposte_trovate += 1
                j += 1

            # Se mancano risposte dei tool, salta sia il messaggio assistant sia le risposte parziali
            if risposte_trovate < num_calls:
                print(
                    f"Rimosso messaggio assistant orfano con {num_calls} tool_calls."
                )
                i = j
                continue

            for k in range(i, j):
                messaggi_puliti.append(messaggi[k])

            i = j
            continue

        # Scarta eventuali messaggi 'tool' isolati (senza il relativo assistant)
        if role == "tool":
            print(
                "Rimosso messaggio 'tool' isolato senza assistant precedente."
            )
            i += 1
            continue

        messaggi_puliti.append(msg)
        i += 1

    return messaggi_puliti

# Pruning di routine
# 2 esegui_analisi_mcp
def applica_pruning_contesto(
    messaggi: List[Dict[str, Any]],
    max_messaggi_recenti: int = 6,
    max_chars_tool: int = 3000,
) -> List[Dict[str, Any]]:
    """
    Mantiene l'intera struttura dello storico, ma applica il troncamento al contenuto dei messaggi 'tool' se superano max_chars_tool.
    I tool meno recenti (fuori dalla finestra max_messaggi_recenti) vengono troncati preservando le prime righe fino a un massimo di max_chars_tool.
    """
    messaggi_prunati = []
    totale_messaggi = len(messaggi)

    for idx, msg in enumerate(messaggi):
        msg_copia = copy.deepcopy(msg)

        if msg_copia.get("role") in ["tool", "function"] or "tool_call_id" in msg_copia:
            contenuto = msg_copia.get("content", "")

            if isinstance(contenuto, str) and len(contenuto) > max_chars_tool:
                # Determina se il messaggio è "vecchio"
                e_vecchio = (totale_messaggi - idx) >= max_messaggi_recenti

                if e_vecchio:
                    # Mantiene le prime 15 righe
                    limite_vecchi = max_chars_tool // 3
                    prime_righe = "\n".join(contenuto.splitlines()[:15])[:limite_vecchi]
                    msg_copia["content"] = (
                        f"{prime_righe}\n\n"
                        f"[... RISULTATO VECCHIO TRONCATO ({len(contenuto)} char orig.) ...]"
                    )
                else:
                    # Troncamento diretto al limite max_chars_tool per i tool recenti
                    msg_copia["content"] = (
                        contenuto[:max_chars_tool]
                        + f"\n\n[... TRONCATO A {max_chars_tool} CHAR (su {len(contenuto)} orig.) ...]"
                    )

        messaggi_prunati.append(msg_copia)

    return messaggi_prunati

# Pruning di emergenza Rate Limit/413
# 2 esegui_analisi_mcp
def pruning_messages_for_context(messages: list, max_tool_chars: int = 300) -> list:
    """
        Riduce il peso dei messaggi dei tool per rientrare nei 6000 token di Groq.
    """
    cleaned = []
    for msg in messages:
        msg_copy = copy.deepcopy(msg)
        # Se è un output di un tool ed è troppo lungo, lo tagliamo
        if msg_copy.get("role") in ["tool", "function"] or "tool_call_id" in msg_copy:
            content = msg_copy.get("content", "")
            if isinstance(content, str) and len(content) > max_tool_chars:
                msg_copy["content"] = content[:max_tool_chars] + "\n... [OUTPUT TRUNCATED TO FIT TPM LIMIT]"
        cleaned.append(msg_copy)
    return cleaned

# ==============================================================================
# Guardrail e Inizializzazione Prompt
# ==============================================================================

# 1 esegui_analisi_mcp
def inizializza_storico(ip_target: str, categoria_tag: str, prompt_iniziale: str) -> list:
    """
    Inizializza lo storico messaggi forzando l'LLM alla valutazione deterministica pura.
    """
    system_prompt = (
        f"Sei un motore di classificazione deterministico per la sicurezza di rete.\n"
        f"Target in esame: {ip_target}.\n\n"
        f"DIRETTIVE TASSATIVE:\n"
        f"1. NON ESISTONO alert pre-approvati o notifiche automatiche. Devi giudicare ESCLUSIVAMENTE dai dati estratti.\n"
        f"2. Se un parametro non supera la soglia numerica esplicita indicata nelle istruzioni utente, la condizione è FALSE.\n"
        f"3. È SEVERAMENTE VIETATO inventare 'allarmi automatici' per giustificare un verdetto se le medie matematiche non lo supportano."
    )
    
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt_iniziale}
    ]

# 1 esegui_analisi_mcp
def applica_guardrail_deterministico(categoria_tag: str, messages: list) -> Optional[str]:
    """
    Ispeziona l'output restituito dai tool di analisi e applica guardrail deterministici basati su regole rigide per evitare falsi negativi/positivi.
    """
    cat_lower = str(categoria_tag).lower()
    
    # Raccogli tutto il testo generato dall'output dei TOOL (role: tool / function)
    tool_outputs = " ".join([
        str(m.get("content", "")).lower() 
        for m in messages 
        if m.get("role") in ["tool", "function"] or m.get("name")
    ])

    # -------------------------------------------------------------------------
    # GUARDRAIL TRASVERSALE / CAT_C (Scan & BruteForce)
    # -------------------------------------------------------------------------

    # Controllo termini espliciti nel testo dei log/tool
    terms_scan = [
        "portscan", "port_scan", "bruteforce", "brute_force", 
        "hydra", "patator", "ssh-patator", "ftp-patator", "masscan", "nmap"
    ]
    has_scan_terms = any(term in tool_outputs for term in terms_scan)

    # Conteggio flussi focalizzati su porte BruteForce (21, 22, 3389, 1433)
    # Cerca menzioni di porte o servizi critici nei log estratti
    ssh_ftp_matches = re.findall(r'(?:port\s*(?:21|22|3389|1433)|\bssh\b|\bftp\b|\brdp\b)', tool_outputs)
    ssh_ftp_count = len(ssh_ftp_matches)

    # Se siamo in CAT_C oppure se ci sono > 50 flussi/richieste su porte di gestione -> FORZA SCAN_BRUTEFORCE
    if "cat_c" in cat_lower or ssh_ftp_count >= 10 or has_scan_terms:
        return "SCAN_BRUTEFORCE"

    # -------------------------------------------------------------------------
    # GUARDRAIL CAT_B (DoS Volumetric & Slow DoS)
    # -------------------------------------------------------------------------
    
    if "cat_b" in cat_lower:
        pps_matches = re.findall(r'(\d+(?:\.\d+)?)\s*pps', tool_outputs)
        for match in pps_matches:
            if float(match) >= 5000.0:
                return "DOS_VOLUMETRIC"

        if any(term in tool_outputs for term in ["slowhttptest", "slowloris"]):
            return "DOS_VOLUMETRIC"

    # -------------------------------------------------------------------------
    # GUARDRAIL CAT_D (Botnet / Beaconing C2)
    # -------------------------------------------------------------------------
    
    if "cat_d" in cat_lower:
        terms_beacon = ["bot", "c2", "beaconing", "flag_dns_tunneling_suspect", "stable_periodicity"]
        if any(term in tool_outputs for term in terms_beacon):
            return "BEACONING_C2"

    return None

# ==============================================================================
# Ciclo di Controllo Validazione
# ==============================================================================

# 3 esegui_analisi_mcp
def validate_and_process_turn(
    messaggio_dict: Dict[str, Any],
    min_char_limit: int,
    ip_target_sessione: str,
    storico_messaggi: List[Dict[str, Any]],
    fase_corrente: str = "ESPLORAZIONE",
    consecutive_errors: int = 0,
    max_retries: int = 3,
    verdetti_ammessi: List[str] = None,
    chiamate_effettuate: set = None
) -> Tuple[bool, str, bool]:
    """
    Valida le risposte dell'LLM in base alla fase corrente (ESPLORAZIONE o REPORT_FINALE).
    
    Ritorna:
        Tuple[bool, str, bool]: 
        - is_valid (bool): True se la risposta rispetta tutte le regole.
        - messaggio (str): Messaggio di OK oppure dettaglio dell'errore per l'LLM.
        - force_switch_to_report (bool): True se sono stati superati i tentativi massimi.
    """
    if verdetti_ammessi is None:
        verdetti_ammessi = config.VERDETTI_AMMESSI

    # Se l'LLM ha fallito troppe volte di fila, forziamo il Report Finale
    if consecutive_errors >= max_retries:
        return (
            False,
            f"[ERRORE]: Superato il limite massimo di tentativi errati ({max_retries}). "
            "Procedi immediatamente a stilare il REPORT FINALE basandoti sulle sole informazioni raccolte finora.",
            True
        )

    content = (messaggio_dict.get("content") or "").strip()
    tool_calls = messaggio_dict.get("tool_calls") or []

    """
    print(f"\n--- [DEBUG VALIDAZIONE TURN] ---", flush=True)
    print(f"Fase Corrente: '{fase_corrente}' | Errore Consecutivo: {consecutive_errors}/{max_retries}", flush=True)
    print(f"Lunghezza Content: {len(content)} | Tool Calls Presenti: {len(tool_calls)}", flush=True)
    print(f"--------------------------------", flush=True)
    """

    # Impedisce all'LLM di simulare tool in testo
    if fase_corrente == "ESPLORAZIONE":
        stringhe_tool_vietate = ["<function=", '"arguments":', '"name":']
        if any(s in content for s in stringhe_tool_vietate) and not tool_calls:
            return (
                False,
                "[ERRORE DI SINTASSI]: Hai scritto il codice del tool nel testo anziché usare la chiamata nativa API! "
                f"(Tentativo {consecutive_errors + 1}/{max_retries})",
                False
            )

    if fase_corrente == "REPORT_FINALE":
        if tool_calls:
            return (
                False,
                "[ERRORE FASE]: Sei nella fase di REPORT FINALE. Non puoi più chiamare tool! "
                "Genera l'analisi dettagliata in testo ed emetti il Verdetto.",
                False
            )

        content_clean = content.replace("\\n", "\n").replace("\\'", "'").replace("\r", "").strip()

        opzioni_verdetti = "|".join([re.escape(v) for v in verdetti_ammessi])
        pattern_verdetto = rf"(?i)^\s*\*?\*?VERDETTO\*?\*?\s*:\s*\*?\*?\b({opzioni_verdetti})\b\*?\*?[\.\s]*$"

        righe = [r.strip() for r in content_clean.splitlines() if r.strip()]
        ultima_riga = righe[-1] if righe else ""

        match = re.search(pattern_verdetto, ultima_riga)

        if not match:
            verdetti_str = ", ".join(verdetti_ammessi)
            return (
                False,
                "[ERRORE FORMATO VERDETTO]:\n"
                "L'ULTIMA RIGA del report DEVE contenere il verdetto esplicito.\n"
                "Formato richiesto: VERDETTO: <VALORE>\n"
                f"Valori validi ammessi: {verdetti_str}\n"
                f"Esempio: VERDETTO: {verdetti_ammessi[0]}",
                False
            )

        if len(content_clean) < min_char_limit:
            return (
                False,
                f"[ERRORE REPORT INCOMPLETO]: Il report finale contiene solo {len(content_clean)} caratteri. "
                f"Fornisci almeno {min_char_limit} caratteri di analisi dettagliata a supporto del Verdetto.",
                False
            )

        return True, "OK", False

    elif fase_corrente == "ESPLORAZIONE":
        if not tool_calls:
            return True, "Fine esplorazione rilevata. Transizione a FASE REPORT.", True

        # MAX 1 tool per turno
        if len(tool_calls) > 1:
            return (
                False,
                f"[ERRORE REGOLE]: Hai invocato {len(tool_calls)} tool in parallelo! "
                "Devi eseguire tassativamente MAX 1 tool per ogni turno. Scegline solo uno. "
                f"(Tentativo {consecutive_errors + 1}/{max_retries})",
                False
            )

        if chiamate_effettuate is not None:
            hash_storico = chiamate_effettuate
        else:
            hash_storico = set()
            for msg in storico_messaggi:
                if msg.get("role") == "assistant" and msg.get("tool_calls"):
                    for past_tc in msg["tool_calls"]:
                        past_fn = past_tc.get("function", {}).get("name")
                        past_args_raw = past_tc.get("function", {}).get("arguments", {})
                        try:
                            if isinstance(past_args_raw, str):
                                past_args = json.loads(past_args_raw) if past_args_raw.strip() else {}
                            elif isinstance(past_args_raw, dict):
                                past_args = past_args_raw
                            else:
                                past_args = {}
                            hash_storico.add(calcola_hash_chiamata(past_fn, past_args))
                        except (json.JSONDecodeError, TypeError):
                            continue

        tc = tool_calls[0]
        nome_fn = tc.get("function", {}).get("name")
        args_raw = tc.get("function", {}).get("arguments", {})

        if isinstance(args_raw, str):
            try:
                args_dict = json.loads(args_raw) if args_raw.strip() else {}
            except json.JSONDecodeError as err:
                return (
                    False,
                    f"[ERRORE SINTASSI PARAMETRI (Tool '{nome_fn}')]: "
                    f"I parametri passati non sono un JSON valido ({str(err)}). "
                    f"(Tentativo {consecutive_errors + 1}/{max_retries})",
                    False
                )
        elif isinstance(args_raw, dict):
            args_dict = args_raw
        else:
            args_dict = {}

        # Controllo duplicati
        chiamata_corrente = calcola_hash_chiamata(nome_fn, args_dict)
        if chiamata_corrente in hash_storico:
            return (
                False,
                f"[ERRORE TOOL DUPLICATO]: Hai già eseguito '{nome_fn}' con gli stessi parametri!\n"
                "Scegli un altro tool oppure dichiara di aver completato l'esplorazione. "
                f"(Tentativo {consecutive_errors + 1}/{max_retries})",
                False
            )
        
        if chiamate_effettuate is not None:
            chiamate_effettuate.add(chiamata_corrente)

        return True, "OK", False

    return True, "OK", False

