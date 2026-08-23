import asyncio
import io
import json
import os
import sys
import time
import traceback
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv
from openai import AsyncOpenAI
from mcp import StdioServerParameters

import config
import utils
from client import esegui_analisi_mcp

load_dotenv()

class TeeStream:
    """Classe di supporto per catturare i log in una stringa e contemporaneamente stamparli su console."""
    def __init__(self, original_stream):
        self.original_stream = original_stream
        self.buffer = io.StringIO()

    def write(self, message):
        self.original_stream.write(message)
        self.buffer.write(message)

    def flush(self):
        self.original_stream.flush()

    def get_log(self):
        return self.buffer.getvalue()

def seleziona_modello_engine():
    """Mostra il menu di selezione del modello."""
    while True:
        print("============================================================")
        print("CONFIGURAZIONE INIZIALE MODELLO PER BENCHMARK")
        print("1) Llama 3.3 (70B Versatile) [Context Limit: 5000 char/tool]")
        print("2) Qwen 3.6 27B (Server Interhost)  [Context Limit: 5000 char/tool]")
        print("3) Esci dal programma")
        print("============================================================")

        scelta = input("\nScegli il modello engine (default: 2): ").strip() or "2"

        if scelta == "3":
            print("\nUscita dal programma.")
            sys.exit(0)

        elif scelta == "1":
            api_key = os.getenv("GROQ_API_KEY")
            if not api_key:
                print("[ERRORE]: Chiave GROQ_API_KEY non trovata nel file .env")
                sys.exit(1)
            base_url = "https://api.groq.com/openai/v1"
            model_name = "llama-3.3-70b-versatile"
            max_tool_chars = 5000

            return api_key, base_url, model_name, max_tool_chars

        elif scelta == "2":
            model_name = "Qwen3.6-27B"
            max_tool_chars = 5000
            api_key = os.getenv("INTERHOST_API_KEY", "ntopng_mcp_test")
            base_url = os.getenv("INTERHOST_BASE_URL", "https://aitest.interhost.it/v1")
            
            if not api_key:
                print("[ERRORE]: Chiave INTERHOST_API_KEY non trovata nel file .env")
                sys.exit(1)

            return api_key, base_url, model_name, max_tool_chars
        else:
            print("\n[ERRORE]: Opzione non valida. Inserisci 1, 2 o 3.\n")

# =====================================================================
# CORE ESECUZIONE BENCHMARK
# =====================================================================
async def run_benchmark():
    file_scenari = "test_scenarios.json"
    file_gt = "ground_truth.json"

    if not os.path.exists(file_scenari):
        print(f"File {file_scenari} non trovato.")
        return

    # Carica la Ground Truth solo per l'auditing di Python
    mappa_gt = {}
    if os.path.exists(file_gt):
        with open(file_gt, "r", encoding="utf-8") as f_gt:
            gt_data = json.load(f_gt)
            mappa_gt = {
                item["id"]: item.get("verdetto_atteso", "SCONOSCIUTO") 
                for item in gt_data 
                if "id" in item
            }

    api_key, base_url, model_name, max_tool_chars = seleziona_modello_engine()

    client_openai = AsyncOpenAI(
        api_key=api_key,
        base_url=base_url
    )

    mcp_server_params = StdioServerParameters(
        command=sys.executable,
        args=["server.py"],
        env=os.environ.copy(),
    )

    with open(file_scenari, "r", encoding="utf-8") as f:
        scenari = json.load(f)

    risultati = []
    stats = {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "FP_MISMATCH": 0, "NON_PARSABILE": 0}

    print(f"\n==================================================")
    print(f"AVVIO TEST SUITE AUTOMATIZZATA CON GROUND TRUTH")
    print(f"Scenari: {len(scenari)} | Modello: {model_name} | Base URL: {base_url}")
    print(f"==================================================\n")

    for idx, sc in enumerate(scenari, start=1):
        print(f"\n--- [SCENARIO {idx}/{len(scenari)}: {sc['id']}] ---")
        print(f"Target: {sc['ip_target']} | Categoria Originaria: {sc['categoria_tag']}")

        if not utils.valida_indirizzo_ip(sc["ip_target"]):
            print(f"IP target non valido ({sc['ip_target']}.")
            stats["NON_PARSABILE"] += 1
            continue

        dt_start = utils.valida_formato_timestamp(sc["start_time"])
        dt_end = utils.valida_formato_timestamp(sc["end_time"])

        if not dt_start or not dt_end:
            print(f"Errore nei timestamp per lo scenario {sc['id']}: formato non valido.")
            stats["NON_PARSABILE"] += 1
            continue

        # Formattazione ISO-8601 con 'T' per i prompt e per i Tool MCP
        start_time_iso = sc["start_time"].replace(" ", "T")
        end_time_iso = sc["end_time"].replace(" ", "T")

        verdetto_atteso = mappa_gt.get(sc["id"], sc.get("verdetto_atteso", "SCONOSCIUTO"))

        mappa_tag_config = {
            "web_attack_exploit": "cat_a",
            "dos_volumetric": "cat_b",
            "scan_bruteforce": "cat_c",
            "beaconing_c2": "cat_d",
            "benign": "cat_e",
            "cat_a": "cat_a",
            "cat_b": "cat_b",
            "cat_c": "cat_c",
            "cat_d": "cat_d",
            "cat_e": "cat_e"
        }

        tag_cat_raw = str(sc.get("categoria_tag", "")).strip().lower()
        cat_tag_config = mappa_tag_config.get(tag_cat_raw, "cat_e")

        id_upper = str(sc.get("id", "")).upper()
        if "TEST_CAT_A" in id_upper:
            cat_tag_config = "cat_a"
        elif "TEST_CAT_B" in id_upper:
            cat_tag_config = "cat_b"
        elif "TEST_CAT_C" in id_upper:
            cat_tag_config = "cat_c"
        elif "TEST_CAT_D" in id_upper:
            cat_tag_config = "cat_d"
        elif "TEST_CAT_E" in id_upper:
            cat_tag_config = "cat_e"

        prompt_iniziale = config.genera_prompt_iniziale(
            sc['ip_target'], start_time_iso, end_time_iso, cat_tag_config
        )

        t_inizio = time.perf_counter()

        # Intercetta lo stdout per catturare la trascrizione CLI completa durante l'esecuzione dell'analisi MCP
        original_stdout = sys.stdout
        tee = TeeStream(original_stdout)
        sys.stdout = tee

        try:
            try:
                report_md, verdetto_ottenuto, meta = await esegui_analisi_mcp(
                    client=client_openai,
                    mcp_server_params=mcp_server_params,
                    ip_target=sc["ip_target"],
                    start_time=start_time_iso,
                    end_time=end_time_iso,
                    model_name=model_name,
                    prompt_iniziale=prompt_iniziale,
                    categoria_tag=cat_tag_config,
                    max_tool_chars=max_tool_chars,
                    sleep_time=1.0
                )

                tempo_totale = time.perf_counter() - t_inizio
                
            finally:
                # Assicura il ripristino dello stdout anche in caso di eccezioni 
                sys.stdout = original_stdout
                cli_log = tee.get_log()

            # Fallback del verdetto: se l'estrazione da markdown fallisce, usa il verdetto raw del tool
            verdetto_final = utils.estrai_verdetto_pulito(report_md)
            if not verdetto_final or verdetto_final in ["-", "", "NON_IDENTIFICATO"]:
                verdetto_final = verdetto_ottenuto if (verdetto_ottenuto and verdetto_ottenuto != "-") else "NON_IDENTIFICATO"

            ground_truth_db = utils.controlla_ground_truth(sc["ip_target"], sc["start_time"], sc["end_time"])
            esito_metrica = utils.calcola_esito_classificazione(verdetto_final, ground_truth_db, verdetto_atteso)

            if esito_metrica in ["TP", "TN", "FP", "FN", "NON_PARSABILE"]:
                stats[esito_metrica] += 1
            elif esito_metrica.startswith("FP_MISMATCH"):
                stats["FP_MISMATCH"] += 1
            else:
                stats["NON_PARSABILE"] += 1

            telemetria_txt = f"--- TELEMETRIA ESECUZIONE ---\n```json\n{json.dumps(meta, indent=2)}\n```"

            utils.salva_risultati_su_disco(
                ip_target=sc["ip_target"],
                categoria=cat_tag_config,
                report_md=report_md,
                log_txt=cli_log,
                telemetria_txt=telemetria_txt,
                start_time=dt_start,
                end_time=dt_end
            )

            esito = {
                "ID": sc["id"],
                "ip_target": sc["ip_target"],
                "start_time": sc["start_time"],
                "end_time": sc["end_time"],
                "Categoria": cat_tag_config,
                "Verdetto Atteso": verdetto_atteso,
                "Verdetto LLM": verdetto_final,
                "Esito Auditing": esito_metrica,
                "Report_MD": report_md,
                "Telemetria": meta,
                "Ground Truth DB": ground_truth_db,
                "Tempo Totale (s)": round(tempo_totale, 2)
            }
            
            print(f" -> Categoria Applicata: {cat_tag_config}")
            print(f" -> Verdetto LLM       : {verdetto_final}")
            print(f" -> Ground Truth       : {ground_truth_db}")
            print(f" -> Verdetto Atteso    : {verdetto_atteso}")
            print(f" -> Esito              : {esito_metrica}")

            risultati.append(esito)

        except (asyncio.CancelledError, KeyboardInterrupt):
            sys.stdout = original_stdout
            print(f"\n[CHIAMANTE]: Task annullato/interrotto dall'utente durante lo scenario {sc['id']}.")
            raise
        except Exception as e:
            sys.stdout = original_stdout
            cli_log = tee.get_log() + f"\nEccezione sollevata: {traceback.format_exc()}"

            print(f"Errore durante lo scenario {sc['id']}: {e}")
            stats["NON_PARSABILE"] += 1

            utils.salva_risultati_su_disco(
                ip_target=sc["ip_target"],
                categoria=f"{cat_tag_config}_ERROR",
                report_md="[ERRORE DURANTE L'ESECUZIONE]",
                log_txt=cli_log,
                telemetria_txt="--- TELEMETRIA ESECUZIONE ---\nERRORE",
                start_time=dt_start,
                end_time=dt_end
            )

            esito = {
                "ID": sc["id"],
                "ip_target": sc["ip_target"],
                "start_time": sc["start_time"],
                "end_time": sc["end_time"],
                "Categoria": cat_tag_config,
                "Verdetto Atteso": verdetto_atteso,
                "Verdetto LLM": "ERRORE",
                "Esito Auditing": "NON_PARSABILE",
                "Report_MD": "[ERRORE DURANTE L'ESECUZIONE]",
                "Telemetria": {},
                "Ground Truth DB": {},
                "Tempo Totale (s)": 0
            }
            
            risultati.append(esito)

    output_dir = Path("benchmark_results")
    output_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = output_dir / f"benchmark_{model_name.replace(':', '_')}_{timestamp}.json"

    # Salva il dataset aggregato
    with open(output_filename, "w", encoding="utf-8") as f_out:
        json.dump(risultati, f_out, indent=2, ensure_ascii=False)

    print(f"\nBenchmark completato! Dataset salvato in '{output_filename}'")
    utils.stampa_e_salva_metriche(stats, output_dir, timestamp, model_name)

    await client_openai.close()

if __name__ == "__main__":
    try:
        asyncio.run(run_benchmark())
    except (KeyboardInterrupt, SystemExit):
        print("\n\nBenchmark interrotto dall'utente.")
        sys.exit(0)
