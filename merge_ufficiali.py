import pandas as pd

print("Unione files del Giovedì...")
# encoding='cp1252' per evitare l'errore di decodifica
gio_mattina = pd.read_csv('Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv', encoding='cp1252', low_memory=False)
gio_pomeriggio = pd.read_csv('Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv', encoding='cp1252', low_memory=False)

giovedi_completo = pd.concat([gio_mattina, gio_pomeriggio], ignore_index=True)
giovedi_completo.to_csv('Thursday-Ufficiali-Completo.csv', index=False, encoding='utf-8')


print("Unione files del Venerdì...")
ven_mattina = pd.read_csv('Friday-WorkingHours-Morning.pcap_ISCX.csv', encoding='cp1252', low_memory=False)
ven_portscan = pd.read_csv('Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv', encoding='cp1252', low_memory=False)
ven_ddos = pd.read_csv('Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv', encoding='cp1252', low_memory=False)

venerdi_completo = pd.concat([ven_mattina, ven_portscan, ven_ddos], ignore_index=True)
venerdi_completo.to_csv('Friday-Ufficiali-Completo.csv', index=False, encoding='utf-8')

print("File completi generati con successo!")
