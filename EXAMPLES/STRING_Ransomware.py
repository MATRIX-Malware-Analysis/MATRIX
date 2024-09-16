from neo4j import GraphDatabase
import json
from collections import defaultdict, Counter
from tqdm import tqdm

# Connessione a Neo4j
uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"

driver = GraphDatabase.driver(uri, auth=(user, password))

# Funzione per estrarre i comportamenti del malware e i loro ID esterni
def extract_malware_behaviors(tx):
    query = """
    MATCH (m:Malware)-[:uses]->(b:MalwareBehavior)
    WHERE toLower(m.description) CONTAINS 'ransomware'
    RETURN m.name AS malware, b.name AS behavior, b.external_references_0_external_id AS external_id
    """
    result = tx.run(query)
    malware_behaviors = defaultdict(list)
    for record in tqdm(result, desc="Retrieving Behaviors ..."):
        malware = record["malware"]
        behavior = record["behavior"]
        external_id = record["external_id"]
        #print(f"Behavior : {behavior} -> External ID : {external_id}")
        malware_behaviors[malware].append(external_id)
    return malware_behaviors

# Esegui la query e ottieni i comportamenti del malware
with driver.session() as session:
    malware_behaviors = session.read_transaction(extract_malware_behaviors)

print("[!] Extracting APIs ...")
# Carica il file JSON contenente le API utilizzate per ogni tecnica
with open("attack_to_strings.json", 'r', encoding='utf-8') as f:
    attack_to_apis = json.load(f)

# Conta le API utilizzate per i malware ransomware
api_counter = Counter()
for malware, external_ids in tqdm(malware_behaviors.items(), desc='Processing malware behaviors'):
    for external_id in external_ids:
        if external_id in attack_to_apis:
            apis = attack_to_apis[external_id]
            api_counter.update(apis)

# Estrai le API più utilizzate
most_common_apis = api_counter.most_common()

# Stampa i risultati
with open("Strings_Ransomware.txt", "a") as f:
    print("Most common Strings used by Ransomware:")
    for api, count in most_common_apis:
        print(f"{api}: {count}")
        f.write(f"{api}: {count}\n")

# Chiudi la connessione a Neo4j
driver.close()
