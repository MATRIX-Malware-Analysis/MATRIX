from neo4j import GraphDatabase
import json
from collections import defaultdict, Counter
from tqdm import tqdm
import time
# Connessione a Neo4j
uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"

driver = GraphDatabase.driver(uri, auth=(user, password))
start_time = time.time()
# Funzione per estrarre i comportamenti del malware e i loro ID esterni e obiettivi
def extract_malware_behaviors(tx):
    query = """
    MATCH (m:Malware)-[:uses]->(b:Malware_Behavior)-[:related_to]->(o:Malware_Objective)
    WHERE toLower(m.description) CONTAINS 'ursnif'
    RETURN m.name AS malware, b.name AS behavior, b.external_references_0 AS external_id, o.name AS objective
    """
    result = tx.run(query)
    malware_behaviors = defaultdict(list)
    behavior_objectives = defaultdict(list)
    for record in tqdm(result, desc="Retrieving Behaviors and Objectives ..."):
        print(record)
        malware = record["malware"]
        print(f'Malware -> {malware}')
        behavior = record["behavior"]
        print(f'\nBehaviors -> {behavior}')
        technique_id = record["external_id"]
        technique_dict = eval(technique_id)
        external_id = technique_dict["external_id"]
        objective = record["objective"]
        malware_behaviors[malware].append(external_id)
        behavior_objectives[external_id].append(objective)
    return malware_behaviors, behavior_objectives

# Esegui la query e ottieni i comportamenti del malware
with driver.session() as session:
    malware_behaviors, behavior_objectives = session.read_transaction(extract_malware_behaviors)

print("[!] Extracting APIs ...")
# Carica il file JSON contenente le API utilizzate per ogni tecnica
with open("attack_to_apis.json", 'r', encoding='utf-8') as f:
    attack_to_apis = json.load(f)

# Conta le API utilizzate per i malware Spyware e i loro obiettivi
api_counter = Counter()
api_objectives = defaultdict(set)

for malware, external_ids in tqdm(malware_behaviors.items(), desc='Processing malware behaviors'):
    for external_id in external_ids:
        if external_id in attack_to_apis:
            apis = attack_to_apis[external_id]
            api_counter.update(apis)
            objectives = behavior_objectives[external_id]
            for api in apis:
                api_objectives[api].update(objectives)

# Estrai le API più utilizzate
most_common_apis = api_counter.most_common()

# Stampa i risultati
with open("API_Ursnif_Objectives.txt", "w") as f:
    print("Most common APIs used by Spyware and their associated Objectives:")
    f.write("Most common APIs used by Spyware and their associated Objectives:\n")
    for api, count in most_common_apis:
        associated_objectives = ", ".join(api_objectives[api])
        print(f"{api}: {count} (Objectives: {associated_objectives})")
        f.write(f"{api}: {count} (Objectives: {associated_objectives})\n")

# Chiudi la connessione a Neo4j
end_time = time.time()

final_time = end_time - start_time

print(f'Final Time -> {final_time}')
driver.close()
