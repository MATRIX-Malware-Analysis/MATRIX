from neo4j import GraphDatabase
import json
from collections import defaultdict, Counter
from tqdm import tqdm

# Connessione a Neo4j
uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"

driver = GraphDatabase.driver(uri, auth=(user, password))

# Funzione per categorizzare il malware in base alla descrizione
def categorize_malware(description):
    description = description.lower()
    if 'ransomware' in description:
        return 'ransomware'
    elif 'spy' in description:
        return 'spy'
    elif 'rat' in description:
        return 'rat'
    elif 'backdoor' in description:
        return 'backdoor'
    elif 'trojan' in description:
        return 'trojan'
    elif 'downloader' in description:
        return 'downloader'
    return 'unknown'

# Funzione per estrarre i comportamenti del malware con focus su "Discovery"
def extract_malware_behaviors(tx):
    query = """
    MATCH (m:Malware)-[:uses]->(b:Malware_Behavior)-[:related_to]->(o:Malware_Objective)
    WHERE toLower(m.description) CONTAINS 'ransomware'
    OR toLower(m.description) CONTAINS 'spy'
    OR toLower(m.description) CONTAINS 'rat'
    OR toLower(m.description) CONTAINS 'backdoor'
    OR toLower(m.description) CONTAINS 'trojan'
    OR toLower(m.description) CONTAINS 'downloader'
    AND o.name = 'Impact'
    RETURN m.name AS malware, m.description AS description, b.name AS behavior, b.external_references_0 AS external_id, o.name AS objective
    """
    result = tx.run(query)
    malware_behaviors = defaultdict(list)
    behavior_objectives = defaultdict(list)
    malware_categories = defaultdict(list)  # Per memorizzare la categoria di malware
    for record in tqdm(result, desc="Retrieving Behaviors and Objectives for 'Discovery' ..."):
        malware = record["malware"]
        description = record["description"]
        behavior = record["behavior"]
        technique_id = record["external_id"]
        technique_dict = eval(technique_id)
        external_id = technique_dict["external_id"]
        objective = record["objective"]
        
        # Categorizza il malware
        category = categorize_malware(description)
        malware_behaviors[malware].append(external_id)
        behavior_objectives[external_id].append(objective)
        malware_categories[category].append(malware)  # Collega il malware alla categoria
        
    return malware_behaviors, behavior_objectives, malware_categories

# Esegui la query e ottieni i comportamenti del malware relativi all'obiettivo "Discovery"
with driver.session() as session:
    malware_behaviors, behavior_objectives, malware_categories = session.read_transaction(extract_malware_behaviors)

print("[!] Extracting APIs ...")
# Carica il file JSON contenente le API utilizzate per ogni tecnica
with open("attack_to_apis.json", 'r', encoding='utf-8') as f:
    attack_to_apis = json.load(f)

# Conta le API utilizzate per ciascuna categoria di malware per l'obiettivo "Discovery"
api_counter_per_category = defaultdict(Counter)
api_objectives_per_category = defaultdict(lambda: defaultdict(set))

for category, malwares in malware_categories.items():
    for malware in malwares:
        external_ids = malware_behaviors[malware]
        for external_id in external_ids:
            if external_id in attack_to_apis:
                apis = attack_to_apis[external_id]
                api_counter_per_category[category].update(apis)
                objectives = behavior_objectives[external_id]
                for api in apis:
                    api_objectives_per_category[category][api].update(objectives)

# Estrai le API più utilizzate per ciascuna categoria, salva le prime 15 e calcola la percentuale sui top 50%
with open("Discovery_APIs_Per_Category_Percentages_Top50.txt", "w") as f:
    print("Most common APIs (Top 15) used by each malware category for the 'Discovery' objective (with percentages):")
    f.write("Most common APIs (Top 15) used by each malware category for the 'Discovery' objective (with percentages):\n")
    
    for category, api_counter in api_counter_per_category.items():
        f.write(f"\nMalware Category: {category.capitalize()}\n")
        f.write("-----------------------------\n")
        
        # Ordina le API per il loro conteggio
        most_common_apis = api_counter.most_common()
        total_apis = sum(api_counter.values())  # Calcola il totale delle API per la categoria
        
        # Calcola il 50% superiore
        cumulative_count = 0
        top_50_percent_apis = []
        
        for api, count in most_common_apis:
            cumulative_count += count
            top_50_percent_apis.append((api, count))
            if cumulative_count >= total_apis * 0.10:
                break

        # Calcola il totale delle API selezionate (top 50%)
        total_top_50_apis = sum(count for _, count in top_50_percent_apis)

        # Ora salva le prime 15 API e calcola la percentuale in base al top 50% delle API
        top_15_apis = top_50_percent_apis[:15]  # Seleziona le prime 15 API dalle top 50%

        for api, count in top_15_apis:
            percentage = (count / total_top_50_apis) * 100  # Calcola la percentuale sui top 50%
            associated_objectives = ", ".join(api_objectives_per_category[category][api])
            f.write(f"{api}: {percentage:.2f}% (Objectives: {associated_objectives})\n")
            print(f"{category.capitalize()} -> {api}: {percentage:.2f}% (Objectives: {associated_objectives})\n")

# Chiudi la connessione a Neo4j
driver.close()
