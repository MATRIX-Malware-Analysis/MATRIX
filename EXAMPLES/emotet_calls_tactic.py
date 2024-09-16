from elasticsearch import Elasticsearch
from collections import defaultdict, Counter
from tqdm import tqdm
from neo4j import GraphDatabase
import json

# Database connection details
uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"
driver = GraphDatabase.driver(uri, auth=(user, password))

# Funzione per estrarre indicatori da Neo4j
#WHERE toLower(m.description) CONTAINS 'emotet'
def extract_indicators(tx):
    query = """
    MATCH (m:Malware)<-[:indicates]-(b:Indicator)
    WHERE toLower(m.description) CONTAINS 'spyware'
    RETURN m.name AS malware, b.pattern AS PATTERN
    """
    result = tx.run(query)
    patterns = []
    for record in tqdm(result, desc="Retrieving Malware and Indicators ..."):
        pattern = record["PATTERN"]
        patterns.append(pattern)
    return patterns

# Funzione per mappare le MITRE Techniques agli Objectives
def extract_mitre_to_objective(tx):
    query = """
    MATCH (m:Malware)-[:uses]->(b:Malware_Behavior)-[:related_to]->(i:Malware_Objective)
    RETURN b.external_references_0 AS technique_id, i.name AS tactic_name
    """
    result = tx.run(query)
    technique_to_objective = {}
    
    for record in result:
        technique_id = record["technique_id"]
        technique_id = eval(technique_id)["external_id"]  # Parsing the technique ID
        tactic_name = record["tactic_name"]
        technique_to_objective[technique_id] = tactic_name
    
    return technique_to_objective

# Estrai indicatori da Neo4j
with driver.session() as session:
    patterns = session.execute_read(extract_indicators)
    technique_to_objective = session.execute_read(extract_mitre_to_objective)

# Estrai hash dagli indicatori
HASHES = [pattern.split('= ', 1)[1].replace(" ]", '').replace("'", "") for pattern in tqdm(patterns, desc='Extract Hashes ...')]

# Connessione a Elasticsearch
es = Elasticsearch(
    hosts=[{
        'host': 'localhost',
        'port': 9200,
        'scheme': 'http'
    }]
)

# Query per ottenere documenti con tecniche MITRE ATT&CK e chiamate evidenziate
query = {
    "query": {
        "bool": {
            "must": [
                {"exists": {"field": "data.attributes.mitre_attack_techniques.id"}},
                {"exists": {"field": "data.attributes.calls_highlighted"}}
            ]
        }
    },
    "_source": ["data.id", "data.attributes.mitre_attack_techniques.id", "data.attributes.calls_highlighted"]
}

# Esegui la query su Elasticsearch
response = es.search(index="malware_reports", body=query, size=10000)

# Dizionario per correlare hash e calls_highlighted
hash_to_calls = {}
hash_to_techniques = {}

print(f"Total number of Results -> {len(response['hits']['hits'])}")
# Costruisci il dizionario hash -> calls_highlighted e hash -> mitre_techniques
for hit in response['hits']['hits']:
    data_list = hit['_source'].get('data', [])
    for data_item in data_list:
        if '_CAPE Sandbox' in data_item.get('id', ""):
            doc_id = data_item.get('id', "").split("_")[0]  # Estrarre l'ID del documento
            if doc_id in HASHES:
                calls_highlighted = data_item.get('attributes', {}).get('calls_highlighted', [])
                mitre_techniques = data_item.get('attributes', {}).get('mitre_attack_techniques', [])
                if calls_highlighted:
                    hash_to_calls[doc_id] = set(calls_highlighted)  # Usare set per la similarità
                if mitre_techniques:
                    hash_to_techniques[doc_id] = [tech.get('id') for tech in mitre_techniques if tech.get('id')]

# Correlazione API -> Objective
api_to_objectives = defaultdict(Counter)

# Assegna gli Objectives a ciascun API
for doc_id, techniques in hash_to_techniques.items():
    for technique in techniques:
        if technique in technique_to_objective:
            tactic = technique_to_objective[technique]
            if doc_id in hash_to_calls:
                for api_call in hash_to_calls[doc_id]:
                    api_to_objectives[api_call][tactic] += 1  # Conta gli obiettivi associati all'API

# Calcola l'influenza di ciascun API sugli Objectives
api_influence = {}

for api_call, objective_counts in api_to_objectives.items():
    total_objectives_for_api = sum(objective_counts.values())  # Somma totale degli obiettivi per l'API
    influence_percentages = {objective: (count / total_objectives_for_api) * 100 for objective, count in objective_counts.items()}
    api_influence[api_call] = influence_percentages

# Stampa l'influenza delle API sugli Objectives
print("API Influence on Objectives (percentage of objectives per API):")
for api_call, influence_data in api_influence.items():
    print(f"\nAPI: {api_call}")
    for objective, percentage in influence_data.items():
        print(f"  Objective: {objective} - {percentage:.2f}%")

# Salva i risultati in un file JSON
with open("api_influence_ransomware_on_objectives.json", "w") as f:
    json.dump(api_influence, f, indent=4)


# Funzione per selezionare le 10 API con la percentuale più alta per ogni Objective
def top_10_api_per_objective(api_influence):
    # Dizionario per memorizzare le 10 API più influenti per ogni Objective
    objective_top_10_apis = defaultdict(list)

    # Passa attraverso ogni API e la sua influenza sugli Objectives
    for api_call, influence_data in api_influence.items():
        for objective, percentage in influence_data.items():
            objective_top_10_apis[objective].append((api_call, percentage))

    # Ordina le API per ogni Objective in base alla percentuale e seleziona le prime 10
    for objective, api_list in objective_top_10_apis.items():
        # Ordina le API per percentuale decrescente e prendi le prime 10
        api_list.sort(key=lambda x: x[1], reverse=True)
        objective_top_10_apis[objective] = api_list[:3]

    return objective_top_10_apis

# Calcola le 10 API più influenti per ogni Objective
top_10_api_by_objective = top_10_api_per_objective(api_influence)

# Stampa i risultati delle 10 API con la percentuale più alta per ogni Objective
print("\nTop 3 API used by Spyware for each Objective:")
for objective, top_apis in top_10_api_by_objective.items():
    print(f"\nObjective: {objective}")
    for api_call, percentage in top_apis:
        print(f"  API: {api_call} - {percentage:.2f}%")

# Salva i risultati in un file JSON
with open("top_10_api_per_objective.json", "w") as f:
    json.dump(top_10_api_by_objective, f, indent=4)
