from elasticsearch import Elasticsearch
from collections import defaultdict, Counter
from tqdm import tqdm
from neo4j import GraphDatabase
import json

uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"
driver = GraphDatabase.driver(uri, auth=(user, password))

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

with driver.session() as session:
    patterns = session.execute_read(extract_indicators)
    technique_to_objective = session.execute_read(extract_mitre_to_objective)

HASHES = [pattern.split('= ', 1)[1].replace(" ]", '').replace("'", "") for pattern in tqdm(patterns, desc='Extract Hashes ...')]

es = Elasticsearch(
    hosts=[{
        'host': 'localhost',
        'port': 9200,
        'scheme': 'http'
    }]
)

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

response = es.search(index="malware_reports", body=query, size=10000)

hash_to_calls = {}
hash_to_techniques = {}

print(f"Total number of Results -> {len(response['hits']['hits'])}")
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

api_to_objectives = defaultdict(Counter)

for doc_id, techniques in hash_to_techniques.items():
    for technique in techniques:
        if technique in technique_to_objective:
            tactic = technique_to_objective[technique]
            if doc_id in hash_to_calls:
                for api_call in hash_to_calls[doc_id]:
                    api_to_objectives[api_call][tactic] += 1  # Conta gli obiettivi associati all'API

api_influence = {}

for api_call, objective_counts in api_to_objectives.items():
    total_objectives_for_api = sum(objective_counts.values())  # Somma totale degli obiettivi per l'API
    influence_percentages = {objective: (count / total_objectives_for_api) * 100 for objective, count in objective_counts.items()}
    api_influence[api_call] = influence_percentages

print("API Influence on Objectives (percentage of objectives per API):")
for api_call, influence_data in api_influence.items():
    print(f"\nAPI: {api_call}")
    for objective, percentage in influence_data.items():
        print(f"  Objective: {objective} - {percentage:.2f}%")

with open("api_influence_ransomware_on_objectives.json", "w") as f:
    json.dump(api_influence, f, indent=4)


def top_10_api_per_objective(api_influence):
    objective_top_10_apis = defaultdict(list)

    for api_call, influence_data in api_influence.items():
        for objective, percentage in influence_data.items():
            objective_top_10_apis[objective].append((api_call, percentage))

    for objective, api_list in objective_top_10_apis.items():
        api_list.sort(key=lambda x: x[1], reverse=True)
        objective_top_10_apis[objective] = api_list[:3]

    return objective_top_10_apis

top_10_api_by_objective = top_10_api_per_objective(api_influence)

print("\nTop 3 API used by Spyware for each Objective:")
for objective, top_apis in top_10_api_by_objective.items():
    print(f"\nObjective: {objective}")
    for api_call, percentage in top_apis:
        print(f"  API: {api_call} - {percentage:.2f}%")

with open("top_10_api_per_objective.json", "w") as f:
    json.dump(top_10_api_by_objective, f, indent=4)
