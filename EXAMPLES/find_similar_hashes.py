from elasticsearch import Elasticsearch
from collections import defaultdict, Counter
from tqdm import tqdm
from neo4j import GraphDatabase
from sklearn.metrics import jaccard_score
import json
import time  # Importa il modulo time

# Database connection details
uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"
driver = GraphDatabase.driver(uri, auth=(user, password))

# Funzione per estrarre indicatori da Neo4j
def extract_indicators(tx):
    query = """
    MATCH (m:Malware)<-[:indicates]-(b:Indicator)
    WHERE toLower(m.description) CONTAINS 'emotet'
    RETURN m.name AS malware, b.pattern AS PATTERN
    """
    result = tx.run(query)
    patterns = []
    for record in tqdm(result, desc="Retrieving Malware and Indicators ..."):
        pattern = record["PATTERN"]
        patterns.append(pattern)
    return patterns

# Estrai indicatori da Neo4j
with driver.session() as session:
    patterns = session.execute_read(extract_indicators)

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

# Query per ottenere documenti con MITRE ATT&CK, calls_highlighted, registry_keys, e modules_loaded
query = {
    "query": {
        "bool": {
            "must": [
                {"exists": {"field": "data.attributes.mitre_attack_techniques.id"}},
                {"exists": {"field": "data.attributes.calls_highlighted"}},
                {"exists": {"field": "data.attributes.registry_keys_opened"}},
                {"exists": {"field": "data.attributes.registry_keys_set"}},
                {"exists": {"field": "data.attributes.modules_loaded"}}
            ]
        }
    },
    "_source": ["data.id", "data.attributes.mitre_attack_techniques.id", "data.attributes.calls_highlighted", 
                "data.attributes.registry_keys_opened", "data.attributes.registry_keys_set", "data.attributes.modules_loaded"]
}

# Esegui la query su Elasticsearch
response = es.search(index="malware_reports", body=query, size=10000)

# Dizionario per correlare hash e campi
hash_to_data = {}

print(f"Total number of Results -> {len(response['hits']['hits'])}")
# Costruisci il dizionario hash -> attributi (calls_highlighted, mitre_attack_techniques, registry_keys, modules_loaded)
for hit in response['hits']['hits']:
    data_list = hit['_source'].get('data', [])
    for data_item in data_list:
        doc_id = data_item.get('id', "").split("_")[0]  # Estrarre l'ID del documento
        if '_CAPE San' in data_item.get('id', ""):
            if doc_id in HASHES:
                # Estrai i vari campi
                calls_highlighted = data_item.get('attributes', {}).get('calls_highlighted', [])
                mitre_techniques = data_item.get('attributes', {}).get('mitre_attack_techniques', [])
                registry_keys_opened = data_item.get('attributes', {}).get('registry_keys_opened', [])
                registry_keys_set = data_item.get('attributes', {}).get('registry_keys_set', [])
                modules_loaded = data_item.get('attributes', {}).get('modules_loaded', [])
                
                # Associa ogni campo all'hash
                hash_to_data[doc_id] = {
                    "calls_highlighted": set(calls_highlighted),
                    "mitre_techniques": set([tech['id'] for tech in mitre_techniques if 'id' in tech]),  # Estrai solo l'ID dalle tecniche MITRE
                    "registry_keys_opened": set(registry_keys_opened),
                    "registry_keys_set": set([key['key'] for key in registry_keys_set if 'key' in key]),  # Estrai il campo 'key' dalle chiavi impostate
                    "modules_loaded": set(modules_loaded)  # Assumendo che questo campo sia già una lista di valori hashable
                }


# Funzione per calcolare la Jaccard Similarity tra due insiemi
def jaccard_similarity(set1, set2):
    if not set1 and not set2:
        return 0.0  # Se entrambi gli insiemi sono vuoti, sono identici
    return len(set1.intersection(set2)) / len(set1.union(set2))

# Funzione per calcolare la similarità complessiva tra due hash
def calculate_overall_similarity(data1, data2):
    total_similarity = 0
    fields = ["calls_highlighted", "mitre_techniques", "registry_keys_opened", "registry_keys_set", "modules_loaded"]
    
    # Calcola la similarità per ciascun campo
    for field in fields:
        total_similarity += jaccard_similarity(data1[field], data2[field])
    
    # Media delle similarità su tutti i campi
    overall_similarity = total_similarity / len(fields)
    return overall_similarity

# Genera coppie di hash e calcola la similarità complessiva
hash_pairs_similarity = []
hashes = list(hash_to_data.keys())

total_time = 0  # Variabile per il tempo totale
total_comparisons = 0  # Numero totale di confronti

for i in range(len(hashes)):
    for j in range(i + 1, len(hashes)):
        hash1, hash2 = hashes[i], hashes[j]
        data1, data2 = hash_to_data[hash1], hash_to_data[hash2]
        
        start_time = time.time()  # Tempo di inizio
        similarity = calculate_overall_similarity(data1, data2)
        end_time = time.time()  # Tempo di fine
        
        elapsed_time = end_time - start_time  # Tempo impiegato per questa coppia
        total_time += elapsed_time
        total_comparisons += 1
        
        common_calls = data1["calls_highlighted"].intersection(data2["calls_highlighted"])
        
        hash_pairs_similarity.append((hash1, hash2, similarity, common_calls))

# Calcola il tempo medio per confronto
average_time_per_comparison = total_time / total_comparisons if total_comparisons > 0 else 0
print(f"Average time per comparison: {average_time_per_comparison:.6f} seconds")

# Ordina le coppie per similarità decrescente
hash_pairs_similarity.sort(key=lambda x: x[2], reverse=True)

# Stampa le prime 10 coppie più simili e i loro attributi in comune
print("Top 10 most similar hash pairs based on overall similarity:")
for hash1, hash2, similarity, common_calls in hash_pairs_similarity[:10]:
    data1, data2 = hash_to_data[hash1], hash_to_data[hash2]
    
    # Trova gli elementi in comune per ciascun campo
    common_mitre_techniques = data1["mitre_techniques"].intersection(data2["mitre_techniques"])
    common_registry_keys_opened = data1["registry_keys_opened"].intersection(data2["registry_keys_opened"])
    common_registry_keys_set = data1["registry_keys_set"].intersection(data2["registry_keys_set"])
    common_modules_loaded = data1["modules_loaded"].intersection(data2["modules_loaded"])
    
    print(f"{hash1} - {hash2}: Similarity = {similarity:.2f}")
    print(f"Common calls_highlighted: {common_calls}")
    print(f"Common mitre_techniques: {common_mitre_techniques}")
    print(f"Common registry_keys_opened: {common_registry_keys_opened}")
    print(f"Common registry_keys_set: {common_registry_keys_set}")
    print(f"Common modules_loaded: {common_modules_loaded}\n")

# Salva i risultati in un file JSON
results = []
for hash1, hash2, similarity, common_calls in hash_pairs_similarity:
    data1, data2 = hash_to_data[hash1], hash_to_data[hash2]
    
    # Trova gli elementi in comune per ciascun campo
    common_mitre_techniques = data1["mitre_techniques"].intersection(data2["mitre_techniques"])
    common_registry_keys_opened = data1["registry_keys_opened"].intersection(data2["registry_keys_opened"])
    common_registry_keys_set = data1["registry_keys_set"].intersection(data2["registry_keys_set"])
    common_modules_loaded = data1["modules_loaded"].intersection(data2["modules_loaded"])
    
    results.append({
        "hash1": hash1,
        "hash2": hash2,
        "similarity": similarity,
        "common_calls": list(common_calls),
        "common_mitre_techniques": list(common_mitre_techniques),
        "common_registry_keys_opened": list(common_registry_keys_opened),
        "common_registry_keys_set": list(common_registry_keys_set),
        "common_modules_loaded": list(common_modules_loaded)
    })

with open("Spyware_hash_pairs_similarity_with_all_fields.json", "w") as f:
    json.dump(results, f, indent=4)
