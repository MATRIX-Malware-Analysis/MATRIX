from elasticsearch import Elasticsearch
from neo4j import GraphDatabase
from collections import Counter
import ast
from tqdm import tqdm
import matplotlib.pyplot as plt

# Connessione a Elasticsearch
es = Elasticsearch(
    hosts=[{
        'host': 'localhost',
        'port': 9200,
        'scheme': 'http'
    }]
)

# Connessione a Neo4j
uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"
driver = GraphDatabase.driver(uri, auth=(user, password))

# Funzione per estrarre indicatori da Neo4j
def extract_indicators(tx):
    query = """
    MATCH (m:Malware)<-[:indicates]-(b:Indicator)
    WHERE toLower(m.description) CONTAINS 'ransom'
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

# Query per ottenere documenti con tecniche MITRE ATT&CK
query = {
    "query": {
        "bool": {
            "must": [
                {"exists": {"field": "data.attributes.mitre_attack_techniques.id"}},
            ]
        }
    },
    "_source": ["data.id", "data.attributes.mitre_attack_techniques.id"]
}

# Esegui la query su Elasticsearch
response = es.search(index="malware_reports", body=query, size=10000)

# Dizionario per correlare hash e tecniche MITRE
hash_to_techniques = {}

print(f"Total number of Results -> {len(response['hits']['hits'])}")
# Costruisci il grafo totale
for hit in response['hits']['hits']:
    techniques = []
    data_list = hit['_source'].get('data', [])
    for data_item in data_list:
        attributes = data_item.get('id', "")
        doc_id = attributes.split("_")[0]
        if 'b68f76d17c4343e1a3a709c09d37a5e069ce1aec55dcb1861b2af79cc1aef47b' in doc_id:
            print("++++++++++++++++++++++ b68f76d17c4343e1a3a709c09d37a5e069ce1aec55dcb1861b2af79cc1aef47b FOUND ++++++++++++++++")
        try:
            if doc_id in HASHES:
                mitre_techniques = data_item.get('attributes', {}).get('mitre_attack_techniques', [])
                techniques.extend([tech.get('id') for tech in mitre_techniques if tech.get('id')])
                # Mappa l'hash alle tecniche corrispondenti
                hash_to_techniques[doc_id] = techniques
        except Exception as e:
            print(f'Exception -> {e}: \n{data_item}')
    
    #print(hash_to_techniques)
# Debug: stampa il risultato dell'associazione tra hash e tecniche
if not hash_to_techniques:
    print("Nessuna corrispondenza trovata tra gli hash estratti e le tecniche MITRE ATT&CK.")
else:
    print("Associazione tra Hash e Tecniche MITRE ATT&CK:")
    for hash_val, techniques in hash_to_techniques.items():
        print(f"Hash: {hash_val} - Tecniche: {techniques}")

# Visualizzazione dei risultati con un esempio di distribuzione
def plot_techniques_distribution(hash_to_techniques):
    # Conta la frequenza di ciascuna tecnica
    techniques_counter = Counter(tech for techniques in hash_to_techniques.values() for tech in techniques)
    sorted_techniques = sorted(techniques_counter.items(), key=lambda x: x[1], reverse=True)
    
    # Controlla se ci sono tecniche da visualizzare
    if not sorted_techniques:
        print("Nessuna tecnica disponibile per la visualizzazione.")
        return

    techniques, counts = zip(*sorted_techniques)

    plt.figure(figsize=(15, 10))
    plt.barh(techniques[:20], counts[:20], color='skyblue')  # Mostra le prime 20 tecniche più frequenti
    plt.xlabel('Frequenza')
    plt.ylabel('Tecniche MITRE ATT&CK')
    plt.title('Distribuzione delle Tecniche MITRE ATT&CK nei Documenti di Elasticsearch')
    plt.gca().invert_yaxis()  # Inverte l'asse y per mostrare le tecniche più frequenti in alto
    plt.tight_layout()
    plt.savefig("hash_techniques_distribution.png")
    plt.show()
    print(techniques_counter)
    return techniques_counter


# Mostra la distribuzione delle tecniche MITRE ATT&CK
techniques_counter = plot_techniques_distribution(hash_to_techniques)

technique_count = dict(techniques_counter)

from neo4j import GraphDatabase
from collections import defaultdict
import json
import networkx as nx
import matplotlib.pyplot as plt
import ast
from matplotlib.lines import Line2D

# Connessione a Neo4j
uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"
driver = GraphDatabase.driver(uri, auth=(user, password))

# Ordinamento delle tattiche
tactics_order = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact"
]

# Funzione per estrarre le tecniche e tattiche con conteggio
def extract_techniques_and_tactics(tx):
    query = """
    MATCH (m:Malware)-[:uses]->(b:Malware_Behavior)-[:related_to]->(i:Malware_Objective)
    WHERE toLower(m.description) CONTAINS 'ransom'
    RETURN b.external_references_0 AS technique_id, i.name AS tactic_name
    """
    result = tx.run(query)
    technique_count = defaultdict(int)
    technique_to_tactic = {}
    
    for record in result:
        technique_id = record["technique_id"]
        tactic_name = record["tactic_name"]
        technique_id = ast.literal_eval(technique_id)
        technique_id = technique_id["external_id"]
        if technique_id:
            technique_to_tactic[technique_id] = tactic_name
            # Incrementa il conteggio della tecnica
            technique_count[technique_id] += 1
    return technique_to_tactic, technique_count

# Funzione per ordinare e raggruppare le tecniche in base alle tattiche
def group_techniques_by_tactic(technique_to_tactic):
    grouped_techniques = defaultdict(list)
    for technique, tactic in technique_to_tactic.items():
        grouped_techniques[tactic].append(technique)
    return grouped_techniques

# Estrai le tecniche e le tattiche da Neo4j
with driver.session() as session:
    technique_to_tactic, _ = session.read_transaction(extract_techniques_and_tactics)

# Raggruppa le tecniche per tattica
grouped_techniques = group_techniques_by_tactic(technique_to_tactic)

# Calcola la frequenza normalizzata delle tecniche
def calculate_normalized_frequencies(technique_count):
    total_techniques = sum(technique_count.values())
    technique_frequencies = {}

    # Calcola la frequenza normalizzata
    for technique, count in technique_count.items():
        technique_frequencies[technique] = count / total_techniques

    return technique_frequencies

# Calcola le frequenze normalizzate delle tecniche
technique_frequencies = calculate_normalized_frequencies(technique_count)
print(technique_frequencies)

# Prepara i dati per il grafico
techniques = []
frequencies = []
colors = []
tactic_color_map = {tactic: plt.cm.get_cmap('tab20')(i / len(tactics_order)) for i, tactic in enumerate(tactics_order)}

for tactic in tactics_order:
    for technique in grouped_techniques.get(tactic, []):
        techniques.append(technique)
        frequencies.append(technique_frequencies.get(technique, 0))
        colors.append(tactic_color_map[tactic])

# Crea il grafico a barre orizzontali
plt.figure(figsize=(15, 10))
bars = plt.barh(techniques, frequencies, color=colors)

# Aggiungi una legenda per le Tactics
legend_elements = [Line2D([0], [0], color=tactic_color_map[tactic], lw=4, label=tactic) for tactic in tactics_order]
plt.legend(handles=legend_elements, title="Tactics", bbox_to_anchor=(1.05, 1), loc='upper left')

# Imposta etichette e titolo
plt.xlabel('Normalized Frequency')
plt.ylabel('Techniques')
plt.title('Distribution of Techniques within Ransomware by Tactic')

# Mostra il grafico
plt.show()
plt.savefig("Ransomware_hash_distribution.png")
plt.close()
