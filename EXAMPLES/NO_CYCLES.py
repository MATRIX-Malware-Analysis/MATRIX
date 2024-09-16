from elasticsearch import Elasticsearch
from collections import defaultdict, Counter
import json
import networkx as nx

# Connessione a Elasticsearch
es = Elasticsearch(
    hosts=[{
        'host': 'localhost',
        'port': 9200,
        'scheme': 'http'
    }]
)

# Query per ottenere documenti con tecniche MITRE ATT&CK
query = {
    "query": {
        "exists": {"field": "data.attributes.mitre_attack_techniques.id"}
    },
    "_source": ["data.id", "data.attributes.mitre_attack_techniques.id"]
}

# Esegui la query
response = es.search(index="malware_reports", body=query, size=10000)

# Raccogliere le tecniche MITRE dai report
technique_sequences = []

for hit in response['hits']['hits']:
    data_list = hit['_source'].get('data', [])
    for data_item in data_list:
        techniques = data_item.get('attributes', {}).get('mitre_attack_techniques', [])
        technique_sequence = [technique.get('id') for technique in techniques if technique.get('id')]
        if technique_sequence:
            technique_sequences.append(technique_sequence)

# Salva le sequenze in un file JSON per ulteriori analisi
with open("technique_sequences.json", "w") as f:
    json.dump(technique_sequences, f, indent=4)

# Carica le sequenze salvate
with open("technique_sequences.json", "r") as f:
    technique_sequences = json.load(f)

# Costruisci la matrice di co-occorrenza
co_occurrence_matrix = defaultdict(lambda: defaultdict(int))

for sequence in technique_sequences:
    for i in range(len(sequence)):
        for j in range(i + 1, len(sequence)):
            co_occurrence_matrix[sequence[i]][sequence[j]] += 1
            co_occurrence_matrix[sequence[j]][sequence[i]] += 1

# Salva la matrice di co-occorrenza in un file JSON
with open("co_occurrence_matrix.json", "w") as f:
    json.dump(co_occurrence_matrix, f, indent=4)

# Crea un grafo delle tecniche basato sulla matrice di co-occorrenza
G = nx.DiGraph()

for tech_a, neighbors in co_occurrence_matrix.items():
    for tech_b, weight in neighbors.items():
        if weight > 0:  # Considera solo le co-occorrenze positive
            G.add_edge(tech_a, tech_b, weight=weight)

# Funzione per rimuovere i cicli dal grafo
def remove_cycles(G):
    cycles = list(nx.simple_cycles(G))
    while cycles:
        for cycle in cycles:
            G.remove_edge(cycle[0], cycle[1])
        cycles = list(nx.simple_cycles(G))
    return G

# Rimuovi i cicli dal grafo
G_no_cycles = remove_cycles(G.copy())

# Ottieni l'ordine delle tecniche tramite l'ordinamento topologico
ordered_techniques = list(nx.topological_sort(G_no_cycles))

# Stampa e salva l'ordine delle tecniche
print("Ordered Techniques:")
print(ordered_techniques)

with open("ordered_techniques_no_cycles.json", "w") as f:
    json.dump(ordered_techniques, f, indent=4)
