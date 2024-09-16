from elasticsearch import Elasticsearch
from collections import defaultdict, Counter
import json
import networkx as nx
from tqdm import tqdm

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
    "_source": ["data.id", "data.attributes.mitre_attack_techniques.id"],
    #"size": 100  # Dimensione della pagina
}

# Funzione per ottenere documenti con paginazione
def get_documents(es, index, query):
    documents = []
    response = es.search(index=index, body=query, scroll='2m')
    scroll_id = response['_scroll_id']
    scroll_size = len(response['hits']['hits'])
    while scroll_size > 0:
        documents.extend(response['hits']['hits'])
        response = es.scroll(scroll_id=scroll_id, scroll='2m')
        scroll_id = response['_scroll_id']
        scroll_size = len(response['hits']['hits'])
    return documents

# Esegui la query con paginazione
index_name = "malware_reports"
documents = get_documents(es, index_name, query)

# Raccogliere le tecniche MITRE dai report
technique_sequences = []

for hit in documents:
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

for tech_a, neighbors in tqdm(co_occurrence_matrix.items(), desc="[+] Building graph from techniques ..."):
    for tech_b, weight in neighbors.items():
        if weight > 0:  # Considera solo le co-occorrenze positive
            G.add_edge(tech_a, tech_b, weight=weight)

# Funzione per calcolare la probabilità dei percorsi da una tecnica di partenza con un limite di profondità
def calculate_path_probabilities(G, start_technique, max_depth=5):
    paths = []
    stack = [(start_technique, [start_technique], 1.0)]
    
    while stack:
        (node, path, prob) = stack.pop()
        
        if len(path) > max_depth:
            continue  # Ignora i percorsi che superano il limite di profondità
        
        extended = False
        neighbors = sorted(G[node], key=lambda x: G[node][x]['weight'], reverse=True)
        
        for neighbor in neighbors:
            if neighbor in path:
                continue  # Evita i cicli
            edge_weight = G[node][neighbor]['weight']
            if edge_weight < 0.1:
                continue  # Ignora i vicini con peso inferiore alla soglia
            new_prob = prob * edge_weight
            stack.append((neighbor, path + [neighbor], new_prob))
            extended = True
        
        if not extended:
            paths.append((path, prob))
    
    # Calcola le percentuali per ciascun passaggio nel path
    path_with_percentages = []
    for path, total_prob in paths:
        path_probabilities = []
        cumulative_prob = 1.0
        for i in range(len(path) - 1):
            step_prob = G[path[i]][path[i + 1]]['weight'] / total_prob
            cumulative_prob *= step_prob
            path_probabilities.append((path[i], path[i + 1], step_prob))
        path_with_percentages.append((path, path_probabilities, cumulative_prob))
    
    path_with_percentages = sorted(path_with_percentages, key=lambda x: x[2], reverse=True)
    return path_with_percentages

# Identifica le tecniche di partenza più probabili
technique_start_probabilities = Counter()
for sequence in technique_sequences:
    if sequence:
        technique_start_probabilities[sequence[0]] += 1

total_sequences = sum(technique_start_probabilities.values())
technique_start_probabilities = {tech: count / total_sequences for tech, count in technique_start_probabilities.items()}

# Stampa le tecniche di partenza più probabili
print("Most probable starting techniques:")
print(json.dumps(technique_start_probabilities, indent=4))

# Calcola e stampa le probabilità dei percorsi per i tre punti di partenza più probabili
top_3_starting_points = [tech for tech, _ in sorted(technique_start_probabilities.items(), key=lambda item: item[1], reverse=True)[:3]]

all_paths_probabilities = {}

for start_technique in top_3_starting_points:
    print(f'Calculating Path probabilities for {start_technique} ...')
    path_probabilities = calculate_path_probabilities(G, start_technique, max_depth=20)
    top_3_paths = path_probabilities[:3]
    all_paths_probabilities[start_technique] = top_3_paths

# Stampa le probabilità dei percorsi per i top 3 starting points
print(f"Path probabilities for top 3 starting points:")
print(json.dumps(all_paths_probabilities, indent=4))

# Salva i risultati in un file JSON
with open("top3_path_probabilities.json", "w") as f:
    json.dump(all_paths_probabilities, f, indent=4)
