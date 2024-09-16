from elasticsearch import Elasticsearch
from collections import defaultdict, Counter
import json
import networkx as nx
from tqdm import tqdm

es = Elasticsearch(
    hosts=[{
        'host': 'localhost',
        'port': 9200,
        'scheme': 'http'
    }]
)

query = {
    "query": {
        "exists": {"field": "data.attributes.mitre_attack_techniques.id"}
    },
    "_source": ["data.id", "data.attributes.mitre_attack_techniques.id"],
}

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

index_name = "malware_reports"
documents = get_documents(es, index_name, query)

technique_sequences = []

for hit in documents:
    data_list = hit['_source'].get('data', [])
    for data_item in data_list:
        techniques = data_item.get('attributes', {}).get('mitre_attack_techniques', [])
        technique_sequence = [technique.get('id') for technique in techniques if technique.get('id')]
        if technique_sequence:
            technique_sequences.append(technique_sequence)

with open("technique_sequences.json", "w") as f:
    json.dump(technique_sequences, f, indent=4)

with open("technique_sequences.json", "r") as f:
    technique_sequences = json.load(f)

co_occurrence_matrix = defaultdict(lambda: defaultdict(int))

for sequence in technique_sequences:
    for i in range(len(sequence)):
        for j in range(i + 1, len(sequence)):
            co_occurrence_matrix[sequence[i]][sequence[j]] += 1
            co_occurrence_matrix[sequence[j]][sequence[i]] += 1

with open("co_occurrence_matrix.json", "w") as f:
    json.dump(co_occurrence_matrix, f, indent=4)

G = nx.DiGraph()

for tech_a, neighbors in tqdm(co_occurrence_matrix.items(), desc="[+] Building graph from techniques ..."):
    for tech_b, weight in neighbors.items():
        if weight > 0:  # Considera solo le co-occorrenze positive
            G.add_edge(tech_a, tech_b, weight=weight)

def calculate_path_probabilities(G, start_technique, max_depth=4):
    paths = []
    stack = [(start_technique, [start_technique], 1.0)]
    
    while stack:
        (node, path, prob) = stack.pop()
        if len(path) > max_depth:
            continue
        
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
    
    paths = sorted(paths, key=lambda x: x[1], reverse=True)
    return paths

technique_start_probabilities = Counter()
for sequence in technique_sequences:
    if sequence:
        technique_start_probabilities[sequence[0]] += 1

total_sequences = sum(technique_start_probabilities.values())
technique_start_probabilities = {tech: count / total_sequences for tech, count in technique_start_probabilities.items()}

print("Most probable starting techniques:")
print(json.dumps(technique_start_probabilities, indent=4))

top_3_starting_points = [tech for tech, _ in sorted(technique_start_probabilities.items(), key=lambda item: item[1], reverse=True)[:3]]

all_paths_probabilities = {}

for start_technique in top_3_starting_points:
    path_probabilities = calculate_path_probabilities(G, start_technique)
    top_3_paths = path_probabilities[:3]
    all_paths_probabilities[start_technique] = top_3_paths

print(f"Path probabilities for top 3 starting points:")
print(json.dumps(all_paths_probabilities, indent=4))

with open("top3_path_probabilities.json", "w") as f:
    json.dump(all_paths_probabilities, f, indent=4)
