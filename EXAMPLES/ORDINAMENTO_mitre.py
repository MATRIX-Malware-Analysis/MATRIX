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

def remove_cycles(G):
    try:
        cycles = list(nx.find_cycle(G, orientation='original'))
        while cycles:
            for cycle in tqdm(cycles, desc='Removing cycles ...'):
                if len(cycle) > 1:
                    print((cycle[0], cycle[1]))
                    G.remove_edge(cycle[0], cycle[1])
                else:
                    G.remove_edge(cycle[0], cycle[1])
            cycles = list(nx.find_cycle(G, orientation='original'))
    except nx.NetworkXNoCycle:
        pass
    return G

print("[!] Removing cycles ...")
G_no_cycles = remove_cycles(G)

ordered_techniques = list(nx.topological_sort(G_no_cycles))

print("Ordered Techniques:")
print(ordered_techniques)

with open("ordered_techniques.json", "w") as f:
    json.dump(ordered_techniques, f, indent=4)
