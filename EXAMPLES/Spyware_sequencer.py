from elasticsearch import Elasticsearch
from neo4j import GraphDatabase
from collections import defaultdict
import json
import networkx as nx
from tqdm import tqdm
import matplotlib.pyplot as plt

es = Elasticsearch(
    hosts=[{
        'host': 'localhost',
        'port': 9200,
        'scheme': 'http'
    }]
)

uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"
driver = GraphDatabase.driver(uri, auth=(user, password))

tactics_order = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact"
]

def extract_tactics(tx):
    query = """
    MATCH (b:MalwareBehavior)-[:related_to]->(i:MalwareObjective)
    RETURN b.external_references_0_external_id AS technique_id, i.name AS tactic_name
    """
    result = tx.run(query)
    technique_to_tactic = {}
    for record in result:
        technique_to_tactic[record["technique_id"]] = record["tactic_name"]
    return technique_to_tactic

def extract_indicators(tx):
    query = """
    MATCH (m:Malware)<-[:indicates]-(b:Indicator)
    WHERE toLower(m.description) CONTAINS 'spy'
    RETURN m.name AS malware, b.pattern AS PATTERN
    """
    result = tx.run(query)
    patterns = []
    for record in tqdm(result, desc="Retrieving Malware and Indicators ..."):
        pattern = record["PATTERN"]
        patterns.append(pattern)
    return patterns

with driver.session() as session:
    patterns = session.read_transaction(extract_indicators)

HASHES = [pattern.split('= ', 1)[1].replace(" ]", '').replace("'", "") for pattern in tqdm(patterns, desc='Extract Hashes ...')]

def group_techniques_by_tactic(techniques, technique_to_tactic):
    grouped_techniques = defaultdict(list)
    for technique in techniques:
        tactic = technique_to_tactic.get(technique)
        if tactic:
            grouped_techniques[tactic].append(technique)
    return grouped_techniques

def create_total_graph(grouped_techniques, G, tactics_order):
    for i in range(len(tactics_order)):
        current_tactic = tactics_order[i]
        current_level_techniques = grouped_techniques.get(current_tactic, [])
        
        for current_technique in current_level_techniques:
            G.add_node(current_technique, tactic=current_tactic)
        
        next_level_techniques = []
        next_tactic_index = i + 1
        
        while next_tactic_index < len(tactics_order) and not next_level_techniques:
            next_tactic = tactics_order[next_tactic_index]
            next_level_techniques = grouped_techniques.get(next_tactic, [])
            next_tactic_index += 1

        for current_technique in current_level_techniques:
            for next_technique in next_level_techniques:
                if G.has_edge(current_technique, next_technique):
                    G[current_technique][next_technique]['weight'] += 1
                else:
                    G.add_edge(current_technique, next_technique, weight=1)
G_total = nx.DiGraph()

with driver.session() as session:
    technique_to_tactic = session.read_transaction(extract_tactics)

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

response = es.search(index="malware_reports", body=query, size=10000)

for hit in response['hits']['hits']:
    techniques = []
    data_list = hit['_source'].get('data', [])
    for data_item in data_list:
        attributes = data_item.get('id', "")
        id = attributes.split("_")[0]
        if id in HASHES:
            mitre_techniques = data_item.get('attributes', {}).get('mitre_attack_techniques', [])
            techniques.extend([tech.get('id') for tech in mitre_techniques if tech.get('id')])

    grouped_techniques = group_techniques_by_tactic(techniques, technique_to_tactic)

    create_total_graph(grouped_techniques, G_total, tactics_order)

print("Spyware Graph nodes with tactics:")
for node, data in G_total.nodes(data=True):
    print(f"{node}: {data['tactic']}")

print("\n\nSpyware Graph edges with weights:")
for u, v, data in G_total.edges(data=True):
    print(f"{u} -> {v}: {data['weight']}")

graph_data = nx.node_link_data(G_total)
with open("Spyware_layered_graph.json", "w") as f:
    json.dump(graph_data, f, indent=4)

def hierarchical_layout(G, tactics_order):
    pos = {}
    layer_height = 1.0 / (len(tactics_order) + 1)
    
    for i, tactic in enumerate(tactics_order):
        layer_nodes = [node for node, data in G.nodes(data=True) if data['tactic'] == tactic]
        layer_pos = nx.shell_layout(G.subgraph(layer_nodes), scale=layer_height * (len(tactics_order) - i))
        
        for node, p in layer_pos.items():
            pos[node] = (p[0], layer_height * (len(tactics_order) - i))
    
    return pos

pos = hierarchical_layout(G_total, tactics_order)

plt.figure(figsize=(15, 15))
nx.draw(G_total, pos, with_labels=True, node_size=200, node_color="skyblue", font_size=10, font_weight="bold", edge_color="gray")
edge_labels = nx.get_edge_attributes(G_total, 'weight')
nx.draw_networkx_edge_labels(G_total, pos, edge_labels=edge_labels)

layer_height = 1.0 / (len(tactics_order) + 1)
for i, tactic in enumerate(tactics_order):
    y_position = layer_height * (len(tactics_order) - i)
    plt.text(-1.1, y_position, tactic, horizontalalignment='right', verticalalignment='center', fontsize=12, fontweight='bold')

plt.title("Spyware Technique Graph with Hierarchical Layout")
plt.savefig("Spyware_technique_graph_hierarchical_with_tactics.png")
plt.close()
