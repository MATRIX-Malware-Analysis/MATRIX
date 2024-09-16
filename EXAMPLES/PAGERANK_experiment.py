from neo4j import GraphDatabase
from collections import defaultdict
import json
import networkx as nx

# Connessione a Neo4j
uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"

driver = GraphDatabase.driver(uri, auth=(user, password))

def extract_data(tx):
    query = """
    MATCH (m:Malware)-[:uses]->(b:MalwareBehavior)
    RETURN m.name AS malware, b.name AS behavior
    """
    result = tx.run(query)
    edges = []
    for record in result:
        malware = record["malware"]
        behavior = record["behavior"]
        edges.append((malware, behavior))
    
    return edges

with driver.session() as session:
    edges = session.read_transaction(extract_data)

# Creazione del grafo
G = nx.DiGraph()
G.add_edges_from(edges)

# Calcolo del PageRank
pagerank = nx.pagerank(G)

# Creazione del dataset JSON
malware_behavior_importance = defaultdict(dict)

# Associa ogni MalwareBehavior ai malware corrispondenti
for malware, behavior in edges:
    if behavior in pagerank:
        malware_behavior_importance[malware][behavior] = pagerank[behavior]

#print(malware_behavior_importance)
malware_data = []
for malware, behaviors in malware_behavior_importance.items():
    behavior_list = [{"behavior": behavior, "importance": importance} for behavior, importance in behaviors.items()]
    malware_data.append({"malware": malware, "behaviors": behavior_list})

#print(malware_data)
output_file = "malware_behavior_importance_pagerank.json"
with open(output_file, 'w', encoding='utf-8') as f:
    json.dump(malware_data, f, indent=4)

print(f"Results saved to {output_file}")

# Chiusura della connessione a Neo4j
driver.close()
