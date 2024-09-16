from neo4j import GraphDatabase
from collections import defaultdict
import json
import networkx as nx

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

G = nx.DiGraph()
G.add_edges_from(edges)

pagerank = nx.pagerank(G)

malware_behavior_importance = defaultdict(dict)

for malware, behavior in edges:
    if behavior in pagerank:
        malware_behavior_importance[malware][behavior] = pagerank[behavior]

malware_data = []
for malware, behaviors in malware_behavior_importance.items():
    behavior_list = [{"behavior": behavior, "importance": importance} for behavior, importance in behaviors.items()]
    malware_data.append({"malware": malware, "behaviors": behavior_list})

output_file = "malware_behavior_importance_pagerank.json"
with open(output_file, 'w', encoding='utf-8') as f:
    json.dump(malware_data, f, indent=4)

print(f"Results saved to {output_file}")

driver.close()
