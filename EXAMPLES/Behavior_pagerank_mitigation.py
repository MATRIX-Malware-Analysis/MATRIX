from neo4j import GraphDatabase
import networkx as nx
import json

uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"

driver = GraphDatabase.driver(uri, auth=(user, password))

def extract_graph(tx):
    query = """
    MATCH (d:DataComponent)-[:detects]->(b:MalwareBehavior)  
    RETURN d.id AS data_component, b.id AS behavior_id, b.name AS behavior_name
    """
    result = tx.run(query)
    edges = []
    names = {}
    for record in result:
        edges.append((record["data_component"], record["behavior_id"]))
        #edges.append((record["behavior_id"], record["malware"]))
        names[record["behavior_id"]] = record["behavior_name"]
    return edges, names

with driver.session() as session:
    edges, behavior_names = session.read_transaction(extract_graph)

G = nx.DiGraph()
G.add_edges_from(edges)

# Calcola il PageRank
page_rank = nx.pagerank(G)

# Estrai solo i nodi di tipo MalwareBehavior
# Assumiamo che gli ID dei nodi di tipo MalwareBehavior contengano "malware-behavior"
malware_behavior_ranks = {behavior_names[node]: rank for node, rank in page_rank.items() if node in behavior_names}

# Ordina i MalwareBehavior per PageRank
sorted_behaviors = sorted(malware_behavior_ranks.items(), key=lambda item: item[1], reverse=True)

# Salva i risultati su un file JSON
output_file = "MalwareBehavior_PageRank_DataComponent.json"
with open(output_file, 'w', encoding='utf-8') as f:
    json.dump(sorted_behaviors, f, indent=4)

print(f"Results saved to {output_file}")

# Chiudi la connessione a Neo4j
driver.close()
