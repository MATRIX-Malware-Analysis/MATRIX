from neo4j import GraphDatabase
import networkx as nx
import json
import time
uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"

driver = GraphDatabase.driver(uri, auth=(user, password))
start_time = time.time()
def extract_graph(tx):
    query = """
    MATCH (m:Malware)-[:uses]->(b:Malware_Behavior)
    WHERE toLower(m.description) CONTAINS 'spy'
    RETURN m.name AS malware, b.name AS behavior, b.external_references_0 AS external_id
    """
    result = tx.run(query)
    edges = []
    names = {}
    for record in result:
        malware = record["malware"]
        print(f'Malware -> {malware}')
        behavior = record["behavior"]
        print(f'\nBehaviors -> {behavior}')
        technique_id = record["external_id"]
        try:
            technique_dict = eval(technique_id)
            external_id = technique_dict["external_id"]
            edges.append((malware, external_id))
            #edges.append((record["behavior_id"], record["malware"]))
            names[external_id] = behavior
        except Exception as e:
            print(e)
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
output_file = "MalwareBehavior_Spyware.json"
with open(output_file, 'w', encoding='utf-8') as f:
    json.dump(sorted_behaviors, f, indent=4)

print(f"Results saved to {output_file}")

end_time = time.time()

final_time = end_time - start_time

print(f'Final Time -> {final_time}')
# Chiudi la connessione a Neo4j
driver.close()
