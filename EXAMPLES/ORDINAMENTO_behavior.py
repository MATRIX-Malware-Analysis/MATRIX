from neo4j import GraphDatabase
import networkx as nx
import json

# Connessione a Neo4j
uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"
driver = GraphDatabase.driver(uri, auth=(user, password))

def extract_techniques(tx):
    query = """
    MATCH (m:Malware)-[:uses]->(b:MalwareBehavior)
    RETURN b.external_references_0_external_id AS technique_id, b.name AS behavior_name
    """
    result = tx.run(query)
    techniques = []
    for record in result:
        techniques.append((record["technique_id"], record["behavior_name"]))
    return techniques

with driver.session() as session:
    techniques = session.read_transaction(extract_techniques)

# Costruisci il grafo delle tecniche basato sulle relazioni estratte
G = nx.DiGraph()
from tqdm import tqdm 
# Aggiungi nodi e archi al grafo
for technique_id, behavior_name in tqdm(techniques, desc='Building Graph ...'):
    G.add_node(technique_id)
    G.add_node(behavior_name)
    G.add_edge(technique_id, behavior_name)

# Funzione per rimuovere i cicli dal grafo
def remove_cycles(G):
    cycles = list(nx.simple_cycles(G))
    while cycles:
        for cycle in tqdm(cycles, desc=f'Removing cycles ...'):
            G.remove_edge(cycle[0], cycle[1])
        cycles = list(nx.simple_cycles(G))
    return G

# Rimuovi i cicli dal grafo
print('Removing cycles ...')
G_no_cycles = remove_cycles(G.copy())

# Ottieni l'ordine delle tecniche tramite l'ordinamento topologico
ordered_techniques = list(nx.topological_sort(G_no_cycles))

# Stampa e salva l'ordine delle tecniche
print("Ordered Techniques:")
print(ordered_techniques)

with open("ordered_behaviors_no_cycles.json", "w") as f:
    json.dump(ordered_techniques, f, indent=4)
