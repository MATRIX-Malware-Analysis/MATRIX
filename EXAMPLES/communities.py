import networkx as nx
import matplotlib.pyplot as plt
from community import community_louvain
from neo4j import GraphDatabase

# Connessione a Neo4j
uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"

driver = GraphDatabase.driver(uri, auth=(user, password))

def extract_graph_by_label(tx, label):
    query = f"""
    MATCH (n:{label})-[r]->(m:{label})
    RETURN n.id AS source, m.id AS target
    """
    result = tx.run(query)
    edges = [(record["source"], record["target"]) for record in result]
    return edges

def detect_and_plot_communities(label, edges):
    G = nx.Graph()
    G.add_edges_from(edges)

    # Rilevazione delle comunità usando l'algoritmo di Louvain
    partition = community_louvain.best_partition(G)

    # Assegnazione del colore ai nodi in base alla comunità
    colors = [partition[node] for node in G.nodes()]

    # Visualizzazione del grafo con le comunità
    pos = nx.spring_layout(G)  # Layout del grafo
    plt.figure(figsize=(10, 10))
    nx.draw(G, pos, node_color=colors, with_labels=True, cmap=plt.cm.jet)
    plt.title(f"Communities in {label}")
    plt.show()

    # Salvataggio delle comunità in un file
    with open(f"communities_{label}.txt", "w") as f:
        for node, community in partition.items():
            f.write(f"{node}\t{community}\n")

with driver.session() as session:
    labels = ["MalwareObjective", "MalwareBehavior", "IntrusionSet"]
    for label in labels:
        edges = session.read_transaction(extract_graph_by_label, label)
        if edges:
            detect_and_plot_communities(label, edges)
