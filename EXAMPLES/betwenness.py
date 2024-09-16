import networkx as nx
from neo4j import GraphDatabase
import json
import time
# Connessione al database Neo4j
uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"

driver = GraphDatabase.driver(uri, auth=(user, password))
start_time = time.time()
# Funzione per estrarre i dati da Neo4j per una specifica categoria di malware
def extract_graph(tx, malware_type):
    # Query per ottenere i malware e i loro comportamenti associati
    query = """
    MATCH (m:Malware)-[:uses]->(b:Malware_Behavior)
    WHERE toLower(m.description) CONTAINS $malware_type
    RETURN m.name AS malware, b.name AS behavior, b.external_references_0 AS external_id
    """
    result = tx.run(query, malware_type=malware_type.lower())
    edges = []
    names = {}
    
    for record in result:
        malware = record["malware"]
        behavior = record["behavior"]
        external_id = record["external_id"]
        
        try:
            technique_dict = eval(external_id)
            external_id = technique_dict["external_id"]
            # Aggiungi l'arco tra malware e comportamento
            edges.append((malware, external_id))
            names[external_id] = behavior  # Associa il nome del comportamento all'ID esterno
        except Exception as e:
            print(f"Errore nel parsing dell'ID esterno: {e}")
    
    return edges, names

# Funzione per costruire il grafo per una categoria specifica
def build_graph(malware_type):
    with driver.session() as session:
        edges, behavior_names = session.read_transaction(extract_graph, malware_type)
    
    # Crea un grafo non orientato
    G = nx.Graph()
    G.add_edges_from(edges)
    
    return G, behavior_names

# Funzione per calcolare la Betweenness Centrality tra categorie di malware
def calculate_betweenness_between_categories(graph, malware_categories):
    # Calcola la betweenness centrality di ogni nodo nel grafo
    betweenness = nx.betweenness_centrality(graph)
    
    # Trova i comportamenti che collegano malware appartenenti a categorie diverse
    category_pairs = {}
    for malware1 in malware_categories:
        for malware2 in malware_categories:
            if malware1 != malware2:
                category1 = malware_categories[malware1]
                category2 = malware_categories[malware2]
                if category1 != category2:  # Solo malware di categorie diverse
                    try:
                        # Prova a trovare il percorso più corto tra malware1 e malware2
                        paths = nx.shortest_path(graph, source=malware1, target=malware2)
                        for node in paths:
                            # Verifica se il nodo è un comportamento e non un malware
                            if node in betweenness and node not in malware_categories:
                                pair = tuple(sorted([category1, category2]))
                                if pair not in category_pairs:
                                    category_pairs[pair] = []
                                category_pairs[pair].append(node)
                    except nx.NetworkXNoPath:
                        # Se non esiste un percorso tra malware1 e malware2, ignora
                        continue
    
    # Calcola la centralità solo per i comportamenti che connettono categorie diverse
    filtered_betweenness = {}
    for pair, behaviors in category_pairs.items():
        filtered_betweenness[pair] = {}
        for behavior in behaviors:
            if behavior in betweenness:
                if behavior not in filtered_betweenness[pair]:
                    filtered_betweenness[pair][behavior] = 0
                filtered_betweenness[pair][behavior] += betweenness[behavior]
    
    # Restituisci i comportamenti con betweenness maggiore per ogni coppia di categorie
    return filtered_betweenness

# Funzione principale
def main():
    malware_types = ["ransomware", "spyware", "backdoor", "rat", "worm"]
    
    # Dizionario per memorizzare i grafi e le categorie di malware
    category_graphs = {}
    malware_categories = {}
    
    # Costruisci un grafo per ogni categoria di malware
    for malware_type in malware_types:
        print(f"Costruzione del grafo per: {malware_type}")
        G, behavior_names = build_graph(malware_type)
        category_graphs[malware_type] = G
        
        # Associa i malware alla loro categoria
        for node in G.nodes():
            if node not in behavior_names:
                malware_categories[node] = malware_type
    
    # Combina i grafi in un unico grafo globale
    combined_graph = nx.Graph()
    
    for G in category_graphs.values():
        combined_graph.add_edges_from(G.edges())
    
    # Calcola la Betweenness Centrality per i comportamenti che fungono da connettori tra categorie
    behavior_betweenness = calculate_betweenness_between_categories(combined_graph, malware_categories)
    
    # Organizza i risultati in un unico dizionario per salvarli in un file JSON
    result = {}
    for pair, betweenness in behavior_betweenness.items():
        # Ordina per betweenness centrality in ordine decrescente e prendi solo i primi 30
        sorted_betweenness = sorted(betweenness.items(), key=lambda x: x[1], reverse=True)[:10]
        result[f"{pair[0]}_{pair[1]}"] = sorted_betweenness
    
    # Salva i risultati in un file JSON unico
    output_file = "top10_betweenness_behaviors_by_category.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=4)
    
    print(f"Risultati salvati in '{output_file}'.")

# Esegui lo script
if __name__ == "__main__":
    main()

# Chiudi la connessione a Neo4j
end_time = time.time()
final_time = end_time - start_time
print(f'Final Time -> {final_time}')
driver.close()
