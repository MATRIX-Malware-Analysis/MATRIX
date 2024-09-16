import networkx as nx
from neo4j import GraphDatabase
import json
import time
uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"

driver = GraphDatabase.driver(uri, auth=(user, password))
start_time = time.time()
def extract_graph(tx, malware_type):
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
            edges.append((malware, external_id))
            names[external_id] = behavior  # Associa il nome del comportamento all'ID esterno
        except Exception as e:
            print(f"Errore nel parsing dell'ID esterno: {e}")
    
    return edges, names

def build_graph(malware_type):
    with driver.session() as session:
        edges, behavior_names = session.read_transaction(extract_graph, malware_type)
    
    G = nx.Graph()
    G.add_edges_from(edges)
    
    return G, behavior_names

def calculate_betweenness_between_categories(graph, malware_categories):
    betweenness = nx.betweenness_centrality(graph)
    
    category_pairs = {}
    for malware1 in malware_categories:
        for malware2 in malware_categories:
            if malware1 != malware2:
                category1 = malware_categories[malware1]
                category2 = malware_categories[malware2]
                if category1 != category2:  # Solo malware di categorie diverse
                    try:
                        paths = nx.shortest_path(graph, source=malware1, target=malware2)
                        for node in paths:
                            if node in betweenness and node not in malware_categories:
                                pair = tuple(sorted([category1, category2]))
                                if pair not in category_pairs:
                                    category_pairs[pair] = []
                                category_pairs[pair].append(node)
                    except nx.NetworkXNoPath:
                        continue
    
    filtered_betweenness = {}
    for pair, behaviors in category_pairs.items():
        filtered_betweenness[pair] = {}
        for behavior in behaviors:
            if behavior in betweenness:
                if behavior not in filtered_betweenness[pair]:
                    filtered_betweenness[pair][behavior] = 0
                filtered_betweenness[pair][behavior] += betweenness[behavior]
    
    return filtered_betweenness

def main():
    malware_types = ["ransomware", "spyware", "backdoor", "rat", "worm"]
    
    category_graphs = {}
    malware_categories = {}
    
    for malware_type in malware_types:
        print(f"Costruzione del grafo per: {malware_type}")
        G, behavior_names = build_graph(malware_type)
        category_graphs[malware_type] = G
        
        for node in G.nodes():
            if node not in behavior_names:
                malware_categories[node] = malware_type
    
    combined_graph = nx.Graph()
    
    for G in category_graphs.values():
        combined_graph.add_edges_from(G.edges())
    
    behavior_betweenness = calculate_betweenness_between_categories(combined_graph, malware_categories)
    
    result = {}
    for pair, betweenness in behavior_betweenness.items():
        sorted_betweenness = sorted(betweenness.items(), key=lambda x: x[1], reverse=True)[:10]
        result[f"{pair[0]}_{pair[1]}"] = sorted_betweenness
    
    output_file = "top10_betweenness_behaviors_by_category.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=4)
    
    print(f"Risultati salvati in '{output_file}'.")

if __name__ == "__main__":
    main()

end_time = time.time()
final_time = end_time - start_time
print(f'Final Time -> {final_time}')
driver.close()
