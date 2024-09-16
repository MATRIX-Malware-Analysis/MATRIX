import networkx as nx
import json
import matplotlib.pyplot as plt

CATEGORY = input('Choose the catogory among Ransomware and Spyware :')
# Funzione per caricare i grafi da file JSON
def load_graph(filename):
    with open(filename, 'r') as f:
        data = json.load(f)
    return nx.node_link_graph(data)

# Carica i due grafi
G1 = load_graph(f"{CATEGORY}_layered_graph.json")
G2 = load_graph(f"{CATEGORY}_MITRE_layered_graph.json")

# Analisi della distribuzione dei gradi
def degree_distribution(G, graph_name):
    degrees = [G.degree(n) for n in G.nodes()]
    plt.hist(degrees, bins=20, alpha=0.7, label=f'Degree Distribution of {graph_name}')
    plt.xlabel('Degree')
    plt.ylabel('Frequency')
    plt.title(f'Degree Distribution - {graph_name}')
    plt.legend()
    plt.savefig(f'{graph_name}_{CATEGORY}_degree_distribution.png')
    plt.close()

# Analisi delle centralità
def centrality_analysis(G):
    degree_centrality = nx.degree_centrality(G)
    closeness_centrality = nx.closeness_centrality(G)
    betweenness_centrality = nx.betweenness_centrality(G)
    
    return degree_centrality, closeness_centrality, betweenness_centrality

# Analisi dell'efficienza della rete su grafi diretti
def directed_network_efficiency(G):
    # Converte il grafo diretto in un grafo non diretto
    G_undirected = G.to_undirected()
    return nx.global_efficiency(G_undirected)

# Analisi della connettività
def connectivity_analysis(G):
    strongly_connected = list(nx.strongly_connected_components(G))
    weakly_connected = list(nx.weakly_connected_components(G))
    return strongly_connected, weakly_connected

# Esegui le analisi per G1 e G2
print("Degree Distribution Analysis:")
degree_distribution(G1, "G1")
degree_distribution(G2, "G2")

print("\nCentrality Analysis:")
G1_centrality = centrality_analysis(G1)
G2_centrality = centrality_analysis(G2)

print("\nNetwork Efficiency:")
G1_efficiency = directed_network_efficiency(G1)
G2_efficiency = directed_network_efficiency(G2)
print(f"Efficiency of G1: {G1_efficiency}")
print(f"Efficiency of G2: {G2_efficiency}")

print("\nConnectivity Analysis:")
G1_strongly_connected, G1_weakly_connected = connectivity_analysis(G1)
G2_strongly_connected, G2_weakly_connected = connectivity_analysis(G2)
print(f"G1 Strongly Connected Components: {len(G1_strongly_connected)}")
print(f"G1 Weakly Connected Components: {len(G1_weakly_connected)}")
print(f"G2 Strongly Connected Components: {len(G2_strongly_connected)}")
print(f"G2 Weakly Connected Components: {len(G2_weakly_connected)}")

# Visualizza i risultati delle centralità
def plot_centrality(centrality, title, filename):
    plt.figure(figsize=(10, 6))
    plt.bar(range(len(centrality)), list(centrality.values()), align='center')
    plt.xticks(range(len(centrality)), list(centrality.keys()), rotation='vertical')
    plt.title(title)
    plt.savefig(filename)
    plt.close()

print("\nPlotting Centrality Distributions:")
plot_centrality(G1_centrality[0], 'Degree Centrality of G1', f'G1_{CATEGORY}_degree_centrality.png')
plot_centrality(G2_centrality[0], 'Degree Centrality of G2', f'G2_{CATEGORY}_degree_centrality.png')
plot_centrality(G1_centrality[1], 'Closeness Centrality of G1', f'G1_{CATEGORY}_closeness_centrality.png')
plot_centrality(G2_centrality[1], 'Closeness Centrality of G2', f'G2_{CATEGORY}_closeness_centrality.png')
plot_centrality(G1_centrality[2], 'Betweenness Centrality of G1', f'G1_{CATEGORY}_betweenness_centrality.png')
plot_centrality(G2_centrality[2], 'Betweenness Centrality of G2', f'G2_{CATEGORY}_betweenness_centrality.png')
