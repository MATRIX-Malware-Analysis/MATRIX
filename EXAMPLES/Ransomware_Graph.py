from elasticsearch import Elasticsearch
from neo4j import GraphDatabase
import networkx as nx
import matplotlib.pyplot as plt
from tqdm import tqdm
from collections import Counter

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

def extract_indicators(tx):
    query = """
    MATCH (m:Malware)<-[:indicates]-(b:Indicator)
    WHERE toLower(m.description) CONTAINS 'ransomware'
    RETURN m.name AS malware, b.pattern AS pattern
    """
    result = tx.run(query)
    indicators = []
    for record in tqdm(result, desc="Retrieving Malware and Indicators ..."):
        indicators.append(record)
    return indicators

with driver.session() as session:
    indicators = session.read_transaction(extract_indicators)

hashes_to_malware = {record["pattern"].split('= ', 1)[1].replace(" ]", '').replace("'", ""): record["malware"] for record in indicators}
hashes = list(hashes_to_malware.keys())

query = {
    "query": {
        "match_all": {}
    },
    "_source": ["data.id", "data.attributes.processes_tree"]
}
response = es.search(index="malware_reports", body=query, size=10000)

processes = []
for hit in response['hits']['hits']:
    data_list = hit['_source'].get('data', [])
    for data_item in data_list:
        hash_value = data_item.get('id', "").split("_")[0]
        if hash_value in hashes:
            processes_tree = data_item.get('attributes', {}).get('processes_tree', [])
            processes.append(processes_tree)

process_counter = Counter()
relation_counter = Counter()
total_trees = len(processes)

def count_process_and_relations(process, parent=None):
    if 'name' in process:
        process_name = process['name'].replace("\\", "\\\\").replace("\"", "\\\"")
        process_counter[process_name] += 1
        if parent:
            parent_name = parent.replace("\\", "\\\\").replace("\"", "\\\"")
            relation_counter[(parent_name, process_name)] += 1
    if 'children' in process:
        for child in process['children']:
            count_process_and_relations(child, process['name'])

for processes_tree in processes:
    for process in processes_tree:
        count_process_and_relations(process)

threshold = 0.01
filtered_processes = {p for p, count in process_counter.items() if count / total_trees >= threshold}
filtered_relations = {r for r, count in relation_counter.items() if count / total_trees >= threshold}

G = nx.DiGraph()

for process in filtered_processes:
    G.add_node(process)

for parent, child in filtered_relations:
    if parent in filtered_processes and child in filtered_processes:
        G.add_edge(parent, child)

pos = nx.spring_layout(G)
plt.figure(figsize=(15, 10))
nx.draw(G, pos, with_labels=True, node_size=3000, node_color="lightblue", font_size=10, font_weight="bold", arrows=True, arrowstyle="->", arrowsize=20)
plt.title("Most Probable Process Tree Graph for Maze Ransomware")
plt.savefig("ransomware_process_tree_graph.png")
plt.show()

nx.write_graphml(G, "ransomware_process_tree_graph.graphml")
