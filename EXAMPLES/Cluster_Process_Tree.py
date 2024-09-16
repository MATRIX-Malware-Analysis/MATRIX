from elasticsearch import Elasticsearch
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
import json
from neo4j import GraphDatabase
from tqdm import tqdm

# Connessione a Elasticsearch
es = Elasticsearch(
    hosts=[{
        'host': 'localhost',
        'port': 9200,
        'scheme': 'http'
    }]
)

# Connessione a Neo4j
uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"

driver = GraphDatabase.driver(uri, auth=(user, password))

# Estrazione degli indicatori
def extract_indicators(tx):
    query = """
    MATCH (m:Malware)<-[:indicates]-(b:Indicator)
    WHERE toLower(m.description) CONTAINS 'ransomware'
    RETURN m.name AS malware, b.pattern AS PATTERN
    """
    result = tx.run(query)
    patterns = []
    for record in tqdm(result, desc="Retrieving Malware and Indicators ..."):
        pattern = record["PATTERN"]
        patterns.append(pattern)
    return patterns

with driver.session() as session:
    patterns = session.read_transaction(extract_indicators)

# Estrarre gli hash dai pattern
HASHES = [pattern.split('= ', 1)[1].replace(" ]", '').replace("'", "") for pattern in patterns]

# Query per ottenere i documenti con processes_tree
query = {
    "query": {
        "exists": {
            "field": "data.attributes.processes_tree"
        }
    },
    "_source": ["data.attributes.processes_tree", "data.id"]
}

# Esegui la query
response = es.search(index="malware_reports", body=query, size=10000)

# Estrazione e preparazione dei process tree
process_trees = []
hashes = []

for hit in response['hits']['hits']:
    data_list = hit['_source'].get('data', [])
    for data_item in data_list:
        attributes = data_item.get('id', "")
        id = attributes.split("_")[0]
        if id in HASHES:
            processes_tree = data_item.get('attributes', {}).get('processes_tree', [])
            if processes_tree:  # Aggiungi questo controllo
                hashes.append(id)
                # Converti il process tree in una stringa univoca
                process_tree_str = []
                def process_to_str(process):
                    if 'name' in process:
                        process_tree_str.append(process['name'])
                    if 'children' in process:
                        for child in process['children']:
                            process_to_str(child)
                for process in processes_tree:
                    process_to_str(process)
                process_trees.append(' '.join(process_tree_str))

# Debug: Stampa i process_trees e hashes per verifica
print(f"Process Trees: {process_trees}")
print(f"Hashes: {hashes}")

# Verifica se ci sono process_trees
if not process_trees:
    print("No process trees found.")
else:
    # Esegui la vectorizzazione TF-IDF
    vectorizer = TfidfVectorizer(stop_words='english')
    X = vectorizer.fit_transform(process_trees)

    # Clustering con KMeans
    num_clusters = 5  # Cambia il numero di cluster secondo necessità
    kmeans = KMeans(n_clusters=num_clusters, random_state=0).fit(X)

    # Recupera i nomi dei malware con gli hash
    def get_malware_name(tx, hash_value):
        query = """
        MATCH (m:Malware)<-[:indicates]-(b:Indicator)
        WHERE b.pattern CONTAINS $pattern
        RETURN m.name AS malware
        """
        pattern = f"[ file:hashes.'SHA-256' = '{hash_value}' ]"
        result = tx.run(query, pattern=pattern)
        record = result.single()
        if record:
            return record["malware"]
        return None

    # Stampa i risultati della clusterizzazione
    with open('Cluster_by_processes.txt', 'a') as f:
        for i in range(num_clusters):
            cluster_hashes = [hashes[j] for j in range(len(hashes)) if kmeans.labels_[j] == i]
            print(f"Cluster {i + 1}:")
            f.write(f"\n-----------------------------------\nCluster {i + 1}:\n")
            for hash_value in cluster_hashes:
                with driver.session() as session:
                    malware_name = session.read_transaction(get_malware_name, hash_value)
                    print(f"  - Hash: {hash_value}, Malware Name: {malware_name}")
                    f.write(f"  - Hash: {hash_value}, Malware Name: {malware_name}\n")
