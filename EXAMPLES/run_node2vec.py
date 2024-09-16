from neo4j import GraphDatabase
import networkx as nx
from node2vec import Node2Vec
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import classification_report
import numpy as np
from tqdm import tqdm
import json
import itertools
import csv

uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"

driver = GraphDatabase.driver(uri, auth=(user, password))

def extract_graph(tx):
    query = """
    MATCH (m:Malware)-[:uses]->(b:MalwareBehavior)
    RETURN m.name AS malware, b.name AS behavior
    """
    result = tx.run(query)
    edges = []
    labels = {}
    malware_behaviors = {}
    for record in result:
        edges.append((record["malware"], record["behavior"]))
        if record["malware"] not in malware_behaviors:
            malware_behaviors[record["malware"]] = []
        malware_behaviors[record["malware"]].append(record["behavior"])
    return edges, malware_behaviors

with driver.session() as session:
    edges, malware_behaviors = session.read_transaction(extract_graph)

G = nx.Graph()
G.add_edges_from(edges)

node2vec = Node2Vec(G, dimensions=64, walk_length=30, num_walks=200, workers=4)
print("[!] Node2Vec model fitting ...")
model = node2vec.fit(window=10, min_count=1, batch_words=4)

X = []
y = []
for malware, behaviors in tqdm(malware_behaviors.items(), desc='Building Dataset ...'):
    if len(behaviors) >= 3:
        combinations = list(itertools.combinations(behaviors, 3))
        for combo in combinations:
            combo_embeddings = [model.wv[behavior] for behavior in combo if behavior in model.wv]
            if len(combo_embeddings) == 3:  # Assicurarsi di avere embedding per tutti e 3 i comportamenti
                avg_embedding = np.mean(combo_embeddings, axis=0)
                X.append(avg_embedding)
                y.append(malware)

X = np.array(X)
y = np.array(y)

dataset_file = "malware_dataset.csv"
with open(dataset_file, 'w', newline='') as csvfile:
    csvwriter = csv.writer(csvfile)
    csvwriter.writerow(['Malware'] + [f'Feature_{i}' for i in range(X.shape[1])])
    for i in range(X.shape[0]):
        csvwriter.writerow([y[i]] + list(X[i]))

print(f"Dataset saved to {dataset_file}")

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

models = {
    "RandomForest": RandomForestClassifier(n_estimators=100, random_state=42),
    "SVM": SVC(probability=True, random_state=42),
    "KNeighbors": KNeighborsClassifier(),
    "GradientBoosting": GradientBoostingClassifier(n_estimators=100, random_state=42)
}

for model_name, model in tqdm(models.items()):
    print(f"Training {model_name}...")
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    print(f"Classification Report for {model_name}:")
    print(classification_report(y_test, y_pred))

behaviors_input = []
for malware, behaviors in malware_behaviors.items():
    if len(behaviors) >= 3:
        behaviors_input.append(behaviors[:3])

with open("behaviors_input.json", 'w') as f:
    json.dump(behaviors_input, f, indent=4)

def predict_malware(model, behaviors):
    behavior_embeddings = []
    for behavior in behaviors:
        if behavior in model.wv:
            behavior_embeddings.append(model.wv[behavior])
    if not behavior_embeddings:
        print("No valid behaviors found.")
        return
    avg_embedding = np.mean(behavior_embeddings, axis=0).reshape(1, -1)
    probabilities = model.predict_proba(avg_embedding)[0]
    top_malware_indices = np.argsort(probabilities)[::-1][:3]
    top_malware = [(model.classes_[i], probabilities[i]) for i in top_malware_indices]
    return top_malware

input_file = "behaviors_input.json"
with open(input_file, 'r') as f:
    behaviors_list = json.load(f)

for model_name, model in models.items():
    print(f"\nPredictions using {model_name}:")
    for behaviors in behaviors_list:
        top_malware = predict_malware(model, behaviors)
        print(f"For behaviors {behaviors}, top malware predictions are:")
        for malware, prob in top_malware:
            print(f"  - {malware}: {prob:.4f}")

driver.close()
