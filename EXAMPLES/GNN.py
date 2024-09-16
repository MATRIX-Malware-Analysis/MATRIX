import torch
import torch.nn.functional as F
from torch_geometric.nn import GCNConv
from torch_geometric.data import Data
from neo4j import GraphDatabase
import pandas as pd
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

# Step 1: Connettersi a Neo4j ed estrarre i dati

uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"

driver = GraphDatabase.driver(uri, auth=(user, password))

def extract_data(tx):
    query = """
    MATCH (m:Malware)-[:uses]->(b:MalwareBehavior)
    RETURN m.name AS malware, b.name AS behavior
    """
    result = tx.run(query)
    edges = []
    malwares = set()
    behaviors = set()
    for record in result:
        malware = record["malware"]
        behavior = record["behavior"]
        edges.append((malware, behavior))
        malwares.add(malware)
        behaviors.add(behavior)
    return edges, list(malwares), list(behaviors)

with driver.session() as session:
    edges, malwares, behaviors = session.execute_read(extract_data)

# Step 2: Preprocessare i dati
# Creiamo un mapping per i nodi (malware e behaviors) e creiamo le feature dei nodi

node_mapping = {name: i for i, name in enumerate(malwares + behaviors)}
reverse_node_mapping = {i: name for name, i in node_mapping.items()}
num_nodes = len(node_mapping)
node_features = torch.eye(num_nodes)  # One-hot encoding per semplicità

edge_index = torch.tensor([[node_mapping[m], node_mapping[b]] for m, b in edges], dtype=torch.long).t().contiguous()

# Definiamo una matrice di label per i nodi malware (ad esempio, 1 per malware, 0 per behavior)
labels = torch.zeros(num_nodes, dtype=torch.long)
for malware in malwares:
    labels[node_mapping[malware]] = 1

# Step 3: Definire il modello GNN

class GCN(torch.nn.Module):
    def __init__(self, num_node_features, hidden_channels, num_classes):
        super(GCN, self).__init__()
        self.conv1 = GCNConv(num_node_features, hidden_channels)
        self.conv2 = GCNConv(hidden_channels, num_classes)

    def forward(self, data):
        x, edge_index = data.x, data.edge_index
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = self.conv2(x, edge_index)
        return F.log_softmax(x, dim=1)

# Creiamo l'oggetto Data di PyTorch Geometric
data = Data(x=node_features, edge_index=edge_index, y=labels)

# Supponiamo di avere 2 classi di output: malware e non-malware
model = GCN(num_node_features=num_nodes, hidden_channels=16, num_classes=2)

# Definiamo l'ottimizzatore e la funzione di perdita
optimizer = torch.optim.Adam(model.parameters(), lr=0.01)
criterion = torch.nn.CrossEntropyLoss()

# Funzione di addestramento
def train():
    model.train()
    optimizer.zero_grad()
    out = model(data)
    loss = criterion(out, data.y)
    loss.backward()
    optimizer.step()
    return loss.item()

# Funzione di test
def test():
    model.eval()
    _, pred = model(data).max(dim=1)
    correct = (pred == data.y).sum()
    acc = int(correct) / int(data.y.size(0))
    return acc, pred

# Addestramento del modello
losses = []
accuracies = []
for epoch in range(200):
    loss = train()
    acc, pred = test()
    losses.append(loss)
    accuracies.append(acc)
    if epoch % 10 == 0:
        print(f'Epoch {epoch}, Loss: {loss:.4f}, Accuracy: {acc:.4f}')

# Funzione per ottenere i 3 malware più probabili dati 3 comportamenti
def get_top_3_malware(behaviors, model, data, node_mapping, reverse_node_mapping):
    model.eval()
    behavior_indices = [node_mapping[behavior] for behavior in behaviors]
    behavior_features = node_features[behavior_indices]

    with torch.no_grad():
        out = model(data)
        probabilities = F.softmax(out, dim=1)
        malware_scores = probabilities[:, 1]  # Probabilità che il nodo sia un malware

        # Otteniamo i 3 malware con i punteggi più alti
        top_malware_indices = malware_scores.topk(5).indices
        top_malwares = [reverse_node_mapping[idx.item()] for idx in top_malware_indices]
        return top_malwares

# Esempio di inferenza con 3 comportamenti
behaviors = ["Encrypted Channel: Asymmetric Cryptography", "Obfuscated Files or Information: Command Obfuscation", "Ingress Tool Transfer"]  # Sostituisci con i comportamenti reali
top_malwares = get_top_3_malware(behaviors, model, data, node_mapping, reverse_node_mapping)
print("Top 5 malware:", top_malwares)
