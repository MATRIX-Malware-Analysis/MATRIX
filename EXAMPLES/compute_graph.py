from neo4j import GraphDatabase
import networkx as nx
import torch
from torch_geometric.utils import from_networkx
from torch_geometric.data import Data
import torch.nn.functional as F
from torch_geometric.nn import GCNConv
import torch.nn as nn
import torch.optim as optim

uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"

driver = GraphDatabase.driver(uri, auth=(user, password))

def extract_graph(tx):
    query = """
    MATCH (n)-[r:uses]->(m)
    RETURN n.id AS source, m.id AS target
    """
    result = tx.run(query)
    edges = [(record["source"], record["target"]) for record in result]
    return edges

with driver.session() as session:
    edges = session.read_transaction(extract_graph)

G = nx.Graph()
G.add_edges_from(edges)

data = from_networkx(G)

data.x = torch.randn((G.number_of_nodes(), 16))  # 16-dimension feature vector for each node
data.y = torch.randint(0, 2, (G.number_of_nodes(),))  # Binary labels for each node

data.train_mask = torch.rand(G.number_of_nodes()) < 0.8
data.test_mask = ~data.train_mask

import torch.nn.functional as F
from torch_geometric.nn import GCNConv

class GCN(torch.nn.Module):
    def __init__(self):
        super(GCN, self).__init__()
        self.conv1 = GCNConv(16, 32)
        self.conv2 = GCNConv(32, 64)
        self.conv3 = GCNConv(64, 2)
        self.dropout = torch.nn.Dropout(p=0.5)

    def forward(self, data):
        x, edge_index = data.x, data.edge_index
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = self.dropout(x)
        x = self.conv2(x, edge_index)
        x = F.relu(x)
        x = self.dropout(x)
        x = self.conv3(x, edge_index)
        return F.log_softmax(x, dim=1)


model = GCN()

loss_fn = nn.CrossEntropyLoss()
optimizer = optim.Adam(model.parameters(), lr=0.01, weight_decay=5e-4)

model.train()
for epoch in range(200):
    optimizer.zero_grad()
    out = model(data)
    loss = loss_fn(out[data.train_mask], data.y[data.train_mask])
    loss.backward()
    optimizer.step()
    print(f'Epoch {epoch+1}, Loss: {loss.item()}')

model.eval()
_, pred = model(data).max(dim=1)
correct = (pred[data.test_mask] == data.y[data.test_mask]).sum()
accuracy = int(correct) / int(data.test_mask.sum())
print(f'Accuracy: {accuracy:.4f}')
