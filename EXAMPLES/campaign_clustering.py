from neo4j import GraphDatabase
import networkx as nx
from networkx.algorithms.community import louvain_communities
from collections import Counter
import json

uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"

driver = GraphDatabase.driver(uri, auth=(user, password))

def extract_graph(tx):
    query = """
    MATCH (c:Campaign)-[:uses]->(b:MalwareBehavior)
    RETURN c.name AS campaign, b.name AS behavior
    """
    result = tx.run(query)
    edges = [(record["campaign"], record["behavior"]) for record in result]
    return edges

def extract_nodes(tx):
    query = """
    MATCH (c:Campaign)
    RETURN c.name AS campaign, c.id AS campaign_id
    """
    result = tx.run(query)
    campaign_nodes = {record["campaign"]: record["campaign_id"] for record in result}
    
    query = """
    MATCH (b:MalwareBehavior)
    RETURN b.name AS behavior, b.id AS behavior_id
    """
    result = tx.run(query)
    behavior_nodes = {record["behavior"]: record["behavior_id"] for record in result}

    return campaign_nodes, behavior_nodes

with driver.session() as session:
    edges = session.read_transaction(extract_graph)
    campaign_nodes, behavior_nodes = session.read_transaction(extract_nodes)

G = nx.Graph()
G.add_edges_from(edges)

communities = louvain_communities(G)

community_results = []

for i, community in enumerate(communities):
    community_campaigns = [node for node in community if node in campaign_nodes]
    community_behaviors = [node for node in community if node in behavior_nodes]
    
    behavior_counter = Counter()
    
    for behavior in community_behaviors:
        for neighbor in G.neighbors(behavior):
            if neighbor in community_campaigns:
                behavior_counter[behavior] += 1
    
    top_behaviors = behavior_counter.most_common(3)
    top_behaviors = [(behavior, count) for behavior, count in top_behaviors]
    
    community_results.append({
        "community_id": i,
        "campaigns": community_campaigns,
        "top_behaviors": top_behaviors
    })

output_file = "Campaign_community_results_MalwareBahvior.json"
with open(output_file, 'w', encoding='utf-8') as f:
    json.dump(community_results, f, indent=4)

print(f"Results saved to {output_file}")

driver.close()
