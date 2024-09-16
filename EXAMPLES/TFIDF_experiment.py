from neo4j import GraphDatabase
from collections import defaultdict
import json
import math

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
    malware_behaviors = defaultdict(list)
    behavior_counts = defaultdict(int)
    malware_counts = defaultdict(int)
    
    for record in result:
        malware = record["malware"]
        behavior = record["behavior"]
        malware_behaviors[malware].append(behavior)
        behavior_counts[behavior] += 1
        malware_counts[malware] += 1
    
    return malware_behaviors, behavior_counts, malware_counts

with driver.session() as session:
    malware_behaviors, behavior_counts, malware_counts = session.read_transaction(extract_data)

total_malwares = len(malware_counts)
malware_behavior_importance = defaultdict(dict)

for malware, behaviors in malware_behaviors.items():
    for behavior in behaviors:
        tf = behaviors.count(behavior) / len(behaviors)
        idf = math.log(total_malwares / (1 + behavior_counts[behavior]))
        tf_idf = tf * idf
        malware_behavior_importance[malware][behavior] = tf_idf

malware_data = []
for malware, behaviors in malware_behavior_importance.items():
    behavior_list = [{"behavior": behavior, "importance": importance} for behavior, importance in behaviors.items()]
    malware_data.append({"malware": malware, "behaviors": behavior_list})

output_file = "malware_behavior_importance_tfidf.json"
with open(output_file, 'w', encoding='utf-8') as f:
    json.dump(malware_data, f, indent=4)

print(f"Results saved to {output_file}")

driver.close()
