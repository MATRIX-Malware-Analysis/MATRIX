from neo4j import GraphDatabase
import json
from collections import defaultdict, Counter
from tqdm import tqdm

uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"

driver = GraphDatabase.driver(uri, auth=(user, password))

def extract_malware_behaviors(tx):
    query = """
    MATCH (m:Malware)-[:uses]->(b:Malware_Behavior)-[:related_to]->(o:Malware_Objective)
    WHERE toLower(m.description) CONTAINS 'worm'
    RETURN m.name AS malware, b.name AS behavior, b.external_references_0 AS external_id, o.name AS objective
    """
    result = tx.run(query)
    malware_behaviors = defaultdict(list)
    behavior_objectives = defaultdict(list)
    for record in tqdm(result, desc="Retrieving Behaviors and Objectives ..."):
        malware = record["malware"]
        behavior = record["behavior"]
        technique_id = record["external_id"]
        external_id = eval(technique_id)["external_id"]
        objective = record["objective"]
        malware_behaviors[malware].append(external_id)
        behavior_objectives[external_id].append(objective)
    return malware_behaviors, behavior_objectives

with driver.session() as session:
    malware_behaviors, behavior_objectives = session.read_transaction(extract_malware_behaviors)

print("[!] Extracting APIs ...")
with open("attack_to_strings.json", 'r', encoding='utf-8') as f:
    attack_to_apis = json.load(f)

api_counter = Counter()
api_objectives = defaultdict(set)

for malware, external_ids in tqdm(malware_behaviors.items(), desc='Processing malware behaviors'):
    for external_id in external_ids:
        if external_id in attack_to_apis:
            apis = attack_to_apis[external_id]
            api_counter.update(apis)
            objectives = behavior_objectives[external_id]
            for api in apis:
                api_objectives[api].update(objectives)

most_common_apis = api_counter.most_common()

with open("Strings_Worm_Objectives.txt", "w") as f:
    print("Most common Strings used by Ransomware and their associated Objectives:")
    f.write("Most common Strings used by Ransomware and their associated Objectives:\n")
    for api, count in most_common_apis:
        associated_objectives = ", ".join(api_objectives[api])
        print(f"{api}: {count} (Objectives: {associated_objectives})")
        f.write(f"{api}: {count} (Objectives: {associated_objectives})\n")

driver.close()
