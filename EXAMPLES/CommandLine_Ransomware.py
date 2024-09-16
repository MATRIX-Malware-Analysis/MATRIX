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
    WHERE toLower(m.description) CONTAINS 'trojan'
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

print("[!] Extracting CommandLines ...")
with open("technique_commands_with_rules.json", 'r', encoding='utf-8') as f:
    technique_commands = json.load(f)

commandline_counter = Counter()
commandline_objectives = defaultdict(set)

for malware, external_ids in tqdm(malware_behaviors.items(), desc='Processing malware behaviors'):
    for external_id in external_ids:
        if external_id in technique_commands:
            commandline_infos = technique_commands[external_id]
            for info in commandline_infos:
                if "CommandLine" in info['key']:
                    commandlines = info['values']
                    commandline_counter.update(commandlines)
                    objectives = behavior_objectives[external_id]
                    for commandline in commandlines:
                        commandline_objectives[commandline].update(objectives)

most_common_commandlines = commandline_counter.most_common()

with open("CommandLines_Trojan_Objectives.txt", "w") as f:
    print("Most common CommandLines used by Trojan and their associated Objectives:")
    f.write("Most common CommandLines used by Trojan and their associated Objectives:\n")
    for commandline, count in most_common_commandlines:
        associated_objectives = ", ".join(commandline_objectives[commandline])
        print(f"{commandline}: {count} (Objectives: {associated_objectives})")
        f.write(f"{commandline}: {count} (Objectives: {associated_objectives})\n")

driver.close()
