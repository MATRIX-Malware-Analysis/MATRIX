from neo4j import GraphDatabase
from collections import defaultdict
import json

# Connessione a Neo4j
uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"

driver = GraphDatabase.driver(uri, auth=(user, password))

# Estrazione delle relazioni Malware -[:uses]-> (b:MalwareBehavior)-[:related_to]->(i:MalwareObjective)
def extract_tactic_sequences(tx):
    query = """
    MATCH (m:Malware)-[:uses]->(b:Malware_Behavior)-[:related_to]->(i:Malware_Objective)
    RETURN m.name AS malware, i.name AS tactic_name
    """
    result = tx.run(query)
    sequences = defaultdict(list)
    for record in result:
        malware = record["malware"]
        tactic_name = record["tactic_name"]
        sequences[malware].append(tactic_name)
    return sequences

with driver.session() as session:
    tactic_sequences = session.read_transaction(extract_tactic_sequences)

# Costruisci la matrice di co-occorrenza delle tattiche
co_occurrence_matrix = defaultdict(lambda: defaultdict(int))

for sequence in tactic_sequences.values():
    for i in range(len(sequence)):
        for j in range(i + 1, len(sequence)):
            co_occurrence_matrix[sequence[i]][sequence[j]] += 1
            co_occurrence_matrix[sequence[j]][sequence[i]] += 1

# Calcolo delle percentuali di co-occorrenza
results = {}

for tactic, co_occurrences in co_occurrence_matrix.items():
    total = sum(co_occurrences.values())
    percentages = {key: (count / total) * 100 for key, count in co_occurrences.items()}
    sorted_percentages = dict(sorted(percentages.items(), key=lambda item: item[1], reverse=True))
    results[tactic] = sorted_percentages

# Stampa i risultati
print("MITRE ATT&CK Tactics e Tactics correlati:")
print(json.dumps(results, indent=4))

# Salva i risultati in un file
with open("tactic_to_tactic_correlations_neo4j.json", "w") as f:
    json.dump(results, f, indent=4)
