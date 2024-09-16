from neo4j import GraphDatabase
from collections import defaultdict
import json
import networkx as nx
import matplotlib.pyplot as plt
import ast
from matplotlib.lines import Line2D

# Connessione a Neo4j
uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"
driver = GraphDatabase.driver(uri, auth=(user, password))

# Ordinamento delle tattiche
tactics_order = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact"
]

# Funzione per estrarre le tecniche e tattiche con conteggio
def extract_techniques_and_tactics(tx):
    query = """
    MATCH (m:Malware)-[:uses]->(b:Malware_Behavior)-[:related_to]->(i:Malware_Objective)
    WHERE toLower(m.description) CONTAINS 'backdoor'
    RETURN b.external_references_0 AS technique_id, i.name AS tactic_name
    """
    result = tx.run(query)
    technique_count = defaultdict(int)
    technique_to_tactic = {}
    
    for record in result:
        technique_id = record["technique_id"]
        tactic_name = record["tactic_name"]
        technique_id = ast.literal_eval(technique_id)
        technique_id = technique_id["external_id"]
        if technique_id:
            technique_to_tactic[technique_id] = tactic_name
            # Incrementa il conteggio della tecnica
            technique_count[technique_id] += 1
    return technique_to_tactic, technique_count

# Funzione per ordinare e raggruppare le tecniche in base alle tattiche
def group_techniques_by_tactic(technique_to_tactic):
    grouped_techniques = defaultdict(list)
    for technique, tactic in technique_to_tactic.items():
        grouped_techniques[tactic].append(technique)
    return grouped_techniques

# Estrai le tecniche e le tattiche da Neo4j
with driver.session() as session:
    technique_to_tactic, technique_count = session.read_transaction(extract_techniques_and_tactics)

# Raggruppa le tecniche per tattica
grouped_techniques = group_techniques_by_tactic(technique_to_tactic)

# Calcola la frequenza normalizzata delle tecniche
def calculate_normalized_frequencies(technique_count):
    total_techniques = sum(technique_count.values())
    technique_frequencies = {}

    # Calcola la frequenza normalizzata
    for technique, count in technique_count.items():
        technique_frequencies[technique] = count / total_techniques

    return technique_frequencies

# Calcola le frequenze normalizzate delle tecniche
technique_frequencies = calculate_normalized_frequencies(technique_count)
print(technique_frequencies)

# Prepara i dati per il grafico
techniques = []
frequencies = []
colors = []
tactic_color_map = {tactic: plt.cm.get_cmap('tab20')(i / len(tactics_order)) for i, tactic in enumerate(tactics_order)}

for tactic in tactics_order:
    for technique in grouped_techniques.get(tactic, []):
        techniques.append(technique)
        frequencies.append(technique_frequencies.get(technique, 0))
        colors.append(tactic_color_map[tactic])

# Crea il grafico a barre orizzontali
plt.figure(figsize=(15, 10))
bars = plt.barh(techniques, frequencies, color=colors)

# Aggiungi una legenda per le Tactics
legend_elements = [Line2D([0], [0], color=tactic_color_map[tactic], lw=4, label=tactic) for tactic in tactics_order]
plt.legend(handles=legend_elements, title="Tactics", bbox_to_anchor=(1.05, 1), loc='upper left')

# Imposta etichette e titolo
plt.xlabel('Normalized Frequency')
plt.ylabel('Techniques')
plt.title('Distribution of Techniques within Backdoor by Tactic')

# Mostra il grafico
plt.show()
plt.savefig("backdoor_distribution.png")
plt.close()
