import json
import itertools
import random
from collections import defaultdict
from tqdm import tqdm 

# Carica i valori di PageRank dal file
input_file = "malware_behavior_importance.json"
with open(input_file, 'r', encoding='utf-8') as f:
    malware_data = json.load(f)

# Creazione di un dizionario di PageRank
malware_pagerank = defaultdict(dict)
for entry in malware_data:
    malware = entry['malware']
    for behavior_info in entry['behaviors']:
        behavior = behavior_info['behavior']
        importance = behavior_info['importance']
        malware_pagerank[malware][behavior] = importance

# Creazione del dataset con combinazioni limitate di 4 comportamenti per ogni malware
dataset = []
for malware, behaviors in tqdm(malware_pagerank.items(), desc='Building dataset ...'):
    behavior_list = list(behaviors.keys())
    if len(behavior_list) >= 3:
        combinations = list(itertools.combinations(behavior_list, 3))
        selected_combinations = random.sample(combinations, min(10, len(combinations)))  # Limita a 5 combinazioni per malware
        for combo in selected_combinations:
            dataset.append((malware, combo))

# Funzione per calcolare il punteggio PageRank di un sample per un dato malware
def calculate_pagerank_score(sample_behaviors, malware, malware_pagerank):
    return sum(malware_pagerank[malware].get(behavior, 0) for behavior in sample_behaviors)

# Test del classificatore
correct_first = 0
correct_second = 0
correct_third = 0
none_correct = 0

for true_label, sample_behaviors in tqdm(dataset, desc='Computing PageRank for the dataset ...'):
    scores = {}
    for malware, behavior_dict in malware_pagerank.items():
        if all(behavior in behavior_dict for behavior in sample_behaviors):
            scores[malware] = calculate_pagerank_score(sample_behaviors, malware, malware_pagerank)

    top_3_malware = sorted(scores, key=scores.get, reverse=True)[:3]

    if true_label == top_3_malware[0]:
        correct_first += 1
    elif true_label == top_3_malware[1]:
        correct_second += 1
    elif true_label == top_3_malware[2]:
        correct_third += 1
    else:
        none_correct += 1

# Stampa dei risultati
total_samples = len(dataset)
print(f"Total samples: {total_samples}")
print(f"Correct as first choice: {correct_first} ({correct_first / total_samples:.2%})")
print(f"Correct as second choice: {correct_second} ({correct_second / total_samples:.2%})")
print(f"Correct as third choice: {correct_third} ({correct_third / total_samples:.2%})")
print(f"None correct: {none_correct} ({none_correct / total_samples:.2%})")
