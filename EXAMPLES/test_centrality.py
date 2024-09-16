import json
import itertools
import random
from collections import defaultdict
from tqdm import tqdm 

input_file = "malware_behavior_importance_centrality.json"
with open(input_file, 'r', encoding='utf-8') as f:
    malware_data = json.load(f)

malware_centrality = defaultdict(dict)
for entry in malware_data:
    malware = entry['malware']
    for behavior_info in entry['behaviors']:
        behavior = behavior_info['behavior']
        importance = behavior_info['importance']
        malware_centrality[malware][behavior] = importance

dataset = []
for malware, behaviors in tqdm(malware_centrality.items(), desc='Building dataset ...'):
    behavior_list = list(behaviors.keys())
    if len(behavior_list) >= 3:
        combinations = list(itertools.combinations(behavior_list, 3))
        selected_combinations = random.sample(combinations, min(20, len(combinations)))  # Limita a 10 combinazioni per malware
        for combo in selected_combinations:
            dataset.append((malware, combo))

def calculate_centrality_score(sample_behaviors, malware, malware_centrality):
    return sum(malware_centrality[malware].get(behavior, 0) for behavior in sample_behaviors)

correct_first = 0
correct_second = 0
correct_third = 0
none_correct = 0

for true_label, sample_behaviors in tqdm(dataset, desc='Computing centrality for the dataset ...'):
    scores = {}
    for malware, behavior_dict in malware_centrality.items():
        if all(behavior in behavior_dict for behavior in sample_behaviors):
            scores[malware] = calculate_centrality_score(sample_behaviors, malware, malware_centrality)

    top_3_malware = sorted(scores, key=scores.get, reverse=True)[:3]

    if true_label == top_3_malware[0]:
        correct_first += 1
    elif true_label == top_3_malware[1]:
        correct_second += 1
    elif true_label == top_3_malware[2]:
        correct_third += 1
    else:
        none_correct += 1

total_samples = len(dataset)
print(f"Total samples: {total_samples}")
print(f"Correct as first choice: {correct_first} ({correct_first / total_samples:.2%})")
print(f"Correct as second choice: {correct_second} ({correct_second / total_samples:.2%})")
print(f"Correct as third choice: {correct_third} ({correct_third / total_samples:.2%})")
print(f"None correct: {none_correct} ({none_correct / total_samples:.2%})")
