import json
import itertools
import random
import math
from collections import defaultdict
from tqdm import tqdm

input_file = "malware_behavior_importance.json"
with open(input_file, 'r', encoding='utf-8') as f:
    malware_data = json.load(f)

malware_behaviors = defaultdict(list)
behavior_counts = defaultdict(int)
malware_counts = defaultdict(int)

for entry in malware_data:
    malware = entry['malware']
    for behavior_info in entry['behaviors']:
        behavior = behavior_info['behavior']
        malware_behaviors[malware].append(behavior)
        behavior_counts[behavior] += 1
        malware_counts[malware] += 1

total_malwares = len(malware_counts)

dataset = []
for malware, behaviors in tqdm(malware_behaviors.items(), desc='Building dataset ...'):
    behavior_list = list(behaviors)
    if len(behavior_list) >= 3:
        combinations = list(itertools.combinations(behavior_list, 3))
        for combo in combinations:
            dataset.append((malware, combo))

def calculate_tfidf_score(sample_behaviors, malware, malware_behaviors, behavior_counts, total_malwares):
    tfidf_score = 0
    behaviors = malware_behaviors[malware]
    for behavior in sample_behaviors:
        tf = behaviors.count(behavior) / len(behaviors)
        idf = math.log(total_malwares / (1 + behavior_counts[behavior]))
        tfidf_score += tf * idf
    return tfidf_score

correct_first = 0
correct_second = 0
correct_third = 0
none_correct = 0

output_file = "step_by_step_results.json"
results = []

for true_label, sample_behaviors in tqdm(dataset, desc='Computing TFIDF for the dataset ...'):
    scores = {}
    filtered_malware = {malware: behavior_list for malware, behavior_list in malware_behaviors.items() if all(behavior in behavior_list for behavior in sample_behaviors)}
    
    for malware in filtered_malware:
        scores[malware] = calculate_tfidf_score(sample_behaviors, malware, malware_behaviors, behavior_counts, total_malwares)

    top_3_malware = sorted(scores, key=scores.get, reverse=True)[:3]

    result = {
        "sample_behaviors": sample_behaviors,
        "true_label": true_label,
        "top_3_malware": top_3_malware
    }

    if true_label == top_3_malware[0]:
        correct_first += 1
        result["correct"] = "first"
    elif true_label == top_3_malware[1]:
        correct_second += 1
        result["correct"] = "second"
    elif true_label == top_3_malware[2]:
        correct_third += 1
        result["correct"] = "third"
    else:
        none_correct += 1
        result["correct"] = "none"

    results.append(result)

with open(output_file, 'w', encoding='utf-8') as f:
    json.dump(results, f, indent=4)

total_samples = len(dataset)
print(f"Total samples: {total_samples}")
print(f"Correct as first choice: {correct_first} ({correct_first / total_samples:.2%})")
print(f"Correct as second choice: {correct_second} ({correct_second / total_samples:.2%})")
print(f"Correct as third choice: {correct_third} ({correct_third / total_samples:.2%})")
print(f"None correct: {none_correct} ({none_correct / total_samples:.2%})")

def predict_malware(behaviors, malware_behaviors, behavior_counts, total_malwares):
    scores = {}
    filtered_malware = {malware: behavior_list for malware, behavior_list in malware_behaviors.items() if all(behavior in behavior_list for behavior in behaviors)}

    for malware in filtered_malware:
        scores[malware] = calculate_tfidf_score(behaviors, malware, malware_behaviors, behavior_counts, total_malwares)

    top_3_malware = sorted(scores, key=scores.get, reverse=True)[:3]
    return top_3_malware

def user_input_prediction():
    while True:
        input_behaviors = input("Enter three behaviors separated by commas (or type 'exit' to quit): ")
        if input_behaviors.lower() == 'exit':
            break
        behaviors = [behavior.strip() for behavior in input_behaviors.split(',')]
        if len(behaviors) != 3:
            print("Please enter exactly three behaviors.")
            continue
        
        top_3_malware = predict_malware(behaviors, malware_behaviors, behavior_counts, total_malwares)
        print(f"Top 3 predicted malware for behaviors {behaviors}:")
        for malware in top_3_malware:
            print(f"- {malware}")

user_input_prediction()
