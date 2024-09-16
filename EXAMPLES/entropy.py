import pandas as pd
from math import log2

def read_data(file_path):
    with open(file_path, 'r') as file:
        data = file.readlines()
        
    api_objectives = [line.strip().split(":") for line in data if line.strip()]
    objectives_data = []
    
    for item in api_objectives:
        api_info = item[0].strip()
        score_objective = item[1].strip().split('(')
        print(item)
        score = int(score_objective[0].strip())
        tactic = item[2].strip()
        if "(" in tactic:
            tactic = tactic.replace("(", "")
        if ")" in tactic:
            tactic = tactic.replace(")", "")
        objective = tactic
        print(f"SCORE: {score} TACTIC: {objective}")
        objectives_data.append((api_info, score, objective))
    
    return objectives_data

def calculate_entropy(group):
    api_counts = group['API'].nunique()  # Numero di API uniche per l'obiettivo
    if api_counts == 0:
        return 0
    probabilities = 1 / api_counts  # Se esiste un solo gruppo, la probabilità è 1/n API
    return -log2(probabilities) if probabilities > 0 else 0

def analyze_objectives(file_path):
    data = read_data(file_path)
    
    df = pd.DataFrame(data, columns=['API', 'Score', 'Objective'])
    
    objective_distribution = df['Objective'].value_counts(normalize=True) * 100
    print("Distribuzione percentuale degli Objectives in Agent Tesla:")
    print(objective_distribution)
    
    entropy_per_objective = df.groupby('Objective').apply(calculate_entropy)
    
    print("\nEntropia per ciascun Objective (basata sulle API uniche):")
    for objective, entropy in entropy_per_objective.items():
        print(f"{objective}: {entropy:.4f}")

file_path = 'API_Agent_Tesla_Objectives.txt'
analyze_objectives(file_path)
