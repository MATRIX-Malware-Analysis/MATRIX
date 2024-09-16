import pandas as pd
from math import log2

def read_data(file_path):
    # Legge il file e estrae le informazioni
    with open(file_path, 'r') as file:
        data = file.readlines()
        
    # Estrae l'API e il numero associato agli Objectives
    api_objectives = [line.strip().split(":") for line in data if line.strip()]
    objectives_data = []
    
    for item in api_objectives:
        api_info = item[0].strip()
        score_objective = item[1].strip().split('(')
        print(item)
        score = int(score_objective[0].strip())
        tactic = item[2].strip()
        #print(item[2])
        if "(" in tactic:
            tactic = tactic.replace("(", "")
        if ")" in tactic:
            tactic = tactic.replace(")", "")
        objective = tactic
        print(f"SCORE: {score} TACTIC: {objective}")
        objectives_data.append((api_info, score, objective))
    
    return objectives_data

def calculate_entropy(group):
    # Calcola l'entropia basata sul numero di API uniche per ciascun obiettivo
    api_counts = group['API'].nunique()  # Numero di API uniche per l'obiettivo
    if api_counts == 0:
        return 0
    probabilities = 1 / api_counts  # Se esiste un solo gruppo, la probabilità è 1/n API
    return -log2(probabilities) if probabilities > 0 else 0

def analyze_objectives(file_path):
    # Leggi i dati
    data = read_data(file_path)
    
    # Crea un DataFrame
    df = pd.DataFrame(data, columns=['API', 'Score', 'Objective'])
    
    # Calcola la distribuzione percentuale degli Objectives
    objective_distribution = df['Objective'].value_counts(normalize=True) * 100
    print("Distribuzione percentuale degli Objectives in Agent Tesla:")
    print(objective_distribution)
    
    # Calcola l'entropia per ciascun Objective
    entropy_per_objective = df.groupby('Objective').apply(calculate_entropy)
    
    # Mostra l'entropia per ciascun Objective
    print("\nEntropia per ciascun Objective (basata sulle API uniche):")
    for objective, entropy in entropy_per_objective.items():
        print(f"{objective}: {entropy:.4f}")

# Percorso del file (aggiusta secondo il tuo ambiente)
file_path = 'API_Agent_Tesla_Objectives.txt'
analyze_objectives(file_path)
