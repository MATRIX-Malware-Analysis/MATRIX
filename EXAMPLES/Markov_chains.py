import numpy as np
import json
import heapq

# Carica la matrice di co-occorrenza
with open("co_occurrence_matrix.json", "r") as f:
    co_occurrence_matrix = json.load(f)

# Normalizza la matrice di co-occorrenza per ottenere le probabilità di transizione
def normalize_co_occurrence_matrix(co_occurrence_matrix):
    transition_matrix = {}
    for key, neighbors in co_occurrence_matrix.items():
        total = sum(neighbors.values())
        transition_matrix[key] = {k: v / total for k, v in neighbors.items()}
    return transition_matrix

transition_matrix = normalize_co_occurrence_matrix(co_occurrence_matrix)

# Funzione per generare i 3 percorsi più probabili usando un modello di Markov
def top_k_markov_sequences(transition_matrix, start_technique, k=3, max_length=5, repeat_penalty=0.2):
    # Usare un heap per memorizzare i percorsi più probabili
    heap = []
    heapq.heappush(heap, (-1.0, [start_technique]))  # (-probabilità, percorso)
    
    top_k_paths = []

    while heap and len(top_k_paths) < k:
        current_prob, current_sequence = heapq.heappop(heap)
        current_prob = -current_prob  # Convertiamo nuovamente la probabilità in positiva
        current_technique = current_sequence[-1]
        
        if len(current_sequence) >= max_length:
            top_k_paths.append((current_sequence, current_prob))
            continue
        
        if current_technique in transition_matrix:
            next_techniques = list(transition_matrix[current_technique].keys())
            probabilities = list(transition_matrix[current_technique].values())
            
            for i, tech in enumerate(next_techniques):
                if tech in current_sequence:
                    probabilities[i] *= repeat_penalty

            # Normalizza le probabilità
            probabilities_sum = sum(probabilities)
            probabilities = [p / probabilities_sum for p in probabilities]

            for i, tech in enumerate(next_techniques):
                new_prob = current_prob * probabilities[i]
                new_sequence = current_sequence + [tech]
                heapq.heappush(heap, (-new_prob, new_sequence))
                
                # Se la sequenza è completa o non può essere estesa ulteriormente
                if len(new_sequence) >= max_length or not transition_matrix.get(tech):
                    top_k_paths.append((new_sequence, new_prob))
                    top_k_paths = sorted(top_k_paths, key=lambda x: x[1], reverse=True)[:k]
    
    return top_k_paths

# Definisci la tecnica di partenza
start_technique = 'T1129'
top_3_paths = top_k_markov_sequences(transition_matrix, start_technique, max_length=5)

print("Top 3 most probable sequences using Markov Model:")
for i, (sequence, prob) in enumerate(top_3_paths, 1):
    print(f"Path {i}: {sequence} with probability {prob:.4f}")
