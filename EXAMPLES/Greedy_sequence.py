import numpy as np
import json

with open("co_occurrence_matrix.json", "r") as f:
    co_occurrence_matrix = json.load(f)

def generate_greedy_sequence(co_occurrence_matrix, start_technique, max_length=20):
    current_technique = start_technique
    sequence = [current_technique]

    while len(sequence) < max_length:
        if current_technique in co_occurrence_matrix:
            neighbors = co_occurrence_matrix[current_technique]
            next_technique = max(neighbors, key=neighbors.get)
            if next_technique not in sequence:
                sequence.append(next_technique)
                current_technique = next_technique
            else:
                break
        else:
            break

    return sequence

start_technique = 'T1082'
sequence = generate_greedy_sequence(co_occurrence_matrix, start_technique)

print("Generated Sequence using Greedy Algorithm:")
print(sequence)
