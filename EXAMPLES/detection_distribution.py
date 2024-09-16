import time

# Apriamo e leggiamo il file
filename = "Detection_Worm.txt"


start_time = time.time()
# Lista per memorizzare le azioni e le influenze
coa_list = []

with open(filename, 'r') as file:
    for line in file:
        # Split per ottenere il CoA e l'influenza
        parts = line.strip().split(", Influence: ")
        coa = parts[0].replace("Data Component: ", "").strip()
        influence = int(parts[1])
        coa_list.append((coa, influence))

# Calcolo del totale delle influenze
total_influence = sum([coa[1] for coa in coa_list])

# Stampa del risultato con le percentuali
for coa, influence in coa_list:
    percentage = (influence / total_influence) * 100
    print(f"Data Component: {coa}, Influence: {percentage:.2f}%")

end_time = time.time()
final_time = end_time - start_time

print(f'Final Time -> {final_time}')