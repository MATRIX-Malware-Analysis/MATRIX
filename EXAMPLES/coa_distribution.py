filename = "CoA_worm.txt"

coa_list = []

with open(filename, 'r') as file:
    for line in file:
        parts = line.strip().split(", Influence: ")
        coa = parts[0].replace("Course of Action: ", "").strip()
        influence = int(parts[1])
        coa_list.append((coa, influence))

total_influence = sum([coa[1] for coa in coa_list])

for coa, influence in coa_list:
    percentage = (influence / total_influence) * 100
    print(f"Course of Action: {coa}, Influence: {percentage:.2f}%")
