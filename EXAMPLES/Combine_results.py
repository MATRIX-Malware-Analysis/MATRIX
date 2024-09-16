from neo4j import GraphDatabase

uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"

driver = GraphDatabase.driver(uri, auth=(user, password))

def get_objective_percentages(tx):
    query = """
    MATCH (m:Malware)-[:uses]->(b:Malware_Behavior)<-[:uses]-(i:Intrusion_Set)
    MATCH (b)-[:related_to]->(o:Malware_Objective)
    WHERE (toLower(i.description) CONTAINS 'iranian')
    RETURN o.name AS objective, COUNT(o) AS objective_count
    """
    result = tx.run(query)
    
    objectives = {}
    total_count = 0
    
    for record in result:
        objective = record["objective"]
        count = record["objective_count"]
        objectives[objective] = count
        total_count += count
    
    percentages = {objective: (count / total_count) * 100 for objective, count in objectives.items()}
    
    return percentages, total_count

def main():
    with driver.session() as session:
        objective_percentages, total_count = session.execute_read(get_objective_percentages)

    with open("Iran_Objective_Percentages.txt", "w") as f:
        f.write(f"Total objectives related to Iran: {total_count}\n")
        f.write("Objective Percentages:\n")
        print(f"Total objectives related to Iran: {total_count}")
        print("Objective Percentages:")
        
        for objective, percentage in objective_percentages.items():
            f.write(f'{objective}: {percentage:.2f}%\n')
            print(f'{objective}: {percentage:.2f}%')

if __name__ == "__main__":
    main()

driver.close()
