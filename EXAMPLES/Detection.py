from neo4j import GraphDatabase

uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"

driver = GraphDatabase.driver(uri, auth=(user, password))

def get_influential_data_components(tx):
    query = """
    MATCH (m:Malware)-[:uses]->(b:Malware_Behavior)<-[:detects]-(d:Data_Component)
    WHERE m.description CONTAINS 'worm' OR m.description CONTAINS 'worm'
    RETURN d.name AS data_component, COUNT(*) AS influence
    ORDER BY influence DESC
    """
    result = tx.run(query)
    data_components = []
    for record in result:
        data_component = record["data_component"]
        influence = record["influence"]
        data_components.append((data_component, influence))
    return data_components

with driver.session() as session:
    data_components = session.execute_read(get_influential_data_components)

# Stampa i risultati
with open("Detection_Worm.txt", "a") as f:
    for data_component, influence in data_components:
        print(f'Data Component: {data_component}, Influence: {influence}')
        f.write(f'Data Component: {data_component}, Influence: {influence}\n')