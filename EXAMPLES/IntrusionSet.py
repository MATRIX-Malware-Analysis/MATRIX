from neo4j import GraphDatabase

uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"

driver = GraphDatabase.driver(uri, auth=(user, password))
#AND (i.description CONTAINS 'China' OR i.description CONTAINS 'china')
def get_influential_intrusion_sets(tx):
    query = """
    MATCH (m:Malware)-[:uses]->(b:Malware_Behavior)<-[:uses]-(i:Intrusion_Set)
    WHERE (m.description CONTAINS 'spy' OR m.description CONTAINS 'Spy') 
    RETURN i.name AS intrusion_set, COUNT(*) AS influence
    ORDER BY influence DESC
    """
    result = tx.run(query)
    intrusion_sets = []
    for record in result:
        intrusion_set = record["intrusion_set"]
        influence = record["influence"]
        intrusion_sets.append((intrusion_set, influence))
    return intrusion_sets

with driver.session() as session:
    intrusion_sets = session.execute_read(get_influential_intrusion_sets)

# Stampa i risultati
with open("IntrusionSet_Spyware.txt", "a") as f:
    for intrusion_set, influence in intrusion_sets:
        print(f'Intrusion Set: {intrusion_set}, Influence: {influence}')
        f.write(f'Intrusion Set: {intrusion_set}, Influence: {influence}\n')
