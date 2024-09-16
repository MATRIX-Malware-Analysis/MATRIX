from neo4j import GraphDatabase
import time

uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"

driver = GraphDatabase.driver(uri, auth=(user, password))
start_time = time.time()
def get_influential_course_of_action(tx):
    query = """
    MATCH (m:Malware)-[:uses]->(b:Malware_Behavior)<-[:mitigates]-(c:Course_of_Action)
    WHERE m.description CONTAINS 'trojan' OR m.description CONTAINS 'Trojan'
    RETURN c.name AS course_of_action, COUNT(*) AS influence
    ORDER BY influence DESC
    """
    result = tx.run(query)
    actions = []
    for record in result:
        course_of_action = record["course_of_action"]
        influence = record["influence"]
        actions.append((course_of_action, influence))
    return actions

with driver.session() as session:
    actions = session.execute_read(get_influential_course_of_action)

# Stampa i risultati
with open("CoA_Trojan.txt", "a") as f:
    for course_of_action, influence in actions:
        print(f'Course of Action: {course_of_action}, Influence: {influence}')
        f.write(f'Course of Action: {course_of_action}, Influence: {influence}\n')

end_time = time.time()

final_time = end_time - start_time
print(f'Final Time -> {final_time}')