from neo4j import GraphDatabase

# Connessione al database Neo4j
uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"
driver = GraphDatabase.driver(uri, auth=(user, password))

def delete_all(tx):
    tx.run("MATCH (n) DETACH DELETE n")

def main():
    with driver.session() as session:
        session.write_transaction(delete_all)
    print("All nodes and relationships have been deleted.")

if __name__ == "__main__":
    main()
