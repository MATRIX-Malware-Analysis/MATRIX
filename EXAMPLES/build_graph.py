from neo4j import GraphDatabase
import os
import json
from tqdm import tqdm

uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"
driver = GraphDatabase.driver(uri, auth=(user, password))

def read_json_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read().strip()  # Rimuove eventuali spazi bianchi o righe vuote
            if not content:
                print(f"Warning: The file {file_path} is empty.")
                return None
            return json.loads(content)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from file {file_path}: {e}")
        return None
        
def flatten_dict(d, parent_key='', sep='_'):
    items = {}
    
    for k, v in d.items():
        if parent_key:
            if parent_key not in items:
                items[parent_key] = {}
            items[parent_key][k] = v
        else:
            if isinstance(v, dict):
                items.update(flatten_dict(v, k, sep))
            elif isinstance(v, list):
                for index, item in enumerate(v):
                    if isinstance(item, dict):
                        items.update(flatten_dict(item, f"{k}{sep}{index}", sep))
                    else:
                        items[f"{k}{sep}{index}"] = item
            else:
                items[k] = v

    if parent_key and isinstance(items[parent_key], dict):
        return {parent_key: json.dumps(items[parent_key])}
    else:
        return items

def sanitize_properties(properties):
    sanitized = {}
    for key, value in properties.items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            sanitized[key] = value
        else:
            sanitized[key] = json.dumps(value)
    return sanitized

def create_node(tx, label, properties):
    flat_properties = flatten_dict(properties)
    sanitized_properties = sanitize_properties(flat_properties)
    query = f"CREATE (n:{label} $properties)"
    tx.run(query, properties=sanitized_properties)

def sanitize_relationship_type(rel_type):
    return rel_type.replace("-", "_")

def create_relationship(tx, start_node_id, end_node_id, relationship_type, properties):
    sanitized_relationship_type = sanitize_relationship_type(relationship_type)
    flat_properties = flatten_dict(properties)
    sanitized_properties = sanitize_properties(flat_properties)
    query = (
        f"MATCH (a {{id: $start_node_id}}), (b {{id: $end_node_id}}) "
        f"CREATE (a)-[r:{sanitized_relationship_type} $properties]->(b)"
    )
    tx.run(query, start_node_id=start_node_id, end_node_id=end_node_id, properties=sanitized_properties)

def load_elements(base_path, labels):
    with driver.session() as session:
        for label in labels:
            directory = os.path.join(base_path, label)
            for filename in tqdm(os.listdir(directory), desc=f"Loading {label} nodes."):
                if filename.endswith(".json"):
                    filepath = os.path.join(directory, filename)
                    data = read_json_file(filepath)
                    session.write_transaction(create_node, label, data)



def load_relationships(directory):
    with driver.session() as session:
        for filename in tqdm(os.listdir(directory), desc="Loading Relationships ..."):
            if filename.endswith(".json"):
                filepath = os.path.join(directory, filename)
                data = read_json_file(filepath)
                if data is None:
                    continue  # Salta questo file se non è valido
                if data["type"] == "relationship":
                    start_node_id = data["source_ref"]
                    end_node_id = data["target_ref"]
                    relationship_type = data["relationship_type"]
                    session.write_transaction(create_relationship, start_node_id, end_node_id, relationship_type, data)

def main():
    base_path = "/home/marcos/CyberGraphDB/CyberGraphDB/CAPEC/BUILDING_FOLDER/ELEMENTS2"
    
    labels = [
        "Malware", "Malware_Behavior", "Malware_Objective", "Course_of_Action",
        "Intrusion_Set", "Campaign", "Tool", "Data_Source", "Data_Component",
        "Malware_Method", "Indicator", "Vulnerabilities", "Weaknesses", "Exploit"
    ]
    
    load_elements(base_path, labels)

    load_relationships(os.path.join(base_path, "Relationships"))

if __name__ == "__main__":
    main()
