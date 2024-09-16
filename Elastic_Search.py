from elasticsearch import Elasticsearch, helpers
import os
import json
from tqdm import tqdm

# Connection to Elasticsearch
es = Elasticsearch(
    hosts=[{
        'host': 'localhost',
        'port': 9200,
        'scheme': 'http'
    }]
)

# Adjusting Elasticsearch index settings
es.indices.put_settings(
    index="malware_reports",
    body={
        "index.mapping.nested_fields.limit": 20000  # New nested fields limit
    }
)
es.indices.put_settings(
    index="malware_reports",
    body={
        "index.mapping.depth.limit": 3000  # New depth limit
    }
)
es.indices.put_settings(
    index="malware_reports",
    body={
        "index.mapping.total_fields.limit": 5000  # Increases the field limit
    }
)

# Directory containing the JSON files
reports_dir = "/home/marcos/CyberGraphDB/CyberGraphDB/CAPEC/BUILDING_FOLDER/STIX_GRAPH/GET_MITRE_TECHNIQUES/REPORTS"

def contains_field(data, field_path):
    """ Checks if a specific field exists in the JSON dictionary. """
    keys = field_path.split('.')
    current_dict = data
    
    # Traverse the dictionary levels
    for key in keys:
        if isinstance(current_dict, dict):
            current_dict = current_dict.get(key, None)
        elif isinstance(current_dict, list):
            # If it's a list, check each item
            for item in current_dict:
                if isinstance(item, dict):
                    current_dict = item.get(key, None)
                    if current_dict is not None:
                        break
                else:
                    current_dict = None
                    break
        else:
            current_dict = None
            break
    
    return current_dict is not None

def load_reports_to_elasticsearch(reports_dir):
    actions = []
    for root, dirs, files in os.walk(reports_dir):
        for file in tqdm(files, desc="Loading files"):
            if file.endswith(".txt"):  # Change this if the files are in .txt format
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    if '020e75bba53b32452b70c2796aabfd51dbd2c82380bf138158ad590d9db1df72' in file_path:
                        print("---------------- 020e75bba53b32452b70c2796aabfd51dbd2c82380bf138158ad590d9db1df72 --------------")
                    try:
                        report = json.load(f)
                        # Check if the problematic field is present
                        if not contains_field(report, 'data.attributes.http_conversations.response_headers.X-Ms-Version'):
                            action = {
                                "_index": "malware_reports",
                                "_source": report
                            }
                            actions.append(action)
                            print(f"Adding report to actions: {file_path}")
                        else:
                            print(f"Skipping report due to problematic field: {file_path}")
                    except json.JSONDecodeError as e:
                        print(f"Error decoding JSON from {file_path}: {e}")
                    except Exception as e:
                        print(f"Error processing {file_path}: {e}")

    print(f'Number of Reports -> {len(actions)}')
    if actions:
        try:
            # Bulk load into Elasticsearch
            response = helpers.bulk(es, actions)
            print("All reports have been loaded into Elasticsearch")
        except helpers.BulkIndexError as e:
            with open("Elastic_search_error.txt", "a") as f:
                f.write(f"++++++++++++++++++++++++\nBulkIndexError: {e}\n")
                print("\nBulkIndexError: ", e)
                for error in e.errors:
                    f.write(json.dumps(error, indent=4))
    else:
        print("No actions to load into Elasticsearch")

# Load reports into Elasticsearch
load_reports_to_elasticsearch(reports_dir)
