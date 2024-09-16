from elasticsearch import Elasticsearch
from collections import defaultdict
import json
from collections import Counter


es = Elasticsearch(
    hosts=[{
        'host': 'localhost',
        'port': 9200,
        'scheme': 'http'
    }]
)

query = {
    "query": {
        "exists": {
            "field": "data.attributes.sandbox_name"
        }
    },
    "_source": ["data.attributes.sandbox_name", "data.attributes.processes_tree"]
}

response = es.search(index="malware_reports", body=query, size=10000)

sandbox_behaviors = defaultdict(list)

for hit in response['hits']['hits']:
    data_list = hit['_source'].get('data', [])
    for data_item in data_list:
        attributes = data_item.get('attributes', {})
        sandbox_name = attributes.get('sandbox_name')
        processes_tree = attributes.get('processes_tree', [])
        sandbox_behaviors[sandbox_name].append(processes_tree)

for sandbox, behaviors in sandbox_behaviors.items():
    print(f"Sandbox: {sandbox}")
    process_counter = Counter()
    for behavior in behaviors:
        for process in behavior:
            process_counter.update([process['name']])
    print(json.dumps(process_counter.most_common(10), indent=4))
