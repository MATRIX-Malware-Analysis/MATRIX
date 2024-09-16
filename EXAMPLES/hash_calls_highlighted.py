from elasticsearch import Elasticsearch
from collections import defaultdict, Counter
import json
import time
es = Elasticsearch(
    hosts=[{
        'host': 'localhost',
        'port': 9200,
        'scheme': 'http'
    }]
)

query = {
    "query": {
        "bool": {
            "must": [
                {"exists": {"field": "data.attributes.mitre_attack_techniques.id"}},
                {"exists": {"field": "data.attributes.calls_highlighted"}},
            ]
        }
    },
    "_source": ["data.id", "data.attributes.mitre_attack_techniques.id", "data.attributes.calls_highlighted"]
}

start_time = time.time()
response = es.search(index="malware_reports", body=query, size=10000)

technique_to_calls_counter = defaultdict(Counter)

for hit in response['hits']['hits']:
    data_list = hit['_source'].get('data', [])
    for data_item in data_list:
        mitre_techniques = data_item.get('attributes', {}).get('mitre_attack_techniques', [])
        calls_highlighted = data_item.get('attributes', {}).get('calls_highlighted', [])
        
        for technique in mitre_techniques:
            technique_id = technique.get('id')
            if technique_id:
                for call in calls_highlighted:
                    technique_to_calls_counter[technique_id].update([call])

results = {}
for technique, counter in technique_to_calls_counter.items():
    total = sum(counter.values())
    percentages = {key: f"{(count / total) * 100:.2f}%" for key, count in counter.items()}
    results[technique] = percentages

end_time = time.time()
print("MITRE ATT&CK Techniques e Calls Highlighted correlati:")
print(json.dumps(results, indent=4))

with open("technique_to_calls_correlations.json", "w") as f:
    json.dump(results, f, indent=4)


final_time = end_time - start_time

print(f'Final Time -> {final_time}')
