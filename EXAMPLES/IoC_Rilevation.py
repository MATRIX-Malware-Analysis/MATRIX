from elasticsearch import Elasticsearch
from collections import Counter
import json

# Connessione a Elasticsearch
es = Elasticsearch(
    hosts=[{
        'host': 'localhost',
        'port': 9200,
        'scheme': 'http'
    }]
)

# Query per ottenere IoC nei documenti
query = {
    "query": {
        "exists": {
            "field": "data.attributes"
        }
    },
    "_source": ["data.attributes"]
}

# Esegui la query
response = es.search(index="malware_reports", body=query, size=10000)

# Conta le occorrenze di diversi IoC
ioc_counters = {
    "files_opened": Counter(),
    "files_written": Counter(),
    "calls_highlighted": Counter(),
    "ip_traffic": Counter(),
    "modules_loaded": Counter()
}

for hit in response['hits']['hits']:
    data_list = hit['_source'].get('data', [])
    for data_item in data_list:
        attributes = data_item.get('attributes', {})
        for ioc_type in ioc_counters:
            ioc_values = attributes.get(ioc_type, [])
            if ioc_type == 'ip_traffic':
                ips = []
                for value in ioc_values:
                    #print(f"IP: {value['destination_ip']}")
                    ip = value['destination_ip']
                    ips.append(ip)
                ioc_counters[ioc_type].update(ips)
            else:
                ioc_counters[ioc_type].update(ioc_values)

# Stampa i top 10 IoC per ciascun tipo
for ioc_type, counter in ioc_counters.items():
    print(f"Top 10 {ioc_type.replace('_', ' ').title()}:")
    print(json.dumps(counter.most_common(10), indent=4))
