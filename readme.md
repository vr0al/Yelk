#YElK

Yara -> Elasticsearch -> Kibana. Tool for automating large scale scanning and archiving of binary files.

#Functionality

Uses a variety of Yara rules to scan a large number of files. For each rule, record any positive matches and log to Elasticsearch.

# TODO

Resolve issue where externally-defined variables are causing the compilation of Yara rules to crash

# Installation

Docker containers for Elasticsearch, Kibana, Yara
Install Python dependencies e.g. elasticsearch, pyyaml, Yara

To fetch initial set of rules from Github: python run.py --fetch
To run against a specific file: python run.py --file filepath (where filepath is the location of the file to be scanned)
To run against all samples in the specified samples directory: python run.py --all

# Startup

sudo docker ps -a (list all containers)
sudo docker restart dockerelk_elasticsearch_1
sudo docker restart dockerelk_kibana_1