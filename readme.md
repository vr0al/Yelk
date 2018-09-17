# Yelk (In Development)

Yara -> Elasticsearch -> Kibana. Tool for automating large scale scanning and archiving of binary files.

# Functionality

This tool aims to allow analysts quick access to a persistent database of Yara scan results with the ability to produce interesting dashboards via Kibana.
It allows an analyst to scan a large number of files with a large set of publicly-available Yara rules and then ingest the results into Elasticsearch (along with limited, useful metadata such as hashes, filesize, filename etc.). This aims to overcome one of the primary issues many face with using Yara; that results are temporary and difficult to correlate to past scans.
This tool handles downloading publicly-available Yara rules from Github e.g. Florian Roth's (Neo23x0) public repository of Yara rules, which is a good start for analysts looking to determine whether a given file is 'known' malware. This tool will also seek to leverage Florian Roth's publicly-available YarGen tool (https://github.com/Neo23x0/yarGen) to produce additional Yara rules for new samples.

The aim is to allow analysts not only to determine whether a specific sample produces positive matches from specific Yara rules but to form a basic (albeit limited) framework for the creation of new Yara rules and allow for trend-level analysis such as code overlap between apparently-distinct malware samples. Since this tool uses Elasticsearch to store rules and results, it is possible for multiple analysts to share a single ELK cluster and therefore share results and rules. In itself, this can be a highly useful resource.

This tool is very much in-development but the overall goal is for the entire framework to dockerised and installable via a single command. Samples and Yara rules could then be added to their respective directories and scans conducted automatically or upon user instruction.

# v1.0 Checklist

- [x] Download public Yara rules via Github API
- [x] Store rules locally and within Elasticsearch index
- [x] Compile Yara rules into rules object, allowing for scanning via Yara-python
- [x] Find Yara rule matches in sample files
- [x] Parse and enrich Yara rule matches
- [x] Store enriched results in Elasticsearch index
- [x] Enable multiple runmodes to enable setup, file-specific scans, and general scans

# v.1.1 Checklist

- [ ] Implement cross-project logging
- [ ] Enable externally-defined variables to be passed to Yara rules
- [ ] Add YarGen functionality for the creation of basic rules upon execution of overall module
- [ ] Add pulling of rulesets from Elasticsearch
- [ ] Create dockerfile to encompass installation and configuration of overall tool

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

# Development Notes

This project uses a modular structure with specific classes for elasticsearch, yara, github etc. These all inherit a variety of objects and functions from the overall basic_module such as access to a shared configuration file and logging. This helps keep the project clearly structured and allows for specific features to be added to project-wide classes.