from basic_module import BasicClass

import elasticsearch
import os
import hashlib

class ElasticsearchModule(BasicClass):
    def __init__(self):
        super(ElasticsearchModule, self).__init__()
        self.elasticsearch_rules_index = self.conf['elasticsearch']['rules_index']
        self.elasticsearch_samples_index = self.conf['elasticsearch']['samples_index']
        self.elasticsearch_host = self.conf['elasticsearch']['host']
        self.elasticsearch_port = self.conf['elasticsearch']['port']
        self.es = elasticsearch.Elasticsearch()

    def index_item(self, item, index, id_field=None):
        """
        Basic function for indexing a single object to an index
        """
        if id_field:
            try:
                self.es.index(
                    index=index,
                    body=item,
                    id=item[id_field],
                    doc_type="data"
                )
            except Exception as e:
                print(e)
        else:
            try:
                self.es.index(
                    index=index,
                    body=item,
                    doc_type="data"
                )
            except Exception as e:
                print(e)
        
    def index_rules(self):
        """
        Function which indexes all rules within rules_dir to elasticsearch
        """
        for file_name in os.listdir(self.conf['rules']['directory']):
            if ".yar" in file_name:
                data = {}
                file_loc = "rules/{}".format(file_name)
                with open(file_loc, "r") as yara_file:
                    rule =  yara_file.read()
                data['rule'] = rule
                data['rule_name'] = file_name
                data['hash_id'] = hashlib.sha256(file_name + rule).hexdigest()
                self.index_item(
                    item=data,
                    index=self.conf['elasticsearch']['rules_index'],
                    id_field='hash_id'
                )