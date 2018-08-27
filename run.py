from modules.yara_module import GithubRules
from modules.elasticsearch_module import ElasticsearchModule
from modules.basic_module import BasicClass

import os
import hashlib

class Yelk(BasicClass):
    def __init__(self):
        super(Yelk, self).__init__()
        self.logger.info("Yelk Module initiated")
        try:
            self.github = GithubRules()
        except Exception as e:
            self.logger.error(e)
            quit()
        try:
            self.es = ElasticsearchModule()
        except Exception as e:
            self.logger.error(e)
            quit()

    def initial_run(self):
        """
        Function to be executed the first time Yelk is executed
        """
        if self.github:
            self.github.obtain_all_rules()
        
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
                self.es.index_item(
                    item=data,
                    index=self.conf['elasticsearch']['rules_index'],
                    id_field='hash_id'
                )
