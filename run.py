from modules.yara_module import GithubRules, YaraRules
from modules.elasticsearch_module import ElasticsearchModule
from modules.basic_module import BasicClass

import os
import hashlib

class Yelk(BasicClass):
    def __init__(self):
        super(Yelk, self).__init__()
        #self.logger.info("Yelk Module initiated")
        try:
            self.github = GithubRules()
        except Exception as e:
            #self.logger.error(e)
            print(e)
            quit()
        try:
            self.es = ElasticsearchModule()
        except Exception as e:
            #self.logger.error(e)
            print(e)
            quit()
        try:
            self.yara_rules = YaraRules()
            self.yara_rules.compile_rules()
        except Exception as e:
            print(e)
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
    
    def index_matches(self, sample):
        # TODO use the externals dictionary to pass filename, filepath etc.
        try:
            matches = self.yara_rules.find_rule_matches(sample=sample)
        except Exception as e:
            print(e)
        
        if matches:
            for item in matches:
                data = {}
                data['rule'] = item.rule
                data['namespace'] = item.namespace
                data['tags'] = item.tags
                data['meta'] = item.meta
                #data['string_matches'] = item.strings
                data['raw_string_matches'] = []
                data['string_match_vars'] = []
                data['string_match_locs'] = []
                for triple in item.strings:
                    data['raw_string_matches'].append(triple[2])
                    data['string_match_vars'].append(triple[1])
                    data['string_match_locs'].append(triple[0])
                data['filename'] = sample
                data['hash_id'] = hashlib.sha256("{}{}".format(item.rule, sample)).hexdigest()

                self.es.index_item(
                    item=data,
                    index="yara_positive_matches",
                    id_field="hash_id"
                )

        #if matches:
        #    print(matches)
        else:
            print("No matches found")
        

y = Yelk()
print("Initiated Yelk")
y.index_matches(sample="/home/ubuntu/Yelk/samples/sample_file.exe")
