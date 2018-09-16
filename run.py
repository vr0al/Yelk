from modules.yara_module import GithubRules, YaraRules
from modules.elasticsearch_module import ElasticsearchModule
from modules.basic_module import BasicClass

import os
import hashlib
import sys

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
        if self.es:
            self.index_rules()
    
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

    def index_matches_in_all_files(self):
        """
        Wrapping function to enumerate all samples in sample directory and index rule matches in Elasticsearch
        """
        try:
            self.samples = self.enumerate_samples()
        except Exception as e:
            print(e)
        count = 0
        if self.samples:
            for sample in self.samples:
                print("Indexing {}".format(sample))
                self.index_matches(sample=sample)
                count += 1
            print("Attempted to find Yara rule matches against {} files".format(count))
        else:
            print("No self.samples")

    def enumerate_samples(self):
        """
        Function which produces a list of file names in the specified samples directory
        Returns:
            samples: list, filepaths to all files in samples directory
        """
        samples = []
        for file_name in os.listdir(self.conf['samples']['directory']):
            samples.append("{}/{}".format(
                self.conf['samples']['directory'],
                file_name
            ))
        return samples
    
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
                # User-readable strings containing rule name: variable name
                #   and sample name: line number
                data['rule_var_matches'] = []
                data['sample_loc_matches'] = []
                data['raw_string_matches'] = []
                data['string_match_vars'] = []
                data['string_match_locs'] = []
                for triple in item.strings:
                    data['rule_var_matches'].append("{}:{}".format(item.rule, triple[1]))
                    data['sample_loc_matches'].append("{}:{}".format(sample, triple[0]))
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

        else:
            print("No matches found")
        

if __name__ == "__main__":
    if sys.argv[1]:
        pass
    else:
        print("Please input a runmode argument")
    if sys.argv[1] == "help":
        print("Runmodes:")
        print("--fetch: Will fetch all rules from Github and save in rules directory")
        print("--file filepath: Runs against a specific file")
        print("--all: Runs against all files in the samples directory")
    elif sys.argv[1] == "--fetch":
        y = Yelk()
        y.initial_run()
    elif sys.argv[1] == "--file":
        y = Yelk()
        y.index_matches(sample=sys.argv[2])
    elif sys.argv[1] == "--all":
        y = Yelk()
        y.index_matches_in_all_files()