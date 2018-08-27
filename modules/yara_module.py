from github import Github
from time import sleep

from basic_module import BasicClass

import requests
import base64
import yara
import os

"""
Simple class for obtaining a large number of open-source Yara rules
Usage:
    Initiate class, either execute obtain_all_rules() function to get everything or collect a specific set of rules
    using the download_rule_directory() function with a Github directory url
TODO Add more Yara rule sources
"""

class YaraCompiler(BasicClass):
    def __init__(self):
        super(YaraCompiler, self).__init__()
        self.rules_dir = self.conf['rules']['directory']
    
    def compile_rules(self, includes=False):
        """
        Basic function for iterating through the rules directory and compiling all rules
        Args:
            includes: Boolean, enable if you want includes statements in yara rules to be included
        """
        yara_files = {}
        count = 1

        for file_name in os.listdir(self.rules_dir):
            if file_name[:-4] == ".yar":
                yara_files["file_{}".format(count)] = "{}/{}".format(self.rules_dir, file_name)
                count += 1
            else:
                self.logger.info("Non-.yar file detected, excluding: {}".format(file_name))
        self.rules = yara.compile(filepaths=yara_files, includes=includes)

class GithubRules(BasicClass):
    def __init__(self):
        super(GithubRules, self).__init__()
        self.api_key = self.conf['github_api']['api_key']
        self.roth_yara = "https://api.github.com/repos/Neo23x0/signature-base/git/trees/master?access_token={}&recursive=1".format(self.api_key)
        try:
            self.github_api = Github(self.api_key)
            print("Github API initiated")
        except Exception as e:
            print("Error encountered initiating Github API: {}".format(e))
            quit()
    
    def obtain_all_rules(self):
        """
        Function for downloading all rulesets and storing them within the /rules directory 
        """
        print("Downloading all rules")
        self.download_rule_directory(url=self.roth_yara)
        print("Finished")

    def download_rule_directory(self, url):
        """
        Function for downloading a variety of different .yar rule files from a specific Github directory and storing
        Args:
            url: String, the directory url
        """
        # Use the contents endpoint to enumerate all files in directory
        print("Enumerating rules within repository")
        res = self.send_request(url=url)
        # Checks if the enumerated file is within the yara/ subdirectory
        file_url_list = []
        for item in res.json()['tree']:
            if "yara/" in item['path']:
                temp = {}
                temp['path'] = item['path']
                temp['url'] = item['url']
                file_url_list.append(temp)
        for rule in file_url_list:
            auth_url = rule['url'] + "?access_token={}".format(self.api_key)
            rule_content = self.download_rule(auth_url)
            if rule_content and "vendor/yara/" in rule['path']:
                name=rule['path'].split("vendor/yara/")[1]
                self.store_rule(
                    name=name,
                    content=rule_content
                )
                print("Stored rule: {}".format(name))
            elif rule_content:
                name=rule['path'].split("/")[1]
                self.store_rule(
                    name=name,
                    content=rule_content
                )
                print("Stored rule: {}".format(name))
            sleep(1)

    def download_rule(self, url):
        """
        Single function for downloading a file from Github via API
        Args:
            url: file url
        Returns:
            file: String, raw file as Python string
        """
        res = self.send_request(url)
        if res:
            b64_contents = res.json()['content']
            contents = base64.b64decode(b64_contents)
            return contents
        else:
            return None

    def store_rule(self, name, content):
        """
        Accepts a single rule and stores it within the /rules directory
        Args:
            rule: String, raw file as Python string
        """
        output_file = "rules/{}".format(name)
        with open(output_file, "w") as outfile:
            outfile.write(content)

    def send_request(self, url):
        try:
            res = requests.get(url)
        except Exception as e:
            print("Error encountered: {}".format(e))
        if res.status_code == 200:
            pass
        else:
            print("Error connecting: Error code {}".format(res.status_code))
            return None

        return res