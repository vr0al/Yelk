import sys
import yaml
import yara
import os

with open("settings.yaml", 'r') as stream:
    try:
        conf = yaml.load(stream)
    except yaml.YAMLError as e:
        print(e)

if conf:
    rules_dir = conf['rules']['directory']
    samples_dir = conf['samples']['directory']
else:
    print("No settings.yaml found, please create")
    quit()


yara_files = {}
count = 1
for file_name in os.listdir(rules_dir):
    if file_name[-4:] == ".yar":
        yara_files["file_{}".format(count)] = "{}/{}".format(rules_dir, file_name)
        count += 1
    else:
        print("Non-.yar file detected, excluding: {}".format(file_name))
rules = yara.compile(filepaths=yara_files, includes=False)

samples = []
for file_name in os.listdir(samples_dir):
    if file_name == "__init__.py":
        print("Excluding __init__.py")
    else:
        full = "{}/{}".format(samples_dir, file_name)
        samples.append(full)

for sample in samples:
    matches = rules.match(sample)
    print(matches)