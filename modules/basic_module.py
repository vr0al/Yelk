import logging
import yaml

class BasicClass(object):
    def __init__(self):
        self.logger = logging.getLogger(name=__name__)
        self.logger.info("BasicClass instance initiated")
        with open("settings.yaml", 'r') as stream:
            try:
                self.conf = yaml.load(stream)
            except yaml.YAMLError as e:
                self.logger(e)