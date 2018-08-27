from basic_module import BasicClass

import elasticsearch

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
        