#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from cortexutils.analyzer import Analyzer

import requests
import json
from http import HTTPStatus

class PacketTotalAnalyzer(Analyzer):
    taxonomy_namespace = 'PcapT'
    malicious_categories = ['signature_alerts']
    suspicious_categories = ['notice', 'intel', 'weird']

    def __init__(self):
        Analyzer.__init__(self)
        self.packettotal_key = self.get_param('config.key', None, 'Missing PacketTotal API key')
        self.proxies = self.get_param('config.proxy', None)

    def summary(self, raw):
        taxonomies = []

        # level = 'info'
        # predicate = 'matches'
        # value = raw['result_count']
        # level = 'info'
        # taxonomies.append(self.build_taxonomy(level, self.taxonomy_namespace, predicate, value))

        categories = raw['categories']
        predicate = 'categories'
        value = '/'.join(c['name'] for c in categories)
        if any(c['name'] in self.malicious_categories for c in categories):
            level = 'malicious'
        elif any(c['name'] in self.suspicious_categories for c in categories):
            level = 'suspicious'
        else:
            level = 'info'
        taxonomies.append(self.build_taxonomy(level, self.taxonomy_namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def extract_categories(self, results):
        categories = []
        for result in results:
            for category in result['found_in']:
                if category not in categories:
                    categories.append(category)
        return categories

    def warning(self, message):
        taxonomies = []
        taxonomies.append(self.build_taxonomy('info', self.taxonomy_namespace, '', message))
        return {"taxonomies": taxonomies}

    def run(self):
        if self.data_type in ['domain', 'ip', 'hash']:
            data = self.get_param('data', None, 'Data is missing')
            url = 'https://api.packettotal.com/v1/search?query={}'.format(data)
            try:
                res = requests.get(url, headers={'x-api-key': self.packettotal_key})
                res.raise_for_status()
                j = res.json()
                j['query'] = data
                categories = []
                for category_name in self.extract_categories(j['results']):
                    if category_name in self.malicious_categories:
                        level = 'malicious'
                    elif category_name in self.suspicious_categories:
                        level = 'suspicious'
                    else:
                        level = 'info'
                    categories.append({'name': category_name, 'level': level})
                j['categories'] = categories
                for result in j['results']:
                    categories = []
                    for category_name in result['found_in']:
                        if category_name in self.malicious_categories:
                            level = 'malicious'
                        elif category_name in self.suspicious_categories:
                            level = 'suspicious'
                        else:
                            level = 'info'
                        categories.append({'name': category_name, 'level': level})
                    result['found_in'] = categories
                return self.report(j)
            except requests.exceptions.RequestException as e:
                return self.error(str(e))
        else:
            return self.error('Invalid data type')

if __name__ == '__main__':
    PacketTotalAnalyzer().run()
