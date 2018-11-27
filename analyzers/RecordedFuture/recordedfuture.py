#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from cortexutils.analyzer import Analyzer

import urllib.request
import urllib.error
import json
from http import HTTPStatus

class RecordedFutureAnalyzer(Analyzer):
    taxonomy_namespace = 'RF'

    def __init__(self):
        Analyzer.__init__(self)
        self.recordedfuture_key = self.get_param('config.key', None, 'Missing RecordedFuture API key')
        self.proxies = self.get_param('config.proxy', None)

    def summary(self, raw):
        taxonomies = []

        level = 'info'
        predicate = 'score'
        value = '{}/100'.format(raw['data']['risk']['score'])
        criticality = raw['data']['risk']['criticality']
        if criticality == 0:
            level = 'safe'
        elif criticality == 1:
            level = 'info'
        elif criticality == 2:
            level = 'suspicious'
        elif criticality >= 3:
            level = 'malicious'
        taxonomies.append(self.build_taxonomy(level, self.taxonomy_namespace, predicate, value))

        level = 'info'
        predicate = '#evidenceDetails'
        value = str(len(raw['data']['risk']['evidenceDetails']))
        taxonomies.append(self.build_taxonomy(level, self.taxonomy_namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def warning(self, message):
        taxonomies = []
        taxonomies.append(self.build_taxonomy('suspicious', self.taxonomy_namespace, 'warning', message))
        return {"taxonomies": taxonomies}

    def run(self):
        if self.data_type in ['domain', 'ip', 'hash']:
            data = self.get_param('data', None, 'Data is missing')
            url = 'https://api.recordedfuture.com/v2/{}/{}?fields=risk%2CintelCard'.format(self.data_type, data)
            req = urllib.request.Request(url, None, {'X-RFToken': self.recordedfuture_key})
            try:
                with urllib.request.urlopen(req) as res:
                    j = json.loads(res.read().decode("utf-8"))
                    return self.report(j)
            except urllib.error.HTTPError as e:
                if e.code == HTTPStatus.NOT_FOUND:
                    warning = self.warning('na (404)')
                    report = {
                        'success': True,
                        'summary': warning,
                        'artifacts': None,
                        'full': {
                            'warning': True,
                            'type': 404,
                            'message': str(e),
                            'url': url
                        }
                    }
                    return json.dump(report, self.fpoutput, ensure_ascii=False)
                else:
                    return self.error(str(e))
            except urllib.error.URLError as e:
                return self.error(str(e))
        else:
            return self.error('Invalid data type')

if __name__ == '__main__':
    RecordedFutureAnalyzer().run()
