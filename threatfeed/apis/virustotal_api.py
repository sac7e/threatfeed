import requests

from .api import API
from envparse import env


class VirusTotalAPI(API):
    """Virustotal API

    """

    _name = "VirusTotal"
    _KEY = env('VIRUSTOTAL')

    def dispatch(self, request):
        if 'url' in request:
            response=self.query_by_url(request['url'])
        elif 'hash' in request:
            response=self.query_by_hash(request['hash'])
        elif 'ip' in request:
            response=self.query_by_ip(request['ip'])
        elif 'domain' in request:
            response=self.query_by_domain(request['domain'])
        else:
            response = None

        return response

    def response(self, r):
        if self._require_raw:
            return r.text
        if r.status_code == 200:
            r = r.json()
            if r['response_code']==1:
                if 'md5' in r or 'url' in r:
                    resp = (
                        'Positives: {}\nTotal: {}\nScan date: {}\nPermalink: {}').format(
                            r['positives'], r['total'],
                            r['scan_date'][:10], r['permalink'],)
                elif 'detected_urls' in r:
                    resp = (
                        'Detected URLs: {}').format(r['detected_urls'],)
                else:
                    pass
            elif r['response_code']==-2:
                resp = 'The requested item is still queued for analysis.'
            else:
                resp = ''
        elif r.status_code == 204:
            resp='Wait one minite for more requests'
        else:
            resp = ''
        return resp

    def query_by_hash(self, hash):
        request_body = {'resource': hash, 'apikey': self._KEY}
        request_url = 'https://www.virustotal.com/vtapi/v2/file/report'
        r = requests.post(request_url, data=request_body)
        return self.response(r)

    def query_by_url(self, url):
        request_body = {'resource': url, 'apikey': self._KEY}
        request_url = 'https://www.virustotal.com/vtapi/v2/url/report'
        r = requests.post(request_url, data=request_body)
        return self.response(r)

    def query_by_ip(self, ip):
        payload = {'ip': ip, 'apikey': self._KEY}
        request_url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        r = requests.get(request_url, params=payload)
        return self.response(r)

    def query_by_domain(self, domain):
        payload = {'domain': domain, 'apikey': self._KEY}
        request_url = 'https://www.virustotal.com/vtapi/v2/domain/report'
        r = requests.get(request_url, params=payload)
        return self.response(r)
