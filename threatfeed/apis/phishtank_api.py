import requests

from .api import API
from envparse import env


class PhishTankAPI(API):
    """PhishTank API

    """

    _name = "PhishTank API"
    _KEY = env('PHISHTANK')

    def dispatch(self, request):
        if 'url' in request:
            response=self.query_by_url(request['url'])
        else:
            response = None

        return response

    def response(self, r):
        if self._require_raw:
            return r.text
        if r.status_code == 200:
            r = r.json()
            if r['results']['in_database']:
                resp = (
                    'Phish ID: {}\nPhish detail page: {}\nVerified: {}\nVerified at: {}').format(
                        r['results']['phish_id'], r['results']['phish_detail_page'],
                        r['results']['verified'], r['results']['verified_at'][:10],)
            else:
                resp = (
                    'In database: {}').format(
                        r['results']['in_database'])
        else:
            resp=''
        return resp


    def query_by_url(self, url):
        request_body = {'url': url, 'format': 'json', 'app_key': self._KEY}
        request_url = 'http://checkurl.phishtank.com/checkurl/'
        r = requests.post(request_url, data=request_body)
        return self.response(r)
