import requests

from .api import API
from envparse import env


class SafeBrowsingAPI(API):
    """Safe Browsing API

    """

    _name = "Safe Browsing"
    _KEY = env('SAFE_BROWSING')
    _CLIENT  = "threatfeed"
    _APPVER = '0.1'
    _PVER = '3.1'

    def dispatch(self, request):
        if 'url' in request:
            response=self.query_by_url(request['url'])
        else:
            response = None

        return response

    def response(self, r):
        if r.status_code == 200:
            resp = 'URL type: {}'.format(r.text)
        elif r.status_code == 204:
            resp = 'URL type: Ok'
        else:
            resp=''
        return resp


    def query_by_url(self, url):
        request_body = '1\n'+url
        request_url = ('https://sb-ssl.google.com/safebrowsing/api/lookup'
               '?client={}&key={}&appver={}&pver={}'
               .format(self._CLIENT, self._KEY, self._APPVER, self._PVER))
        r = requests.post(request_url, data=request_body)
        return self.response(r)
