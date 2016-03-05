import requests

from .api import API
from envparse import env


class MalwrAPI(API):
    """Malwr API

    """

    def __init__(self):
        self._KEY = env('DSHIELD')
