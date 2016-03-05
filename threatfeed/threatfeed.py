#!/usr/bin/env python

"""ThreatFeed Main Module

"""

import requests
import click

import settings
from .apis.safe_browsing_api import SafeBrowsingAPI
from .apis.phishtank_api import PhishTankAPI
from .apis.dshield_api import DShieldAPI
from .apis.malwr_api import MalwrAPI
from .apis.virustotal_api import VirusTotalAPI


def print_delimiter():
    print("*"*50)

def print_header(ioc_type, content):
    print()
    print_delimiter()
    if ioc_type=='ip':
        type_name = "IP address"
    elif ioc_type=='port':
        type_name = "Port number"
    elif ioc_type=='date':
        type_name = "Timestamp"
    elif ioc_type=='hash':
        type_name = "File hash"
    elif ioc_type=='url':
        type_name = "URL"
    else:
        type_name = "Domain"
    print("Information for {}: {}".format(type_name, content))
    print_delimiter()
    print()


@click.group()
def cli():
    """Query threat report from APIs, or submit for analysis."""



# **************************
#
# Query command

@cli.command(help='Query threat report')
@click.option('--api', type=click.Choice(['ds', 'vt', 'pt', 'sb']),
              multiple=True, help=('Query against specific resources.'
                                   '(ds: DShield API, vt: VirusTotal API, '
                                   'pt: PhishTank API, sb: Safe Browsing API)'))
@click.option('-r', '--raw', is_flag=True, help='Show raw response from remote resources')
@click.option('--type', 'ioc_type', required=True,
              type=click.Choice(['ip', 'port', 'date', 'hash', 'url', 'domain']),
              help=('Specify which type of IOC.'
                                   '(ip: IP address, port: Port number, date: Data, '
                                   'hash: Hash Value, url: URL, domain: Domain)'))
@click.argument('requests', required=True, nargs=-1)
def query(api, raw, ioc_type, requests):
    """Query threat info from local dataset and remote resources

    Accept options and query diffrent resources with different query type.

    """
    for request in requests:
        if ioc_type=='ip':
            r = {'ip': request}
        elif ioc_type=='port':
            r = {'port': request}
        elif ioc_type=='date':
            r = {'timestamp': request}
        elif ioc_type=='url':
            r = {'url': request}
        elif ioc_type=='hash':
            r = {'hash': request}
        else:
            r = {'domain': request}


        print_header(ioc_type, request)
        is_all = not api

        if 'vt' in api or is_all:
            resp = VirusTotalAPI.query(r, raw)
            print(resp)

        if 'pt' in api or is_all:
            resp = PhishTankAPI.query(r, raw)
            print(resp)

        if 'sb'in api or is_all:
            resp = SafeBrowsingAPI.query(r, raw)
            print(resp)

        if 'ds' in api or is_all:
            resp = DShieldAPI.query(r, raw)
            print(resp)


#*********************************************************
# Submit command

@click.option('--api', type=click.Choice(['ds', 'vt', 'pt', 'mw','sb']),
              multiple=True, help=('Submit to remote resources.'
                                   '(ds: DShield API, vt: VirusTotal API, '
                                   'pt: PhishTank API, mw: Malwr API,'
                                   'sb: Safe Browsing API)'))
@cli.command(help='Submit for analysis')
def submit():
    """Submit for analysis

    """
    # TODO
    pass


if __name__ == '__main__':
    cli()
