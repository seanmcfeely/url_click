#!/usr/bin/env python3

import os
import logging, logging.config
'''
1. Import splunk search and SearchDaemon it
2. Modify the hunt to comply with our normal splunk hunt formats (ini & search file)
3. set up directory structure
4. Create method for submiting the hunt search results to cloudphish. User the requests library
    4.1. Alert on cloudphish 'ALERT' results
    4.2. Wait/query loop cloudphish for 'UNKNOWN' results
    4.3. Write error is cloudphis returns error
5. Log everything
'''

HOME_DIR = os.path.realpath(os.path.dirname(__file__))

logging_config_path = os.path.join(HOME_DIR, 'etc', 'logging.ini')
logging.config.fileConfig(logging_config_path)
logger = logging.getLogger()
logger.setLevel(logging.INFO)

import json
from datetime import datetime, timedelta
import subprocess

def search_splunk(config_path, search_path):
    logger.info('Searching for CB command line URLs in Splunk with search: {}'.format(config_path))

    clicks = []

    start_time = (datetime.now() - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
    print(start_time)

    try:
        results = subprocess.check_output(['/opt/splunklib/splunk', '-i', '-s', start_time, '-c', config_path, '--search-file', search_path, '--json']).decode('utf-8')
    except:
        logger.exception('Unable to query Splunk.')

    # Try converting the results to JSON.
    try:
        j = json.loads(results)
    except:
        logger.exception('Unable to convert Splunk results to JSON.')

    # Loop over the carbonblack process results.
    for cb_proc in j['result']:

        details = {'url': cb_proc['clicked_url'],
                   'hostname': cb_proc['computer_name'],
                   'process_guid': cb_proc['process_guid'],
                   'company': cb_proc['company'],
                   'domain': cb_proc['dest_nt_domain'],
                   'user': cb_proc['user']}
        
        clicks.append(details)

    return clicks


def ace_alert(tbd):
    logger.info("here we create an ace alert")
    pass

'''
{
    "analysis_result": "PASS",
    "details": null,
    "file_name": null,
    "http_message": "COMMON_NETWORK",
    "http_result": null,
    "location": null,
    "result": "OK",
    "sha256_content": null,
    "status": "ANALYZED"
}
'''
def check_cloudphish(clicks):
    cp = cloudphish()

    while clicks:
        for click in clicks:
            print(str(len(clicks)))
            result = cp.submit(click['url'])
            #logger.debug("{} - {} - {} - {}".format(result['status'], result['analysis_result'], result['http_message'], click['url']))
            if result['analysis_result'] == 'UNKNOWN' and result['status'] == 'NEW':
                # cloudphish is still working on this one
                continue
            elif result['analysis_result'] == 'ALERT':
                create_ace_alert(click)
            else:
                logger.info("removing {} from the queue".format(click['url']))
                clicks.remove(click)


from configparser import ConfigParser

config_path = os.path.join(HOME_DIR, 'etc', 'config.ini')
config = ConfigParser()
config.read(config_path)

search_name = config.get('url_click', 'splunk_search')
search_path = os.path.join(HOME_DIR, 'etc', search_name)


results = search_splunk(config_path, search_path)

from cloudphishlib import cloudphish


# ignore the proxy
del os.environ['https_proxy']

check_cloudphish(results)

'''
for result in results:
      print(cp.submit(result['url']))
      break
'''
