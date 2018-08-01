#!/usr/bin/env python3

import os
import time
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

CONFIG = None
HOME_DIR = os.path.realpath(os.path.dirname(__file__))

logging_config_path = os.path.join(HOME_DIR, 'etc', 'logging.ini')
logging.config.fileConfig(logging_config_path)
logger = logging.getLogger('url_click')
logger.setLevel(logging.DEBUG)

import json
from datetime import datetime, timedelta
import subprocess

''' TODO: remove subprocess, and use splunklib to perform the splunk search '''
def search_splunk(config_path, search_path):
    logger.info('Searching for CB command line URLs in Splunk with search: {}'.format(config_path))

    clicks = []

    #start_time = (datetime.now() - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")

    start_time = '2018-07-11 08:20:05'
    end_time = '2018-07-11 08:50:05'

    try:
        results = subprocess.check_output(['/opt/splunklib/splunk', '-i', '-s', start_time, '-e', end_time, '-c', config_path, '--search-file', search_path, '--json']).decode('utf-8')
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

# load lib/ onto the python path
sys.path.append('lib')

from saq.client import Alert

def create_ace_alert(click):
    logger.info("here we create an ace alert")
    alert = Alert(
        tool='url_click',
        tool_instance='Cb cmdline URL Cloudphish checker',
        alert_type='splunk - cb - cloudphish',
        desc='URL Click',
        event_time=time.strftime("%Y-%m-%d %H:%M:%S"),
        details=event_grouping[key_value],
        name='URL Click',
        company_name=CONFIG['ace']['company_name'],
        company_id=CONFIG['ace'].getint('company_id'))

    tags = ['cloudphish_detection','cb_cmdline']
    for tag in tags:
        alert.add_tag(tag)

    alert.add_observable('process_guid', click['process_guid'])
    alert.add_observable('hostname', click['hostname'])
    alert.add_observable('user', click['user'])
    alert.add_observable('url', click['url'])

    try:
        logging.info("submitting alert {}".format(alert.description))
        alert.submit(CONFIG['ace']['uri'], CONFIG['ace']['key'])
    except Exception as e:
        logging.error("unable to submit alert {}: {}".format(alert, str(e)))

    return

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
        logger.info("{} clicks to process".format(len(clicks)))
        for click in clicks:
            result = cp.submit(click['url'])
            logger.debug("{} - {} - {} - {}".format(result['status'], result['analysis_result'], result['http_message'], click['url']))
            if result['analysis_result'] == 'UNKNOWN' and result['status'] == 'NEW':
                # cloudphish is still working on this one
                continue
            elif result['analysis_result'] == 'ALERT':
                create_ace_alert(click)
            else:
                logger.info("removing {} from the queue".format(click['url']))
                clicks.remove(click)

        # if we're still waiting for cloudphish results for some clicks, give cloudphish 5 seconds
        if len(clicks) > 0:
            time.sleep(5)


from configparser import ConfigParser

# load the config
config_path = os.path.join(HOME_DIR, 'etc', 'config.ini')
CONFIG = ConfigParser()
CONFIG.read(config_path)

search_name = CONFIG.get('url_click', 'splunk_search')
search_path = os.path.join(HOME_DIR, 'etc', search_name)


results = search_splunk(config_path, search_path)

from cloudphishlib import cloudphish


# ignore the proxy
if 'https_proxy' in os.environ:
    del os.environ['https_proxy']

check_cloudphish(results)

#cp = cloudphish()

'''
print(cp.clear('http://newslmemorialschool.com/adminstrator/index.htm'))
print(cp.get('6FD093AF3E00D13A13BC3AD3FD64459D20BA20826777E6F9C7B073AABCCB1649'))
print(cp.clear('https://1drv.ms/b/s!AlYlCBTNU8uKgXeQfpyMyfECq6JG'))
print(cp.get('6FD093AF3E00D13A13BC3AD3FD64459D20BA20826777E6F9C7B073AABCCB1649'))


for result in results:
      print(cp.submit(result['url']))
      break
'''
