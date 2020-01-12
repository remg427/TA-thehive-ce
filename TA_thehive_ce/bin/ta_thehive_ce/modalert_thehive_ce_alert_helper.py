
# encoding = utf-8
#!/usr/bin/env python
# Generate TheHive alerts
#
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made

#    autonomous-system
#    domain
#    file
#    filename
#    fqdn
#    hash
#    ip
#    mail
#    mail_subject
#    other
#    regexp
#    registry
#    uri_path
#    url
#    user-agent

# most of the code here was based on the following example on splunk custom alert actions
# http://docs.splunk.com/Documentation/Splunk/6.5.3/AdvancedDev/ModAlertsAdvancedExample

import csv
import gzip
import json
import os
import re
import requests
import time
#from splunk.clilib import cli_common as cli
from splunklib.searchcommands import validators
import splunklib.client as client

__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "1.0.0"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"


def create_datatype_lookup():
    # if it does not exist, create thehive_datatypes.csv
    _SPLUNK_PATH = os.environ['SPLUNK_HOME']
    directory = _SPLUNK_PATH + os.sep + 'etc' + os.sep + 'apps' \
        + os.sep + 'TA_thehive_ce' + os.sep + 'lookups'
    thehive_datatypes = directory + os.sep + 'thehive_datatypes.csv'
    if not os.path.exists(thehive_datatypes):
        # file thehive_datatypes.csv doesn't exist. Create the file
        observables = [['field_name', 'datatype', 'regex', 'description'],
                       ['autonomous-system', 'autonomous-system', '', ''],
                       ['domain', 'domain', '', ''],
                       ['filename', 'filename', '', ''],
                       ['fqdn', 'fqdn', '', ''],
                       ['hash', 'hash', '', ''],
                       ['ip', 'ip', '', ''],
                       ['mail', 'mail', '', ''],
                       ['mail_subject', 'mail_subject', '', ''],
                       ['other', 'other', '', ''],
                       ['regexp', 'regexp', '', ''],
                       ['registry', 'registry', '', ''],
                       ['uri_path', 'uri_path', '', ''],
                       ['url', 'url', '', ''],
                       ['user-agent', 'user-agent', '', '']
                       ]
        try:
            if not os.path.exists(directory):
                os.makedirs(directory)
            with open(thehive_datatypes, 'wb') as file_object:
                csv_writer = csv.writer(file_object, delimiter=',')
                for observable in observables:
                    csv_writer.writerow(observable)
        except IOError:
            helper.log_error("FATAL {} could not be opened in write \
                mode".format(thehive_datatypes))


def prepare_alert_config(helper):
    config_args = dict()
    # get TheHive instance to be used
    th_instance = helper.get_param("th_instance")
    # open lookups/thehive_instance_list.csv
    _SPLUNK_PATH = os.environ['SPLUNK_HOME']
    app_name = "TA_thehive_ce"
    csv_instance_list = _SPLUNK_PATH + os.sep + 'etc' + os.sep + 'apps' \
        + os.sep + app_name + os.sep + 'lookups' \
        + os.sep + 'thehive_instance_list.csv'
    if os.path.exists(csv_instance_list):
        helper.log_info("File {} exists".format(csv_instance_list))
        # file exists - try to open it; fail gracefully
        try:
            with open(csv_instance_list, 'r') as th_list:
                # DictReader lets us grab the first row as a header row
                # and other lines will read as a dict mapping the header
                # to the value
                Reader = csv.DictReader(th_list)
                helper.log_debug("Reader is {}".format(Reader))
                found_instance = False
                for row in Reader:
                    if found_instance is False and \
                       'thehive_instance' in row and \
                       'thehive_url' in row and \
                       'thehive_api_key_name' in row and \
                       'thehive_verifycert' in row and \
                       'thehive_ca_full_path' in row and \
                       'thehive_use_proxy' in row and \
                       'client_use_cert' in row and \
                       'client_cert_full_path' in row:
                        if row['thehive_instance'] == th_instance:
                            found_instance = True
                            th_url = row['thehive_url']
                            # validate that the url starts with 'https://' 
                            # requirement for Cloud Edition
                            match = re.match("^https:\/\/[0-9a-zA-Z\-\.]+(?:\:\d+)?", th_url)
                            if match is None:
                                helper.log_error("FATAL thehive_url does not start with 'https://'; \
                                    Please edit thehive_instance_list.csv to fix this.")
                                return None                                
                            if th_url.endswith('/'):
                                config_args['thehive_url'] = th_url + 'api/alert'
                            else:
                                config_args['thehive_url'] = th_url + '/api/alert'
                            helper.log_info("config_args['thehive_url'] {}".format(config_args['thehive_url']))
                            api_key_name = row['thehive_api_key_name']
                            if api_key_name in ['thehive_api_key1', 'thehive_api_key2', 'thehive_api_key3']:
                                helper.log_info("api_key_name {}".format(api_key_name))
                            else:
                                api_key_name = None
                                helper.log_error("api_key_name must be 'thehive_api_key1' or 2 or 3")
                            if row['thehive_verifycert'] == 'True' or row['thehive_verifycert'] == 'true':
                                thehive_ca_full_path = row['thehive_ca_full_path']
                                if thehive_ca_full_path != '':
                                    config_args['thehive_verifycert'] = thehive_ca_full_path
                                    helper.log_info("config_args['thehive_ca_full_path'] {}".format(config_args['thehive_ca_full_path']))
                                else:
                                    config_args['thehive_verifycert'] = True
                            else:
                                config_args['thehive_verifycert'] = False
                            helper.log_info("config_args['thehive_verifycert'] {}".format(config_args['thehive_verifycert']))
                            # get client cert parameters
                            if row['client_use_cert'] == 'True' or row['client_use_cert'] == 'true':
                                config_args['client_cert_full_path'] = row['client_cert_full_path']
                            else:
                                config_args['client_cert_full_path'] = None
                            helper.log_info("config_args['client_cert_full_path'] {}".format(config_args['client_cert_full_path']))
                            if row['thehive_use_proxy'] == 'True' or row['thehive_use_proxy'] == 'true':
                                use_proxy = True
                            else:
                                use_proxy = False
                            helper.log_info("use_proxy {}".format(use_proxy))
        # something went wrong with opening the results file
        except IOError:
            helper.log_error("FATAL thehive_instance_list.csv exists \
                but could not be opened/read")
            return None
    else:
        helper.log_error("lookups/thehive_instance_list.csv does not exist. \
            Please check install instructions \
            https://github.com/remg427/TA_thehive_ce.")
        return None
    # get clear version of thehive_key
    # get session key
    sessionKey = helper.settings['session_key']
    splunkService = client.connect(token=sessionKey)
    storage_passwords = splunkService.storage_passwords
    config_args['thehive_key'] = None
    # from the thehive_api_key defined in the lookup table
    # securely retrive the API key value from storage_password
    for credential in storage_passwords:
        if api_key_name in credential.content.get('clear_password'):
            th_instance_key = json.loads(credential.content.get('clear_password'))
            config_args['thehive_key'] = str(th_instance_key[api_key_name])
            helper.log_info('thehive_key found for instance  {}'.format(th_instance))
    if config_args['thehive_key'] is None:
        helper.log_error('thehive_key NOT found for instance  {}'.format(th_instance))         
    # get proxy parameters if any
    config_args['proxies'] = dict()
    if use_proxy is True:
        proxy = helper.get_proxy()
        if proxy:
            proxy_url = '://'
            if proxy['proxy_username'] is not '':
                proxy_url = proxy_url + proxy['proxy_username'] + ':' + proxy['proxy_password'] + '@' 
            proxy_url = proxy_url + proxy['proxy_url'] + ':' + proxy['proxy_port'] + '/'
            config_args['proxies'] = {
                "http":  "http"  + proxy_url,
                "https": "https" + proxy_url
            }
    # Get string values from alert form
    myTemplate = helper.get_param("th_case_template")
    if myTemplate in [None, '']:
        config_args['caseTemplate'] = "default"
    else:
        config_args['caseTemplate'] = myTemplate
    myType = helper.get_param("th_type")
    if myType in [None, '']:
        config_args['type'] = "alert"
    else:
        config_args['type'] = myType
    mySource = helper.get_param("th_source")
    if mySource in [None, '']:
        config_args['source'] = "splunk"
    else:
        config_args['source'] = mySource
    if not helper.get_param("th_unique_id"):
        config_args['unique'] = "oneEvent"
    else:
        config_args['unique'] = helper.get_param("th_unique_id")
    if not helper.get_param("th_title"):
        config_args['title'] = "notable event"
    else:
        config_args['title'] = helper.get_param("th_title")
    myDescription = helper.get_param("th_description")
    if myDescription in [None, '']:
        config_args['description'] = "No description provided."
    else:
        config_args['description'] = myDescription
    myTags = helper.get_param("th_tags")
    if myTags in [None, '']:
        config_args['tags'] = []
    else:
        tags = []
        tag_list = myTags.split(',')
        for tag in tag_list:
            if tag not in tags:
                tags.append(tag)
        config_args['tags'] = tags

    # Get numeric values from alert form
    config_args['severity'] = int(helper.get_param("th_severity"))
    config_args['tlp'] = int(helper.get_param("th_tlp"))
    config_args['pap'] = int(helper.get_param("th_pap"))

    # add filename of the file containing the result of the search
    config_args['filename'] = str(helper.settings['results_file'])

    return config_args


def create_alert(helper, config, results):
    # iterate through each row, cleaning multivalue fields 
    # and then adding the attributes under same alert key
    # this builds the dict alerts
    # https://github.com/TheHive-Project/TheHiveDocs/tree/master/api
    dataType = {}
    _SPLUNK_PATH = os.environ['SPLUNK_HOME']
    directory = _SPLUNK_PATH + os.sep + 'etc' + os.sep + 'apps' \
        + os.sep + 'TA_thehive_ce' + os.sep + 'lookups'
    thehive_datatypes = directory + os.sep + 'thehive_datatypes.csv'
    if os.path.exists(thehive_datatypes):
        try:
            # open thehive_datatypes.csv if exists and load content.
            with open(thehive_datatypes, 'rb') as file_object:
                csv_reader = csv.DictReader(file_object)
                for row in csv_reader:
                    if 'field_name' in row:
                        dataType[row['field_name']]=row['datatype']
        except IOError:  # file thehive_datatypes.csv not readable
            helper.log_info('file thehive_datatypes.csv absent or not readable')
    else:
        create_datatype_lookup()
    if not dataType:
        dataType = {'autonomous-system': 'autonomous-system',
                    'domain': 'domain',
                    'filename': 'filename',
                    'fqdn': 'fqdn',
                    'hash': 'hash',
                    'ip': 'ip',
                    'mail': 'mail',
                    'mail_subject': 'mail_subject',
                    'other': 'other',
                    'regexp': 'regexp',
                    'registry': 'registry',
                    'uri_path': 'uri_path',
                    'url': 'url',
                    'user-agent': 'user-agent'}
    alerts = {}
    alertRef = 'SPK' + str(int(time.time()))

    description = dict()
    title = dict()
    description[alertRef] = config['description']
    title[alertRef] = config['title']
    for row in results:
        # Splunk makes a bunch of dumb empty multivalue fields - we filter those out here 
        row = {key: value for key, value in row.iteritems() if not key.startswith("__mv_")}

        # find the field name used for a unique identifier and strip it from the row
        if config['unique'] in row:
            id = config['unique']
            # grabs that field's value and assigns it to our sourceRef 
            sourceRef = str(row.pop(id))
        else:
            sourceRef = alertRef

        # check if description contains a field name instead of a string.
        # if yes, strip it from the row and assign value to description
        if config['description'] in row:
            id = config['description']
            newDescription = str(row.pop(id))  # grabs that field's value
            if newDescription not in [None, '']:
                description[sourceRef] = newDescription

        # check if title contains a field name instead of a string.
        # if yes, strip it from the row and assign value to title
        if config['title'] in row:
            id = config['title']
            newTitle = str(row.pop(id))  # grabs that field's value
            if newTitle not in [None, '']:
                title[sourceRef] = newTitle

        # check if the field th_msg exists and strip it from the row.
        # The value will be used as message attached to artifacts
        if 'th_msg' in row:
            # grabs that field's value and assigns it to
            artifactMessage = str(row.pop("th_msg"))
        else:
            artifactMessage = ''

        # check if artifacts have been stored for this sourceRef.
        # If yes, retrieve them to add new ones from this row
        if sourceRef in alerts:
            alert = alerts[sourceRef]
            artifacts = list(alert["artifacts"])
        else:
            alert = {}
            artifacts = []

        # now we take those KV pairs to add to dict
        for key, value in row.iteritems():
            if value != "":
                # fields can be enriched with a message part
                if ':' in key:
                    dType = key.split(':', 1)
                    key = str(dType[0])
                    cMsg = artifactMessage + '&msg: ' + str(dType[1])
                    if key not in dataType:
                        cKey = 'other'
                    else:
                        cKey = dataType[key]
                    cMsg = cMsg + ' - field: ' + str(key)
                elif key in dataType:
                    cKey = dataType[key]
                    cMsg = artifactMessage + ' - field: ' + str(key)
                else:
                    cKey = 'other'
                    cMsg = artifactMessage + ' - field: ' + str(key)
                if '\n' in value:  # was a multivalue field
                    helper.log_debug('value is not a simple string {} '.format(value))
                    values = value.split('\n')
                    for val in values:
                        if val != "":
                            artifact = dict(dataType=cKey,
                                            data=str(val),
                                            message=cMsg
                                            )
                            helper.log_debug("new artifact is {} ".format(artifact))
                            if artifact not in artifacts:
                                artifacts.append(artifact)
                else:
                    artifact = dict(dataType=cKey,
                                    data=str(value),
                                    message=cMsg
                                    )
                    helper.log_debug("new artifact is {} ".format(artifact))
                    if artifact not in artifacts:
                        artifacts.append(artifact)

        if artifacts:
            alert['artifacts'] = list(artifacts)
            alerts[sourceRef] = alert

    # actually send the request to create the alert; fail gracefully
    try:
        # iterate in dict alerts to create alerts
        for srcRef, artifact_list in alerts.items():
            helper.log_debug("SourceRef is {} ".format(srcRef))
            helper.log_debug("Attributes are {}".format(artifact_list))

            payload = json.dumps(dict(
                title=title[srcRef],
                description=description[srcRef],
                tags=config['tags'],
                severity=config['severity'],
                tlp=config['tlp'],
                type=config['type'],
                artifacts=artifact_list['artifacts'],
                source=config['source'],
                caseTemplate=config['caseTemplate'],
                sourceRef=srcRef
            ))

            # set proper headers
            url = config['thehive_url']
            auth = config['thehive_key']
            # client cert file
            client_cert = config['client_cert_full_path']

            headers = {'Content-type': 'application/json'}
            headers['Authorization'] = 'Bearer ' + auth
            headers['Accept'] = 'application/json'

            helper.log_debug('DEBUG Calling url="{}"'.format(url))
            helper.log_debug('DEBUG payload={}'.format(payload))
            # post alert
            response = requests.post(url, headers=headers, data=payload,
                                     verify=False, cert=client_cert,
                                     proxies=config['proxies'])
            if str(response.status_code) == "200" or str(response.status_code) == "201":
                helper.log_info("INFO theHive server responded with HTTP status {}".format(response.status_code))
            else:
                helper.log_error("ERROR theHive server responded with HTTP status {}".format(response.status_code))
            # check if status is anything other than 200; throw an exception if it is
            response.raise_for_status()

    # somehow we got a bad response code from thehive
    except requests.exceptions.HTTPError as e:
        helper.log_error("theHive server returned following error: {}".format(e)) 

def process_event(helper, *args, **kwargs):
    """
    # IMPORTANT
    # Do not remove the anchor macro:start and macro:end lines.
    # These lines are used to generate sample code. If they are
    # removed, the sample code will not be updated when configurations
    # are updated.

    [sample_code_macro:start]

    # The following example sends rest requests to some endpoint
    # response is a response object in python requests library
    response = helper.send_http_request("http://www.splunk.com", "GET", parameters=None,
                                        payload=None, headers=None, cookies=None, verify=True, cert=None, timeout=None, use_proxy=True)
    # get the response headers
    r_headers = response.headers
    # get the response body as text
    r_text = response.text
    # get response body as json. If the body text is not a json string, raise a ValueError
    r_json = response.json()
    # get response cookies
    r_cookies = response.cookies
    # get redirect history
    historical_responses = response.history
    # get response status code
    r_status = response.status_code
    # check the response status, if the status is not sucessful, raise requests.HTTPError
    response.raise_for_status()


    # The following example gets and sets the log level
    helper.set_log_level(helper.log_level)

    # The following example gets the setup parameters and prints them to the log
    thehive_api_key1 = helper.get_global_setting("thehive_api_key1")
    helper.log_info("thehive_api_key1={}".format(thehive_api_key1))
    thehive_api_key2 = helper.get_global_setting("thehive_api_key2")
    helper.log_info("thehive_api_key2={}".format(thehive_api_key2))
    thehive_api_key3 = helper.get_global_setting("thehive_api_key3")
    helper.log_info("thehive_api_key3={}".format(thehive_api_key3))

    # The following example gets the alert action parameters and prints them to the log
    th_instance = helper.get_param("th_instance")
    helper.log_info("th_instance={}".format(th_instance))

    th_case_template = helper.get_param("th_case_template")
    helper.log_info("th_case_template={}".format(th_case_template))

    th_type = helper.get_param("th_type")
    helper.log_info("th_type={}".format(th_type))

    th_source = helper.get_param("th_source")
    helper.log_info("th_source={}".format(th_source))

    th_unique_id = helper.get_param("th_unique_id")
    helper.log_info("th_unique_id={}".format(th_unique_id))

    th_title = helper.get_param("th_title")
    helper.log_info("th_title={}".format(th_title))

    th_description = helper.get_param("th_description")
    helper.log_info("th_description={}".format(th_description))

    th_tags = helper.get_param("th_tags")
    helper.log_info("th_tags={}".format(th_tags))

    th_severity = helper.get_param("th_severity")
    helper.log_info("th_severity={}".format(th_severity))

    th_tlp = helper.get_param("th_tlp")
    helper.log_info("th_tlp={}".format(th_tlp))

    th_pap = helper.get_param("th_pap")
    helper.log_info("th_pap={}".format(th_pap))


    # The following example adds two sample events ("hello", "world")
    # and writes them to Splunk
    # NOTE: Call helper.writeevents() only once after all events
    # have been added
    helper.addevent("hello", sourcetype="sample_sourcetype")
    helper.addevent("world", sourcetype="sample_sourcetype")
    helper.writeevents(index="summary", host="localhost", source="localhost")

    # The following example gets the events that trigger the alert
    events = helper.get_events()
    for event in events:
        helper.log_info("event={}".format(event))

    # helper.settings is a dict that includes environment configuration
    # Example usage: helper.settings["server_uri"]
    helper.log_info("server_uri={}".format(helper.settings["server_uri"]))
    [sample_code_macro:end]
    """
    helper.set_log_level(helper.log_level)
    helper.log_info("Alert action thehive_ce_alert started.")

    # TODO: Implement your alert action logic here
    Config = prepare_alert_config(helper)
    if Config is None:
        helper.log_error("FATAL Config dict not initialised")
        return 1    
    else:
        helper.log_info("Config dict is ready to use")
        filename = Config['filename']
        # test if the results file exists
        # this should basically never fail unless we are parsing configuration incorrectly
        # example path this variable should hold: '/opt/splunk/var/run/splunk/12938718293123.121/results.csv.gz'
        if os.path.exists(filename):
            # file exists - try to open it; fail gracefully
            try:
                # open the file with gzip lib, start making alerts
                # can with statements fail gracefully??
                with gzip.open(filename, 'rt') as file:
                    # DictReader lets us grab the first row as a header row and other lines will read as a dict mapping the header to the value
                    # instead of reading the first line with a regular csv reader and zipping the dict manually later
                    # at least, in theory
                    Reader = csv.DictReader(file)
                    helper.log_debug("Reader is {}".format(Reader))
                    # make the alert with predefined function; fail gracefully
                    create_alert(helper, Config, Reader)
            # something went wrong with opening the results file
            except IOError:
                helper.log_error("FATAL Results file exists but could not be opened/read")
                return 2
    return 0
