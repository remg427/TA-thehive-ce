
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
# https://docs.splunk.com/Documentation/Splunk/8.0.3/AdvancedDev/ModAlertsAdvancedExample
import csv
import gzip
from hive_common import get_datatype_list, prepare_config
import json
import os
import re
import requests
import time
import splunklib.client as client

__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "1.1.0"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"


def prepare_alert(helper, app_name):
    instance = helper.get_param("th_instance")
    sessionKey = helper.settings['session_key']
    splunkService = client.connect(token=sessionKey)
    storage = splunkService.storage_passwords
    config_args = prepare_config(helper, app_name, instance, storage)
    if config_args is None:
        return None
    alert_args = dict()
    # Get string values from alert form
    myTemplate = helper.get_param("th_case_template")
    if myTemplate in [None, '']:
        alert_args['caseTemplate'] = "default"
    else:
        alert_args['caseTemplate'] = myTemplate
    myType = helper.get_param("th_type")
    if myType in [None, '']:
        alert_args['type'] = "alert"
    else:
        alert_args['type'] = myType
    mySource = helper.get_param("th_source")
    if mySource in [None, '']:
        alert_args['source'] = "splunk"
    else:
        alert_args['source'] = mySource
    myTimestamp = helper.get_param("th_timestamp")
    if myTimestamp in [None, '']:
        alert_args['timestamp'] = int(time.time() * 1000)
    else:
        alert_args['timestamp'] = myTimestamp
    if not helper.get_param("th_unique_id"):
        alert_args['unique'] = "oneEvent"
    else:
        alert_args['unique'] = helper.get_param("th_unique_id")
    if not helper.get_param("th_title"):
        alert_args['title'] = "notable event"
    else:
        alert_args['title'] = helper.get_param("th_title")
    myDescription = helper.get_param("th_description")
    if myDescription in [None, '']:
        alert_args['description'] = "No description provided."
    else:
        alert_args['description'] = myDescription
    myTags = helper.get_param("th_tags")
    if myTags in [None, '']:
        alert_args['tags'] = []
    else:
        tags = []
        tag_list = myTags.split(',')
        for tag in tag_list:
            if tag not in tags:
                tags.append(tag)
        alert_args['tags'] = tags

    # Get numeric values from alert form
    alert_args['severity'] = int(helper.get_param("th_severity"))
    alert_args['tlp'] = int(helper.get_param("th_tlp"))
    alert_args['pap'] = int(helper.get_param("th_pap"))

    # add filename of the file containing the result of the search
    alert_args['filename'] = str(helper.settings['results_file'])

    config_args.update(alert_args)
    return config_args


def create_alert(helper, config, results, app_name):
    # iterate through each row, cleaning multivalue fields
    # and then adding the attributes under same alert key
    # this builds the dict alerts
    # https://github.com/TheHive-Project/TheHiveDocs/tree/master/api
    dataType = get_datatype_list(helper, config, app_name)
    alertRef = 'SPK' + str(int(time.time()))
    helper.log_debug("---: {} ".format(alertRef))
    alerts = dict()
    description = dict()
    timestamp = dict()
    title = dict()
    for row in results:
        helper.log_debug(
            "read row in results: {} ".format(json.dumps(row))
        )
        # Splunk makes a bunch of dumb empty multivalue fields
        # we filter those out here
        row = {key: value for key, value in row.items() if not key.startswith("__mv_")}
        helper.log_debug(
            "clean row : {} ".format(json.dumps(row))
        )

        # find the field name used for a unique identifier
        # and strip it from the row
        sourceRef = alertRef
        if config['unique'] in row:
            newSource = str(row.pop(config['unique']))
            if newSource not in [None, '']:
                # grabs that field's value and assigns it to our sourceRef
                sourceRef = newSource
        helper.log_debug("---: {} ".format(sourceRef))
        # find the field name used for a valid timestamp
        # and strip it from the row
        timestamp[sourceRef] = config['timestamp']
        if config['timestamp'] in row:
            newTimestamp = row.pop(config['timestamp'])
            helper.log_debug("newTimestamp: {} ".format(newTimestamp))
            epoch10 = re.match("^\d{10}", newTimestamp)
            epoch13 = re.match("^\d{13}$", newTimestamp)
            if epoch13 is not None:
                newTS = int(newTimestamp)
                # grabs that field's value and assigns it to our sourceRef
                timestamp[sourceRef] = newTS
            elif epoch10 is not None:
                newTS = int(newTimestamp) * 1000
                # grabs that field's value and assigns it to our sourceRef
                timestamp[sourceRef] = newTS
            else:
                timestamp[sourceRef] = int(time.time() * 1000)
        helper.log_debug("---: {} ".format(timestamp[sourceRef]))
        # check if description contains a field name instead of a string.
        # if yes, strip it from the row and assign value to description
        description[sourceRef] = config['description']
        if config['description'] in row:
            newDescription = str(row.pop(config['description']))  # grabs that field's value
            if newDescription not in [None, '']:
                description[sourceRef] = newDescription
        helper.log_debug("---: {} ".format(description[sourceRef]))
        # check if title contains a field name instead of a string.
        # if yes, strip it from the row and assign value to title
        title[sourceRef] = config['title']
        if config['title'] in row:
            newTitle = str(row.pop(config['title']))  # grabs that field's value
            if newTitle not in [None, '']:
                title[sourceRef] = newTitle
        helper.log_debug("---: {} ".format(title[sourceRef]))
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
            alert = dict()
            artifacts = list()

        # now we take those KV pairs to add to dict
        for key, value in row.items():
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
                    helper.log_debug(
                        'value is not a simple string {} '.format(value)
                    )
                    values = value.split('\n')
                    for val in values:
                        if val != "":
                            artifact = dict(dataType=cKey,
                                            data=str(val),
                                            message=cMsg
                                            )
                            helper.log_debug(
                                "new artifact is {} ".format(artifact)
                            )
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
                date=int(timestamp[srcRef]),
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
            url = config['thehive_url'] + '/api/alert'
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
            if str(response.status_code) == "200" \
               or str(response.status_code) == "201":
                helper.log_info(
                    "INFO theHive server responded with HTTP status {}".format(
                        response.status_code
                    )
                )
            else:
                helper.log_error(
                    "ERROR theHive server responded with status {}".format(
                        response.status_code
                    )
                )
            # check if status is anything other than 200;
            # throw an exception if it is
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
    response = helper.send_http_request("http://www.splunk.com",
                                        "GET", parameters=None,
                                        payload=None, headers=None,
                                        cookies=None, verify=True,
                                        cert=None, timeout=None,
                                        use_proxy=True)
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
    helper.log_info("prepare config dict.")
    th_app_name = "TA_thehive_ce"
    helper.log_info("app {}.".format(th_app_name))
    instance = helper.get_param("th_instance")
    helper.log_info("instance {}.".format(instance))
    th_config = prepare_alert(helper, th_app_name)
    if th_config is None:
        helper.log_error("FATAL config dict not initialised")
        return 1
    else:
        helper.log_info("config dict is ready to use")
        filename = th_config['filename']
        helper.log_info("file is {}".format(filename))
        # test if the results file exists
        # this should basically never fail unless
        # we are parsing configuration incorrectly
        # example path this variable should hold something like
        # '/opt/splunk/var/run/splunk/12938718293123.121/results.csv.gz'
        if os.path.exists(filename):
            # file exists - try to open it; fail gracefully
            try:
                # open the file with gzip lib, start making alerts
                # can with statements fail gracefully??
                fh = gzip.open(filename, "rt")
                helper.log_info("file {} is open with first try".format(filename))
            except ValueError:
                # Workaround for Python 2.7 under Windows
                fh = gzip.open(filename, "r")
                helper.log_info("file {} is open with first alternate".format(filename))

            if fh is not None:
                # DictReader lets us grab the first row as a header row and
                # other lines will read as a dict mapping the header
                # to the value instead of reading the first line with a
                # regular csv reader and zipping the dict manually later at
                # least, in theory
                event_reader = csv.DictReader(fh)
                helper.log_debug("event_reader is {}".format(event_reader))
                # make the alert with predefined function; fail gracefully
                create_alert(helper, th_config, event_reader, th_app_name)
            # something went wrong with opening the results file
            else:
                helper.log_error("FATAL Results file exists but \
could not be opened or read")
                return 2
        else:
            helper.log_error("FATAL Results file not found")
            return 3

    return 0
