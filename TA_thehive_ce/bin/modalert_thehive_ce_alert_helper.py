
# encoding = utf-8
#!/usr/bin/env python
# Generate TheHive alerts
#
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made

from hive_common import get_customField_dict, get_datatype_dict, prepare_config
import json
import re
import requests
import time
import splunklib.client as client

__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "1.1.2"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"

# All available data types
OBSERVABLE_TLP = {
    "W": 0,
    "G": 1,
    "A": 2,
    "R": 3,
    "0": "TLP:WHITE",
    "1": "TLP:GREEN",
    "2": "TLP:AMBER",
    "3": "TLP:RED"
}


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
    onlyDT = helper.get_param("th_onlyDT")
    if onlyDT == "Listed":
        alert_args['onlyDT'] = True
    else:
        alert_args['onlyDT'] = False
    # Get numeric values from alert form
    alert_args['severity'] = int(helper.get_param("th_severity"))
    alert_args['tlp'] = int(helper.get_param("th_tlp"))
    alert_args['pap'] = int(helper.get_param("th_pap"))

    # add filename of the file containing the result of the search
    alert_args['filename'] = str(helper.settings['results_file'])

    config_args.update(alert_args)
    return config_args


def create_alert(helper, config, app_name):
    # iterate through each row, cleaning multivalue fields
    # and then adding the attributes under same alert key
    # this builds the dict alerts
    data_type = get_datatype_dict(helper, config, app_name)
    custom_field_type = get_customField_dict(helper, config, app_name)
    alert_refererence = 'SPK' + str(int(time.time()))
    helper.log_debug("[HA301] alert_refererence: {}".format(alert_refererence))
    alerts = dict()
    description = dict()
    timestamp = dict()
    title = dict()
    events = helper.get_events()
    for row in events:
        helper.log_debug(
            "[HA302] read row in results: {} ".format(json.dumps(row))
        )
        # Splunk makes a bunch of dumb empty multivalue fields
        # we filter those out here
        row = {key: value for key, value in row.items() if not key.startswith("__mv_")}
        helper.log_debug(
            "[HA303] clean row : {}".format(json.dumps(row))
        )

        # find the field name used for a unique identifier
        # and strip it from the row
        sourceRef = alert_refererence
        if config['unique'] in row:
            newSource = str(row.pop(config['unique']))
            if newSource not in [None, '']:
                # grabs that field's value and assigns it to our sourceRef
                sourceRef = newSource
        helper.log_debug("[HA304] sourceRef: {} ".format(sourceRef))
        # find the field name used for a valid timestamp
        # and strip it from the row
        timestamp[sourceRef] = config['timestamp']
        if config['timestamp'] in row:
            newTimestamp = row.pop(config['timestamp'])
            helper.log_debug("[HA305] new Timestamp from row: {} ".format(newTimestamp))
            epoch10 = re.match("^\d{10}$", newTimestamp)
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
        helper.log_debug("[HA306] alert timestamp: {} ".format(timestamp[sourceRef]))
        # check if description contains a field name instead of a string.
        # if yes, strip it from the row and assign value to description
        description[sourceRef] = config['description']
        if config['description'] in row:
            newDescription = str(row.pop(config['description']))  # grabs that field's value
            if newDescription not in [None, '']:
                description[sourceRef] = newDescription
        helper.log_debug("[HA307] alert description: {} ".format(description[sourceRef]))
        # check if title contains a field name instead of a string.
        # if yes, strip it from the row and assign value to title
        title[sourceRef] = config['title']
        if config['title'] in row:
            newTitle = str(row.pop(config['title']))  # grabs that field's value
            if newTitle not in [None, '']:
                title[sourceRef] = newTitle
        helper.log_debug("[HA308] alert title: {} ".format(title[sourceRef]))
        # check if the field th_msg exists and strip it from the row.
        # The value will be used as message attached to artifacts
        if 'th_msg' in row:
            # grabs that field's value and assigns it to
            artifactMessage = str(row.pop("th_msg"))
        else:
            artifactMessage = ''
        helper.log_debug("[HA331] artifact message: {} ".format(artifactMessage))

        # check if the field th_inline_tags exists and strip it from the row.
        # The comma-separated values will be used as tags attached to artifacts
        artifactTags = []
        if 'th_inline_tags' in row:
            # grabs that field's value and assigns it to
            inline_tags = str(row.pop("th_inline_tags"))
            if "," in inline_tags:
                artifactTags = inline_tags.split(',')
            else:
                artifactTags = [inline_tags]

        helper.log_debug("[HA331] artifact tags: {} ".format(artifactTags))

        # check if artifacts have been stored for this sourceRef.
        # If yes, retrieve them to add new ones from this row
        if sourceRef in alerts:
            alert = alerts[sourceRef]
            artifacts = list(alert["artifacts"])
            customFields = dict(alert['customFields'])
        else:
            alert = dict()
            artifacts = []
            customFields = dict()
        # now we take those KV pairs to add to dict
        for key, value in row.items():
            cTags = artifactTags[:]
            if value != "":
                helper.log_debug('[HA320] field to process: {}'.format(key))
                # get the real key and check if this has to be added to the alert
                # fields can be enriched with a message part
                custom_msg = ''
                artifact_key = ''
                cTLP = ''
                if ':' in key:
                    helper.log_debug('[HA321] composite fieldvalue: {}'.format(key))
                    dType = key.split(':', 1)
                    key = str(dType[0])
                    # extract TLP at observable level
                    # it is on letter W G A or R fappended to field name
                    observable_tlp_check = re.match("^(W|G|A|R)$", str(dType[1]))
                    if observable_tlp_check is not None:
                        cTLP = OBSERVABLE_TLP[dType[1]]
                        cTags.append(OBSERVABLE_TLP[str(cTLP)])
                    else:
                        custom_msg = str(dType[1])

                if key in data_type:
                    helper.log_debug('[HA322] key is an artifact: {} '.format(key))
                    artifact_key = data_type[key]
                elif key in custom_field_type:
                    helper.log_debug('[HA327] key is a custom field: {} '.format(key))
                    # expected types are `string`, `boolean`, `number` (only TH3), `date`, `integer` (only TH4), `float` (only TH4)
                    custom_field_check = False
                    custom_field = dict()
                    custom_field['order'] = len(customFields)
                    custom_type = custom_field_type[key]
                    if custom_type == 'string':
                        custom_field_check = True
                        custom_field[custom_type] = str(value)
                    elif custom_type == 'boolean':
                        is_True = re.match("^(1|y|Y|t|T|true|True)$", value)
                        is_False = re.match("^(0|n|N|f|F|false|False)$", value)
                        if is_True is not None:
                            custom_field_check = True
                            custom_field[custom_type] = True
                        elif is_False is not None:
                            custom_field_check = True
                            custom_field[custom_type] = False
                    elif custom_type == 'number':  # for TheHive3 only
                        is_integer = re.match("^\d+$", value)
                        if is_integer is not None:
                            custom_field_check = True
                            custom_field[custom_type] = int(value)
                        else:
                            try:
                                number = float(value)
                                custom_field_check = True
                                custom_field[custom_type] = number
                            except ValueError:
                                pass
                    elif custom_type == 'integer':  # for TheHive4 only
                        try:
                            number = int(value)
                            custom_field_check = True
                            custom_field[custom_type] = number
                        except ValueError:
                            pass
                    elif custom_type == 'float':  # for TheHive4 only
                        try:
                            number = float(value)
                            custom_field_check = True
                            custom_field[custom_type] = number
                        except ValueError:
                            pass
                    elif custom_type == 'date':
                        epoch10 = re.match("^\d{10}$", value)
                        epoch13 = re.match("^\d{13}$", value)
                        if epoch13 is not None:
                            custom_field_check = True
                            custom_field[custom_type] = int(value)
                        elif epoch10 is not None:
                            custom_field_check = True
                            custom_field[custom_type] = int(value) * 1000
                    if custom_field_check is True:
                        customFields[key] = custom_field
                elif config['onlyDT'] is False:
                    helper.log_debug('[HA323] key is added as other artifact (onlyDT is False): {} '.format(key))
                    artifact_key = 'other'

                if artifact_key not in [None, '']:
                    cMsg = 'field: ' + str(key)
                    if custom_msg not in [None, '']:
                        cMsg = custom_msg + ' - ' + cMsg
                    if artifactMessage not in [None, '']:
                        cMsg = artifactMessage + ' - ' + cMsg
                    if '\n' in value:  # was a multivalue field
                        helper.log_debug('[HA324] value is not a simple string: {} '.format(value))
                        values = value.split('\n')
                        for val in values:
                            if val != "":
                                artifact = dict(dataType=artifact_key,
                                                data=str(val),
                                                message=cMsg,
                                                tags=cTags
                                                )
                                if cTLP != '':
                                    artifact['tlp'] = cTLP
                                helper.log_debug(
                                    "[HA325] new artifact is {}".format(artifact)
                                )
                                if artifact not in artifacts:
                                    artifacts.append(artifact)
                    else:
                        artifact = dict(dataType=artifact_key,
                                        data=str(value),
                                        message=cMsg,
                                        tags=cTags
                                        )
                        if cTLP != '':
                            artifact['tlp'] = cTLP
                        helper.log_debug("[HA326] new artifact is {} ".format(artifact))
                        if artifact not in artifacts:
                            artifacts.append(artifact)

        if artifacts:
            alert['artifacts'] = list(artifacts)
            alert['customFields'] = customFields
            alerts[sourceRef] = alert

    # actually send the request to create the alert; fail gracefully
    for srcRef in alerts.keys():
        helper.log_debug("[HA312] SourceRef is {} ".format(srcRef))
        helper.log_debug("[HA313] Attributes are {}".format(alerts[srcRef]['artifacts']))
        helper.log_debug("[HA318] custom fields are {}".format(alerts[srcRef]['customFields']))

        payload = json.dumps(dict(
            title=title[srcRef],
            date=int(timestamp[srcRef]),
            description=description[srcRef],
            tags=config['tags'],
            severity=config['severity'],
            tlp=config['tlp'],
            type=config['type'],
            artifacts=alerts[srcRef]['artifacts'],
            customFields=alerts[srcRef]['customFields'],
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

        helper.log_debug('[HA314] DEBUG Calling url="{}"'.format(url))
        helper.log_debug('[HA315] DEBUG payload={}'.format(payload))
        # post alert
        try:
            # iterate in dict alerts to create alerts
            response = requests.post(url, headers=headers, data=payload,
                                     verify=False, cert=client_cert,
                                     proxies=config['proxies'])
            # check if status is anything other than 200;
            # throw an exception if it is

        # somehow we got a bad response code from thehive
        except requests.exceptions.HTTPError:
            response.raise_for_status()

        if str(response.status_code) == "200" \
           or str(response.status_code) == "201":
            helper.log_info("[HA316] INFO theHive server responded with HTTP status {}".format(response.status_code))
        else:
            helper.log_error("[HA317] ERROR theHive server responded with status {}".format(response.status_code))


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
    helper.log_info("[AL101] Alert action thehive_ce_alert started.")

    # TODO: Implement your alert action logic here
    th_app_name = "TA_thehive_ce"
    th_config = prepare_alert(helper, th_app_name)
    if th_config is None:
        helper.log_error("[AL102] FATAL config dict not initialised")
        return 1
    else:
        helper.log_debug("[AL103] config dict is ready to use")
        create_alert(helper, th_config, th_app_name)
    return 0
