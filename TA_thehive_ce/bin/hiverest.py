# coding=utf-8
#
# collect attributes or events as events in Splunk
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made

from __future__ import absolute_import, division, print_function, unicode_literals
import ta_thehive_ce_declare

from collections import OrderedDict
from itertools import chain
import json
import logging
from hive_common import logging_level, prepare_config
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators
# from splunklib.searchcommands import splunklib_logger as logger
import sys
import time
from splunklib.six.moves import map
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "1.1.4"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"


@Configuration(retainsevents=True, type='events', distributed=False)
class HiveRestCommand(GeneratingCommand):
    """ get the attributes from a TheHive instance.
    ##Syntax
    .. code-block::
        | mispgetioc hive_instance=<input> last=<int>(d|h|m)
        | mispgetioc hive_instance=<input> event=<id1>(,<id2>,...)
        | mispgetioc hive_instance=<input> date=<<YYYY-MM-DD>
                                           (date_to=<YYYY-MM-DD>)

    """
    # MANDATORY TheHive instance for this search
    hive_instance = Option(
        doc='''
        **Syntax:** **hive_instance=instance_name*
        **Description:** TheHive instance parameters
        as described in lookup/thehive_instance_list.csv.''',
        require=True)
    method = Option(
        doc='''
        **Syntax:** **method=****
        **Description:** method to use for API target DELETE GET PATCH POST.''',
        require=True, validate=validators.Match("method", r"^(DELETE|GET|PATCH|POST)$"))
    json_request = Option(
        doc='''
        **Syntax:** **json_request=***JSON request*
        **Description:** JSON-formatted json_request.''',
        require=False, validate=validators.Match("json_request", r"^{.+}$"))
    target = Option(
        doc='''
        **Syntax:** **target=api_target****
        **Description:**target of TheHive API /api/... ''',
        require=True, validate=validators.Match("target", r"^/api/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+$"))

    def log_error(self, msg):
        logging.error(msg)

    def log_info(self, msg):
        logging.info(msg)

    def log_debug(self, msg):
        logging.debug(msg)

    def log_warn(self, msg):
        logging.warning(msg)

    def set_log_level(self):
        logging.root
        loglevel = logging_level('TA_thehive_ce')
        logging.root.setLevel(loglevel)
        logging.error('[HR-101] logging level is set to %s', loglevel)
        logging.error('[HR-102] PYTHON VERSION: ' + sys.version)

    @staticmethod
    def _record(serial_number, time_stamp, host, attributes, attribute_names, encoder):

        raw = encoder.encode(attributes)
        # Formulate record
        fields = dict()
        for f in attribute_names:
            if f in attributes:
                fields[f] = attributes[f]

        if serial_number > 0:
            fields['_serial'] = serial_number
            fields['_time'] = time_stamp
            fields['_raw'] = raw
            fields['host'] = host
            return fields

        record = OrderedDict(chain(
            (('_serial', serial_number), ('_time', time_stamp),
             ('_raw', raw), ('host', host)),
            map(lambda name: (name, fields.get(name, '')), attribute_names)))

        return record

    def displayResponse(results, action, host):

        encoder = json.JSONEncoder(ensure_ascii=False, separators=(',', ':'))
        if action == 'list_alert' or action == 'list_case':
            attribute_names = list()
            serial_number = 0
            for a in results:
                if serial_number == 0:
                    for k in list(a.keys()):
                        attribute_names.append(k)
                if action == 'list_alert':
                    timestamp = int(a['date'] / 1000)
                elif action == 'list_case':
                    timestamp = int(a['startDate'] / 1000)
                yield HiveRestCommand._record(
                    serial_number, timestamp, host, a, attribute_names, encoder)
                serial_number += 1
                GeneratingCommand.flush
        elif action == 'get_an_alert' or action == 'get_a_case':
            attribute_names = list()
            serial_number = 0
            a = results
            if serial_number == 0:
                for k in list(a.keys()):
                    attribute_names.append(k)
            if action == 'get_an_alert':
                timestamp = int(a['date'] / 1000)
            elif action == 'get_a_case':
                timestamp = int(a['startDate'] / 1000)
            yield HiveRestCommand._record(
                serial_number, timestamp, host, a, attribute_names, encoder)
            serial_number += 1
            GeneratingCommand.flush

    def generate(self):
        # Phase 1: Preparation
        logging.root
        loglevel = logging_level(self, 'TA_thehive_ce')
        logging.root.setLevel(loglevel)
        self.log_error('[HR-201] logging level is set to {}'.format(loglevel))
        storage = self.service.storage_passwords
        my_args = prepare_config(self, 'TA_thehive_ce', self.hive_instance, storage)
        if my_args is None:
            raise Exception("Sorry, no configuration for hive_instance={}".format(self.hive_instance))
        my_args['host'] = my_args['thehive_url'].replace('https://', '')
        if self.target not in [None, '']:
            my_args['thehive_url'] = my_args['thehive_url'] + self.target
        if self.json_request not in [None, '']:
            body_dict = json.loads(self.json_request)
            self.log_debug('[HR-202] body_dict is {}'.format(body_dict))
        else:
            body_dict = {}
        headers = {
            "Authorization": "Bearer {}".format(my_args['thehive_key'])
        }
        if self.method == "GET":
            r = requests.get(my_args['thehive_url'],
                             headers=headers,
                             params=body_dict,
                             verify=my_args['thehive_verifycert'],
                             cert=my_args['client_cert_full_path'],
                             proxies=my_args['proxies'])
        elif self.method == "POST":
            r = requests.post(my_args['thehive_url'],
                              headers=headers,
                              data=json.dumps(body_dict),
                              verify=my_args['thehive_verifycert'],
                              cert=my_args['client_cert_full_path'],
                              proxies=my_args['proxies'])
        elif self.method == "PATCH":
            r = requests.patch(my_args['thehive_url'],
                               headers=headers,
                               data=json.dumps(body_dict),
                               verify=my_args['thehive_verifycert'],
                               cert=my_args['client_cert_full_path'],
                               proxies=my_args['proxies'])
        elif self.method == "DELETE":
            r = requests.delete(my_args['thehive_url'],
                                headers=headers,
                                verify=my_args['thehive_verifycert'],
                                cert=my_args['client_cert_full_path'],
                                proxies=my_args['proxies'])
        else:
            raise Exception(
                "Sorry, no valid method provided (GET/POST/PATCH/DELETE)."
                " it was {}.".format(self.method)
            )
        # check if status is anything other than 200;
        # throw an exception if it is
        r.raise_for_status()
        # response is 200 by this point or we would have thrown an exception
        encoder = json.JSONEncoder(ensure_ascii=False, separators=(',', ':'))
        if isinstance(r.json(), list):
            response = r.json()
        else:
            response = []
            response.append(r.json())
        attribute_names = list()
        serial_number = 0
        for a in response:
            if serial_number == 0:
                for k in list(a.keys()):
                    attribute_names.append(k)
            if 'date' in a:
                timestamp = int(a['date'] / 1000)
            elif 'startDate' in a:
                timestamp = int(a['startDate'] / 1000)
            else:
                timestamp = time.time()
            yield HiveRestCommand._record(
                serial_number, timestamp, my_args['host'], a, attribute_names, encoder)
            serial_number += 1
            GeneratingCommand.flush


if __name__ == "__main__":
    # set up custom logger for the app commands
    dispatch(HiveRestCommand, sys.argv, sys.stdin, sys.stdout, __name__)
