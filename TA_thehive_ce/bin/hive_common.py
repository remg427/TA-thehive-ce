# encoding = utf-8
# !/usr/bin/env python
# Generate TheHive alerts
#
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made
import csv
import gzip
import json
import os
import re
from splunk.clilib import cli_common as cli


# All available data types
dataTypeList = [
    "domain",
    "file",
    "filename",
    "fqdn",
    "hash",
    "ip",
    "mail",
    "mail_subject",
    "other",
    "regexp",
    "registry",
    "uri_path",
    "url",
    "user-agent"]


def create_datatype_lookup(helper, app_name):
    # if it does not exist, create thehive_datatypes.csv
    _SPLUNK_PATH = os.environ['SPLUNK_HOME']
    directory = os.path.join(
        _SPLUNK_PATH, 'etc', 'apps', app_name, 'lookups')
    th_dt_filename = os.path.join(directory, 'thehive_datatypes.csv')
    if not os.path.exists(th_dt_filename):
        # file th_dt_filename.csv doesn't exist. Create the file
        observables = list()
        observables.append(['field_name', 'field_type', 'datatype', 'regex', 'description'])
        for dt in dataTypeList:
            observables.append([dt, 'artifact', dt, '', ''])
        try:
            if not os.path.exists(directory):
                os.makedirs(directory)
            with open(th_dt_filename, 'w') as file_object:
                csv_writer = csv.writer(file_object, delimiter=',')
                for observable in observables:
                    csv_writer.writerow(observable)
        except IOError:
            helper.log_error(
                "[HC102] FATAL {} could not be opened in write mode".format(th_dt_filename)
            )


def create_instance_lookup(helper, app_name):
    # if the lookup available on github has not been created
    # generate it on first alert and return a message to configure it
    _SPLUNK_PATH = os.environ['SPLUNK_HOME']
    directory = os.path.join(
        _SPLUNK_PATH, 'etc', 'apps', app_name, 'lookups')
    th_list_filename = os.path.join(directory, 'thehive_instance_list.csv')
    if not os.path.exists(th_list_filename):
        # file thehive_instance_list.csv doesn't exist. Create the file
        th_list = [['thehive_instance', 'thehive_url', 'thehive_api_key_name',
                    'thehive_verifycert', 'thehive_ca_full_path',
                    'thehive_use_proxy', 'client_use_cert',
                    'client_cert_full_path'],
                   ['th_test', 'https://testhive.example.com/',
                    'thehive_api_key1', 'True', '',
                    'False', 'False', 'client_cert_full_path'],
                   ['th_staging', 'https://staginghive.example.com/',
                    'thehive_api_key2', 'True', '',
                    'False', 'False', 'client_cert_full_path'],
                   ['th_prod', 'https://prodhive.example.com/',
                    'thehive_api_key3', 'True', '',
                    'False', 'False', 'client_cert_full_path']
                   ]
        try:
            if not os.path.exists(directory):
                os.makedirs(directory)
            with open(th_list_filename, 'w') as file_object:
                csv_writer = csv.writer(file_object, delimiter=',')
                for instance in th_list:
                    csv_writer.writerow(instance)
        except IOError:
            helper.log_error(
                "[HC202] FATAL {} could not be opened in write mode"
                .format(th_list_filename)
            )


def get_datatype_dict(helper, config, app_name):
    dataType_dict = dict()
    _SPLUNK_PATH = os.environ['SPLUNK_HOME']
    directory = os.path.join(
        _SPLUNK_PATH, 'etc', 'apps', app_name, 'lookups'
    )
    th_dt_filename = os.path.join(directory, 'thehive_datatypes.csv')
    if os.path.exists(th_dt_filename):
        try:
            # open the file with gzip lib, start making alerts
            # can with statements fail gracefully??
            fh = open(th_dt_filename, "rt")
        except ValueError:
            # Workaround for Python 2.7 under Windows
            fh = gzip.open(th_dt_filename, "r")
        if fh is not None:
            try:
                csv_reader = csv.DictReader(fh)
                for row in csv_reader:
                    if 'field_name' in row and 'field_type' in row:
                        if row['field_type'] == 'artifact':
                            dataType_dict[row['field_name']] = row['datatype']
                helper.log_info("[HC304] dataType_dict built from thehive_datatypes.csv")
            except IOError:  # file thehive_datatypes.csv not readable
                helper.log_error('[HC305] file {} empty, malformed or not readable'.format(
                    th_dt_filename
                ))
    else:
        create_datatype_lookup(helper, app_name)
    if not dataType_dict:
        dataType_dict = dict()
        for dt in dataTypeList:
            dataType_dict[dt] = dt
        helper.log_info("[HC306] dataType_dict built from inline table")
    return dataType_dict


def get_customField_dict(helper, config, app_name):
    customField_dict = dict()
    _SPLUNK_PATH = os.environ['SPLUNK_HOME']
    directory = os.path.join(
        _SPLUNK_PATH, 'etc', 'apps', app_name, 'lookups'
    )
    th_dt_filename = os.path.join(directory, 'thehive_datatypes.csv')
    if os.path.exists(th_dt_filename):
        try:
            # open the file with gzip lib, start making alerts
            # can with statements fail gracefully??
            fh = open(th_dt_filename, "rt")
        except ValueError:
            # Workaround for Python 2.7 under Windows
            fh = gzip.open(th_dt_filename, "r")
        if fh is not None:
            try:
                csv_reader = csv.DictReader(fh)
                for row in csv_reader:
                    if 'field_name' in row and 'field_type' in row:
                        if row['field_type'] == 'customField':
                            customField_dict[row['field_name']] = row['datatype']
                helper.log_info("[HC604] customField_dict built from thehive_datatypes.csv")
            except IOError:  # file thehive_datatypes.csv not readable
                helper.log_error('[HC605] file {} absent or not readable'.format(
                    th_dt_filename
                ))
    else:
        create_datatype_lookup(helper, app_name)
    return customField_dict


def logging_level(helper, app_name):

    """
    This function sets logger to the defined level in
    misp42splunk app and writes logs to a dedicated file
    """
    # retrieve log level
    _SPLUNK_PATH = os.environ['SPLUNK_HOME']
    settings_file = os.path.join(
        _SPLUNK_PATH, 'etc', 'apps',
        app_name,
        'local',
        app_name.lower() + '_settings.conf'
    )
    run_level = 'ERROR'
    if os.path.exists(settings_file):
        app_settings = cli.readConfFile(settings_file)
        for name, content in list(app_settings.items()):
            if 'logging' in name:
                if 'loglevel' in content:
                    set_level = content['loglevel']
                    if set_level in ['DEBUG', 'INFO', 'WARNING',
                                     'ERROR', 'CRITICAL']:
                        run_level = set_level
    else:
        helper.log_error("[HC501] file {} does not exist".format(settings_file))
    return run_level


def prepare_config(helper, app_name, th_instance, storage_passwords):
    config_args = dict()
    # get TheHive instance to be used
    # open lookups/thehive_instance_list.csv
    _SPLUNK_PATH = os.environ['SPLUNK_HOME']
    directory = os.path.join(
        _SPLUNK_PATH, 'etc', 'apps', app_name, 'lookups'
    )
    csv_instance_list = os.path.join(directory, 'thehive_instance_list.csv')
    if os.path.exists(csv_instance_list):
        helper.log_info("[HC402] File {} exists".format(csv_instance_list))
        # file exists - try to open it; fail gracefully
        try:
            # open the file with gzip lib, start making alerts
            # can with statements fail gracefully??
            th_list_fh = open(csv_instance_list, "rt")
        except ValueError:
            # Workaround for Python 2.7 under Windows
            th_list_fh = open(csv_instance_list, "r")
        if th_list_fh is None:
            # something went wrong with opening the results file
            helper.log_error(
                "[HC405] FATAL thehive_instance_list.csv exists but could not be opened/read"
            )
            return None
    else:
        create_instance_lookup(helper, app_name)
        helper.log_error(
            """[HC406] lookups/thehive_instance_list.csv was not found.
A lookup has been created following the template available on github.
Please check install instructions and edit the lookup with your parameters."""
        )
        return None

    if th_list_fh is not None:
        helper.log_info("[HC407] th_list is open")
        # DictReader lets us grab the first row as a header row
        # and other lines will read as a dict mapping the header
        # to the value
        config_reader = csv.DictReader(th_list_fh)
        found_instance = False
        for row in config_reader:
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
                    # get URL from lookup entry
                    th_url = str(row['thehive_url']).rstrip('/')
                    # For Splunk Cloud vetting, the URL must start with https://
                    if not th_url.startswith("https://"):
                        th_url = 'https://' + th_url
                        helper.log_info("[HC410] thehive_url does not start with 'https://'; Please edit thehive_instance_list.csv to fix this.")
                    config_args['thehive_url'] = th_url
                    api_key_name = row['thehive_api_key_name']
                    key_match = re.match(
                        "^thehive_api_key[1-5]$", api_key_name
                    )
                    if key_match is None:
                        helper.log_error("[HC411] FATAL api_key_name must be 'thehive_api_keyX' with X=1 to 5")
                        return None
                    verifycert = str(row['thehive_verifycert'])
                    if verifycert == 'True' or verifycert == 'true':
                        th_ca_full_path = row['thehive_ca_full_path']
                        if th_ca_full_path != '':
                            config_args['thehive_verifycert'] = th_ca_full_path
                        else:
                            config_args['thehive_verifycert'] = True
                    else:
                        config_args['thehive_verifycert'] = False
                    # get client cert parameters
                    client_cert = str(row['client_use_cert'])
                    if client_cert == 'True' or client_cert == 'true':
                        config_args['client_cert_full_path'] = \
                            row['client_cert_full_path']
                    else:
                        config_args['client_cert_full_path'] = None
                    th_proxy = str(row['thehive_use_proxy'])
                    if th_proxy == 'True' or th_proxy == 'true':
                        use_proxy = True
                    else:
                        use_proxy = False

    if found_instance is False:
        helper.log_error("[HC412] lookups/thehive_instance_list.csv does not contain configuration for instance {} ".format(th_instance))
        return None

    # get proxy parameters if any
    config_args['proxies'] = dict()
    if use_proxy is True:
        proxy = helper.get_proxy()
        if proxy:
            proxy_url = '://'
            if 'proxy_username' in proxy:
                if proxy['proxy_username'] not in ['', None]:
                    proxy_url = proxy_url + \
                        proxy['proxy_username'] + ':' \
                        + proxy['proxy_password'] + '@'
            proxy_url = proxy_url + proxy['proxy_url'] + \
                ':' + proxy['proxy_port'] + '/'
            config_args['proxies'] = {
                "http": "http" + proxy_url,
                "https": "https" + proxy_url
            }

    # get clear version of thehive_key
    config_args['thehive_key'] = None
    # from the thehive_api_key defined in the lookup table
    # securely retrive the API key value from storage_password
    for credential in storage_passwords:
        if api_key_name in credential.content.get('clear_password'):
            th_instance_key = json.loads(
                credential.content.get('clear_password')
            )
            config_args['thehive_key'] = str(th_instance_key[api_key_name])
            helper.log_info('[HC414] thehive_key found for instance  {}'.format(th_instance))
    if config_args['thehive_key'] is None:
        helper.log_error('[HC415] thehive_key NOT found for instance  {}'.format(th_instance))
        return None

    return config_args
