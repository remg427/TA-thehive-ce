# TA_thehive_ce
This TA provides:  
- an adaptative response/alert action to create an alert on [TheHive](https://thehive-project.org).  
- a custom command **hivecollect** to list alerts and cases into Splunk as events (JSON).
- a custom command **hiverest** that is a wrapper to use TheHive API.

# Installation
This TA is designed to run on Splunk Search Head(s).
1. Download the app directly on splunkbase or this [file](TA_thehive_ce.tar.gz) which is the Splunk TA ( it is an archive containing the sub-directory TA_thehive_ce)
2. Install the app on your Splunk Search Head(s): "Manage Apps" -> "Install app from file" or ask Splunk to install it on your Splunk Cloud instance.
3. Restart Splunk (for later updates, you may skip this step)

# Quick-start configuration
## Configure thehive instances
1. At next logon, launch the app (Manage Apps > TheHive CE > launch app)
5. [optional] Configure proxy (Menu Configuration > Proxy) and logging level (Configuration > Logging)
6. **Save TheHive Api key value under thehive_api_keyX where X=1 to 5** (Menu Configuration > Add-on Settings). This TA can save up to 5 different API keys.
7. With lookup editor or other means, **import the CSV table of TheHive instances** [thehive_instance_list.csv.sample](TA_thehive_ce/README/thehive_instance_list.csv.sample). Save it with the name **thehive_instance_list.csv** (**IMPORTANT for script to work**). Please note that you can upload another file provided the column names are the same.
8. Edit this lookup table to point to your TheHive instance(s)
    - 'thehive_instance': provide a name - this is the name you are going to use in alert form or sendalert command.
    - 'thehive_url': provide the base URL to your TH instance. ( /api/alert will be added to it to reach the endpoint). It must be **HTTPS://**
    - 'thehive_api_key_name': indicate the name of the container containing the api key (saved above.): either **thehive_api_key1** or **thehive_api_key2** or **thehive_api_key3** or **thehive_api_key4** or **thehive_api_key5**. Select only one of those 3 constant names (otherwise the script doesn't work).
    - 'thehive_verifycert': check (or not) the certificate of the TheHive server. Accepted values are "True" or "False".
    - 'thehive_ca_full_path': if applicable, provide the local path on Splunk SH to the certificate of thehive instance (it implies a check of the certificate)
    - 'thehive_use_proxy': use (or not) the proxy for this instance. Accepted values are "True" or "False".
    - 'client_use_cert' & 'client_cert_full_path': if you need to identify client with a certicate, set value to True and provide client certificate full path on Splunk SH.
6. Parameters are saved under TA_thehive_ce/lookups/thehive_instance_list.csv
7. **Important: Role(s)/user(s) configuring this app must have the capability to "list_storage_passwords"** (as API KEYs and proxy password(s) are safely stored encrypted ). It looks like that this capability is not required to set the alert.

## Configure list of fields to be used in alert.
### Upgrade from version before 1.1.0
In version 1.1.0, you can add custom fields to your alerts. The lookup thehive_datatypes.csv has been updated with a new column field_type that takes 2 values: 'artifact' or 'customField' (case sensitive). If you want to add custom fields to your alerts, you first need to edit the lookup file and add this column with the type values.
### standard dataTypes
Thehive expects observables passed in the alert to have specific [data types](TA_thehive_ce/README/thehive_datatypes.csv.sample). If you do nothing, the script will copy this sample to a lookup table. **lookups/thehive_datatypes.csv**. In Splunk search, any field matching one entry in this table will be added to the alert with the corresponding dataType. For example, the value of a field ip in Splunk search will be set as an obersable of dataType ip on TheHive instance.  
If in alert configuration you select "Add all fields to the alert (default dataType is other)" for option "Non-listed fields", all other fields without specific meaning for TA_thehive_ce will be added to the alert with dataType "other".

### additional fields and custom fields
1. In addition, you can edit the CSV file **lookups/thehive_datatypes.csv** to add as many rows as you need.
	- then you can define additional field(s) (from datamodel) mapping to datatype e.g. on Splunk field _src_ (from datamodel Web) can be mapped to datatype _ip_, _dest_ to _domain_ etc.
	- edit lookup/thehive_datatypes.csv and add 2 lines 
```
   src,artifact,ip,,field src from DM Web
   dest,artifact,domain,,field dest from DM Web
```
	- you can now make a search that return fields src and dest; both will be passed to TheHive as observables of type IP and domain (and no longer as "other")

2. likewise, you can add your custom fields with corresponding dataType.
	- expected types are `string`, `boolean`, `number` (only TH3), `date`, `integer` (only TH4), `float` (only TH4)
	- for example to add a custom field "playbook" of type string add this line to lookup/thehive_datatypes.csv
```
   playbook,customField,string,,URL of playbook to use with this alert
```	

# Use Cases

Here some activities you may carry out more easily with this app.
## SOC notable event workflow
- Define a correlation search in Splunk 
- On match it creates an alert on [TheHive](https://thehive-project.org/)
- In thehive, an analyst can review it and if appropriate create a case (if the template set at alert creation exists, it will be used first)

# Usage
Add Splunk alert action to your search to [create TheHive alerts](docs/thehivealerts.md)

# Credits
The alert_action for TheHive was inpired by [this Splunk app](https://splunkbase.splunk.com/app/3642/)

# Licence
This app TA_thehive_ce is licensed under the GNU Lesser General Public License v3.0.
