# TA-thehive-ce
This TA provides an adaptative response/alert action to create an alert on [TheHive](https://thehive-project.org).
This App is a version for Splunk Cloud (it can be used on Splunk Enterprise without problem).  
The main change with [TA-thehive](https://github.com/remg427/TA-thehive/) is that this version uses **only a lookup table thehive_instance_list.csv** instead of creating modular inputs to set the parameters to reach your TheHive instances. 

# Installation
This app is designed to run on Splunk Search Head(s) on Linux plateforms
1. Download the app directly on splunkbase or this [file](TA-thehive-ce.tar.gz) which is the Splunk TA ( it is an archive containing the sub-directory TA-thehive)
2. Install the app on your Splunk Search Head(s): "Manage Apps" -> "Install app from file" or ask Splunk to install it on your Splunk Cloud instance.
3. Restart Splunk (for later updates, you may skip this step)
4. At next logon, launch the app (Manage Apps > TA-thehive > launch app)
5. Configure proxy, logging level
6. **Save TheHive Api key value under thehive_api_key1, thehive_api_key2 or thehive_api_key3 input fields**
7. With lookup editor or other means, **import the CSV table of TheHive instances** [thehive_instance_list.csv.sample](TA-thehive-ce/README/thehive_instance_list.csv.sample) with the name being **thehive_instance_list.csv** (**IMPORTANT for script to work**). Please note that you can upload another file provided the column names are the same.
8. Edit this lookup table to point to your TheHive instance(s)
    - provide a name under column 'thehive_instance' - this is the name you are going to use in alert form or sendalert command
    - provide the base URL to your TH instance, ( /api/alert will be added to it to reach the endpoint)
    - indicate the name of the container containing the api key (defined in 6.): either **thehive_api_key1** or **thehive_api_key2** or **thehive_api_key3**. Select only one of those 3 constant names (otherwise the script doesn't work)
    - check (or not) the certificate of the TheHive server: use only True or False
    - if applicable, provide the path to the certificate of thehive instance (it implies a check of the certificate)
    - use (or not) the proxy for this instance:: use only True or False
    - provide client certificate if required (and check the box to use it - use only True or False)
6. Parameters are saved under TA-thehive-ce/lookups/thehive_instance_list.csv
7. **Important: Role(s)/user(s) configuring this app must have the capability to "list_storage_passwords"** (as API KEYs and proxy password(s) are safely stored encrypted ). It looks like that this capability is not required to set the alert
8. In addition, a CSV file is saved under **lookups/thehive_datatypes.csv**. It contains a mapping between field names and datatypes
	- standard datatypes are included at first alert if the file does not exist yet.
	- then you can defined additional field (from datamodel) mapping to datatype e.g. on Splunk field _src_ (from datamodel Web) can be mapped to datatype _ip_, _dest_ to _domain_ etc.
9. This lookup can be edited to add custom datatypes in the same way.

# Use Cases

Here some activities you may carry out more easily with this app.
## SOC notable event workflow
- Define a correlation search in Splunk 
- On match it creates an alert on [TheHive](https://thehive-project.org/)
- In thehive, an analyst can review it and if appropriate create a case (the template mentioned in Splunk will be used first)

# Usage
Splunk alerts to [create TheHive alerts](docs/thehivealerts.md)

# Credits
The alert_action for TheHive was inpired by [this Splunk app](https://splunkbase.splunk.com/app/3642/)

# Licence
This app TA-thehive is licensed under the GNU Lesser General Public License v3.0.
