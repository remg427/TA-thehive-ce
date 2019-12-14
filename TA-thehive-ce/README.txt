# Send alerts to TheHive
This TA provides an adaptative response/alert action. It takes the result of a search and creates an alert on [TheHive](https://thehive-project.org)
The overall process is as follows:
- search for events & collect observables
- rename splunk fields to match the field names listed in the lookup table thehive_datatypes.csv. If you haven't created it before the first alert, it will be initialised with the default datatypes (see [example file](TA-thehive-ce/README/thehive_datatypes.csv.sample))
- set the alert action: it will create an alert into TheHive with those values
- you can pass additional info, modfify title, description, etc. directly from list of fields

## collect results in Splunk
### basic search results with a column by artifact type
you may build a search returning some values with fields that are mapped (in lookup/thehive_datatypes.csv) to following default datatypes and optionally one field to group rows (Unique ID)
By default, the lookup thehive_datatypes.csv contains a mapping for thehive datatypes

    autonomous-system
    domain
    file
    filename
    fqdn
    hash
    ip
    mail
    mail_subject
    other
    regexp
    registry
    uri_path
    url
    user-agent


For example

    | eval id = md5(some common key in rows belonging to the same alert)
    | table id, autonomous-system, domain, file, filename, fqdn, hash, ip, mail, mail_subject, other, regexp, registry, uri_path, url, user-agent

### manage fields to become observable
here some precisions
- Values may be empty for some fields; they will be dropped gracefully.
- Only one combination (dataType, data, message) is kept for the same "Unique ID".
- You may add any other columns, they will be passed as simple elements (other)
- if you can add other observable by listing them in the lookup table  
1. edit lookup/thehive_datatypes.csv and add 2 lines 
```
   src,ip,,,
   dest,ip,,,
```
2. you can now make a search that return fields src and dest; both will be passed to TheHive as observables of type IP (and no longer as "other"

### advance search results with additional message
The search above produce alerts with the observable datatype and values and a static message 'observed'. If you want to provide a custom message with the artifact, you have 2 options
1. add to your search a field th_msg. That message will be attached to each artifact
2. rename the field to include a message section using the syntax "a dataType:some text". the field name will be split on first ":" and the result will be 
{'dataType': 'a dataType', 'data': 'value', 'message': 'some text'}

You can try the following dummy search to illustrate this behaviour.

        index=_* | streamstats count as rc |where rc < 4
        |eval "ip:c2 ip of APTxx"="1.1.1."+rc 
        |eval domain="www.malicious.com" 
        |eval hash:md5="f3eef6f636a08768cc4a55f81c29f347"
        |table "ip:c2 ip of APTxx" hash:md5 domain

## create the alert action "Alert to create THEHIVE alert(s)"
Fill in fields. If value is not provided, default will be provided if needed.

* Alert overall description
    - TheHive instance: one of the instances defined in inputs.conf
    - Case Template: The case template to use for imported alerts.
    - Type: The alert type. Defaults to "alert".
    - Source: The alert source. Defaults to "splunk".
    - Unique ID: A field name that contains a unique identifier specific to the source event. You may use the field value to group artifacts from several rows under the same alert. The value for the field "unique" have to be the same on those rows.
    - Title: The title to use for created alerts. You can specify a field name to take the title from the row
    - Description: The description to send with the alert. You can specify a field name to take the description from the row
    - Tags: Use single comma-separated string without quotes for multiple tags (ex. "badIP,spam").
    - Severity: Change the severity of the created alert.
    - TLP: Change the TLP of the created alert. Default is TLP:AMBER
    - PAP: Change the PAP of the created alert. Default is PAP:AMBER