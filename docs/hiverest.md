# custom command hiverest

This custom command is a wrapper to call TheHive API endpoints and return results as JSON event.
## [hiverest-command]
syntax = |hiverest <hiverest-options> 
shortdesc = use any api endpoint on TheHive instance.
usage = public
example1 = | hiverest hive_instance=test method=GET target=/api/alert
comment1 = retrieve 10 first alerts ( = 0-10) and display as JSON events
example2 = | hiverest hive_instance=test method=GET target=/api/alert json_request="{\"range\": \"100-200\", \"sort\": [\"-severity\",\"+date\"]}"
comment2 = retrieve alert 100 to 199 (sorted by descending severity and \
  ascending dates) and display them as JSON events.
related = thehive
tags = thehive

[hiverest-options]
syntax = hive_instance=<string> method=<string> target=<string> json_request=<string>
description = hiverest leverages thehive API endpoints. Define your TheHive instances as input.


# All params
    ## MANDATORY hive instance for this search
    hive_instance = Option(
        doc='''
        **Syntax:** **hive_instance=instance_name*
        **Description:** hive instance parameters
        as described in local/hive42splunk_instances.conf.''',
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