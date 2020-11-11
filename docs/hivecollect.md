# custom command hivecollect

This custom command is a wrapper to call TheHive API endpoint /api/alert or /api/case and return results as events with field mapping
## [hivecollect-command]
[hivecollect-command]
syntax = |hivecollect <hivecollect-options> 
shortdesc = use api endpoint to pull alert from TheHive instance and display as events.
usage = public
example1 = | hivecollect hive_instance=test
comment1 = retrieve 10 first alerts ( = 0-10) and display as JSON events
example2 = | hivecollect hive_instance=test endpoint=alert range=100-200 sort="-severity,+date"
comment2 = retrieve alert 100 to 199 (sorted by descending severity and \
  ascending dates) and display them as JSON events.
related = thehive
tags = thehive

[hivecollect-options]
syntax = hive_instance=<string> endpoint=<string> objectid=<string> range=<string> sort=<string>
description = hivecollect leverages thehive API endpoints \
  Define your TheHive instances as input. !!! limit is set by default to 10 first alerts. !!!

# All params
    ## MANDATORY hive instance for this search
    hive_instance = Option(
        doc='''
        **Syntax:** **hive_instance=instance_name*
        **Description:** TheHive instance parameters
        as described in lookup/thehive_instance_list.csv.''',
        require=True)
    endpoint = Option(
        doc='''
        **Syntax:** **endpoint=***alert|case*
        **Description:**endpoint of TheHive API''',
        require=False, validate=validators.Match("endpoint", r"^(alert|case)$"))
    objectid = Option(
        doc='''
        **Syntax:** **objectid=***id*
        **Description:**ID.''',
        require=False, validate=validators.Match("objectid", r"^([0-9a-f]|\w{20})+$"))
    range = Option(
        doc='''
        **Syntax:** **range=***all|start_number-end_number*
        **Description:**A range describing the number of rows to be returned.
        for example range=all or range=10-100''',
        require=False, validate=validators.Match("range", r"^(all|\d+\-\d+)$"))
    sort = Option(
        doc='''
        **Syntax:** **sort=***[+field1,-field2,...]*
        **Description:** Comma-seperated list of fields to sort the result with.
         Prefix the field name with `-` for descending order and `+` for ascending order''',
        require=False)
