"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'playbook_local_KTB_Triage_Playbook_for_Generic_Label_1' block
    playbook_local_KTB_Triage_Playbook_for_Generic_Label_1(container=container)

    return

def playbook_local_PLAYBOOK_ENRICH_INDICATOR_ALL_01_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PLAYBOOK_ENRICH_INDICATOR_ALL_01_1() called')
    
    # call playbook "local/PLAYBOOK-ENRICH-INDICATOR-ALL-01", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/PLAYBOOK-ENRICH-INDICATOR-ALL-01", container=container, name="playbook_local_PLAYBOOK_ENRICH_INDICATOR_ALL_01_1", callback=playbook_local_PLAYBOOK_ENRICH_INDICATOR_VIRUSTOTAL_THREATSTREAM_01_1)

    return

def dest_malicious(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('dest_malicious() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationAddress_malicious", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        chk_dest_critical_server_no_contain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.requestURL_malicious", "==", True],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        chk_req_url_no_contain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 3
    url_not_malicious(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def format_dest_addr(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_dest_addr() called')
    
    template = """Dear Approver,
   This is an automated message to inform you of the containment approval request in phantom.
   According to the case and details below, please attend Phantom to approve the containment accordingly.

====================
[Case ID]: {0}
[Case Name]: {1}
[IOC to contain]: {2}
[Security device to contain]: Palo Alto, FMC, FortiManager, Fortigate
[Link to Phantom Event]: https://phantom.csoc.krungthai.local/mission/{0}
[Case details]: {4}
====================

Please do not respond to this message."""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
        "container:name",
        "artifact:*.cef.destinationAddress",
        "artifact:*.cef._incident_url",
        "artifact:*.name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_dest_addr", separator=", ")

    send_email_dest_addr(container=container)

    return

def send_email_dest_addr(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_email_dest_addr() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_dest_addr' call
    formatted_data_1 = phantom.get_format_data(name='format_dest_addr')

    parameters = []
    
    # build parameters list for 'send_email_dest_addr' call
    parameters.append({
        'cc': "",
        'to': "security-infra@ktbcs.co.th",
        'bcc': "",
        'body': formatted_data_1,
        'from': "no-reply-phantom@ktbcs.co.th",
        'headers': "",
        'subject': "SOAR - Containment Approval Needed - Notification",
        'attachments': "",
    })

    phantom.act(action="send email", parameters=parameters, assets=['smtp asset'], callback=Data_Exfil_DA_Containment_Confirmation, name="send_email_dest_addr")

    return

def Data_Exfil_DA_Containment_Confirmation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Data_Exfil_DA_Containment_Confirmation() called')
    
    # set user and message variables for phantom.prompt call
    user = "Tier2 Analyst"
    message = """***WARNING*** 
Do you want to proceed with containment for Destination Address = {0}?

Event Info:
Case ID: {1}
Case Name: {2}

Send from playbook: PLAYBOOK-INVESTIGATE-DATA-01"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationAddress",
        "container:id",
        "container:name",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="Data_Exfil_DA_Containment_Confirmation", separator=", ", parameters=parameters, response_types=response_types, callback=decision_3)

    return

def chk_dest_critical_server_no_contain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('chk_dest_critical_server_no_contain() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]

    chk_dest_critical_server_no_contain__InNoContainList = None
    chk_dest_critical_server_no_contain__InCriticalList = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    checknocontainlist = 0
    checkcriticallist = 0
	
    success, message, nocontainmentlist = phantom.get_list(list_name='nocontainmentlist')
    success, message, criticallist = phantom.get_list(list_name='Servers and Critical desktops')
    phantom.debug(container_item_0)
    phantom.debug(nocontainmentlist)
    phantom.debug(criticallist)
    if nocontainmentlist is not None:
        for item in container_item_0:
            if not any(item in device for device in nocontainmentlist):
                checknocontainlist = 0
            else:
                checknocontainlist = 1

    if criticallist is not None:        
        for item in container_item_0:
            if not any(item in device for device in criticallist):
                checkcriticallist = 0
            else:
                checkcriticallist = 1
                
    check_critical_and_no_contain_list__InNoContainList = checknocontainlist
    check_critical_and_no_contain_list__InCriticalList = checkcriticallist
    #phantom.debug("checknocontainlist = " + str(checknocontainlist))
    #phantom.debug("checkcriticallist = " + str(checkcriticallist))
    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='chk_dest_critical_server_no_contain:InNoContainList', value=json.dumps(chk_dest_critical_server_no_contain__InNoContainList))
    phantom.save_run_data(key='chk_dest_critical_server_no_contain:InCriticalList', value=json.dumps(chk_dest_critical_server_no_contain__InCriticalList))
    decision_2(container=container)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["chk_dest_critical_server_no_contain:custom_function:InNoContainList", "==", None],
            ["chk_dest_critical_server_no_contain:custom_function:InCriticalList", "==", None],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        format_dest_addr(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    promote_to_case_set_status_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def promote_to_case_set_status_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('promote_to_case_set_status_1() called')

    phantom.promote(container=container, template="KTB Workbook")

    phantom.set_status(container=container, status="In progress")
    format_2(container=container)

    return

def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_2() called')
    
    template = """The destination IP {0} is malicious, but this playbook did not contain due to IP is found in the lists of \"Servers and Critical desktops\" or \"nocontainmentlist\".

Please further analyse."""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_2", separator=", ")

    add_note_2(container=container)

    return

def add_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_2() called')

    formatted_data_1 = phantom.get_format_data(name='format_2')

    note_title = "Note from automation playbook"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    cf_local_Set_last_automated_action_10(container=container)

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Data_Exfil_DA_Containment_Confirmation:action_result.status", "==", "success"],
            ["Data_Exfil_DA_Containment_Confirmation:action_result.summary.responses.0", "==", "Yes"],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        playbook_local_KTB_CONTAIN_EXTERNAL_IP_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Data_Exfil_DA_Containment_Confirmation:action_result.status", "==", "success"],
            ["Data_Exfil_DA_Containment_Confirmation:action_result.summary.responses.0", "==", "No"],
        ],
        logical_operator='and')

    # call connected blocks if condition 2 matched
    if matched:
        fmt_not_block_dest(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 3
    fmt_block_dest_timeout(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def add_note_set_status_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_set_status_4() called')

    formatted_data_1 = phantom.get_format_data(name='fmt_block_dest_timeout')

    note_title = ""
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    phantom.set_status(container=container, status="In progress")
    cf_local_Set_last_automated_action_5(container=container)

    return

def chk_req_url_no_contain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('chk_req_url_no_contain() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.requestURL', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]

    chk_req_url_no_contain__InNoContainUrl = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    checknocontainurl = 0
    
    success, message, nocontainurl = phantom.get_list(list_name='noContainUrl')
    phantom.debug(nocontainurl)
    if nocontainurl is not None:
        for item in container_item_0:
            if not any(item in device for device in nocontainurl):
                checknocontainurl = 0
            else:
                checknocontainurl = 1
                
    chk_req_url_no_contain__InNoContainUrl = checknocontainurl
    phantom.debug('chk_req_url_no_contain__InNoContainUrl')
    phantom.debug(chk_req_url_no_contain__InNoContainUrl)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='chk_req_url_no_contain:InNoContainUrl', value=json.dumps(chk_req_url_no_contain__InNoContainUrl))
    decision_11(container=container)

    return

def decision_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_11() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["chk_req_url_no_contain:custom_function:InNoContainUrl", "==", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        transform_url_to_send_email(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    set_status_promote_to_case_13(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def format_req_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_req_url() called')
    
    template = """Dear Approver,
   This is an automated message to inform you of the containment approval request in phantom.
   According to the case and details below, please attend Phantom to approve the containment accordingly.

====================
[Case ID]: {0}
[Case Name]: {1}
[IOC to contain]: {2}
[Security device to contain]: Fortigate URL
[Link to Phantom Event]: https://phantom.csoc.krungthai.local/mission/{0}
[Case details]: {4}
====================

Please do not respond to this message."""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
        "container:name",
        "transform_url_to_send_email:custom_function:transformURL",
        "artifact:*.cef._incident_url",
        "artifact:*.name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_req_url", separator=", ")

    send_email_req_url(container=container)

    return

def send_email_req_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_email_req_url() called')

    # collect data for 'send_email_req_url' call
    formatted_data_1 = phantom.get_format_data(name='format_req_url')

    parameters = []
    
    # build parameters list for 'send_email_req_url' call
    parameters.append({
        'cc': "",
        'to': "security-infra@ktbcs.co.th",
        'bcc': "",
        'body': formatted_data_1,
        'from': "no-reply-phantom@ktbcs.co.th",
        'headers': "",
        'subject': "SOAR - Containment Approval Needed - Notification",
        'attachments': "",
    })

    phantom.act(action="send email", parameters=parameters, assets=['smtp asset'], callback=Data_Exfil_DU_Containment_Confirmation, name="send_email_req_url")

    return

def Data_Exfil_DU_Containment_Confirmation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Data_Exfil_DU_Containment_Confirmation() called')
    
    # set user and message variables for phantom.prompt call
    user = "Tier2 Analyst"
    message = """***WARNING*** 
Do you want to proceed with containment for Request URL = {0}?

Event Info:
Case ID: {1}
Case Name: {2}

Send from playbook: PLAYBOOK-INVESTIGATE-DATA-01"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.requestURL",
        "container:id",
        "container:name",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="Data_Exfil_DU_Containment_Confirmation", separator=", ", parameters=parameters, response_types=response_types, callback=decision_13)

    return

def decision_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_13() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Data_Exfil_DU_Containment_Confirmation:action_result.status", "==", "success"],
            ["Data_Exfil_DU_Containment_Confirmation:action_result.summary.responses.0", "==", "Yes"],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEKTBCS_URL_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Data_Exfil_DU_Containment_Confirmation:action_result.status", "==", "success"],
            ["Data_Exfil_DU_Containment_Confirmation:action_result.summary.responses.0", "==", "No"],
        ],
        logical_operator='and')

    # call connected blocks if condition 2 matched
    if matched:
        fmt_not_block_url(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 3
    fmt_block_url_timeout(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def set_status_promote_to_case_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_promote_to_case_13() called')

    phantom.set_status(container=container, status="In progress")

    phantom.promote(container=container, template="KTB Workbook")
    format_9(container=container)

    return

def format_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_9() called')
    
    template = """The Request URL {0} is malicious, but this playbook did not contain due to Request URL is found in the lists of \"Servers and Critical desktops\" or \"nocontainmentlist\".

Please further analyse."""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.requestURL",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_9", separator=", ")

    add_note_15(container=container)

    return

def add_note_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_15() called')

    formatted_data_1 = phantom.get_format_data(name='format_9')

    note_title = ""
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    cf_local_Set_last_automated_action_9(container=container)

    return

def fmt_block_url_timeout(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('fmt_block_url_timeout() called')
    
    template = """The Request URL {0} is malicious, but no response from approver.

Please further analyse."""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.requestURL",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="fmt_block_url_timeout", separator=", ")

    add_note_set_status_17(container=container)

    return

def add_note_set_status_17(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_set_status_17() called')

    formatted_data_1 = phantom.get_format_data(name='fmt_block_url_timeout')

    note_title = ""
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    phantom.set_status(container=container, status="In progress")
    cf_local_Set_last_automated_action_1(container=container)

    return

def fmt_not_block_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('fmt_not_block_url() called')
    
    template = """The Request URL {0} is malicious, but approver decide to not contain."""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.requestURL",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="fmt_not_block_url", separator=", ")

    add_note_set_status_18(container=container)

    return

def add_note_set_status_18(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_set_status_18() called')

    formatted_data_1 = phantom.get_format_data(name='fmt_not_block_url')

    note_title = ""
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    phantom.set_status(container=container, status="In progress")
    cf_local_Set_last_automated_action_3(container=container)

    return

def cf_local_Set_last_automated_action_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_Set_last_automated_action_1() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "Request for Containment",
        ],
    ]

    parameters = []

    literal_values_0_0 = [item[0] for item in literal_values_0]
    container_property_0_0 = [item[0] for item in container_property_0]

    parameters.append({
        'a_status': literal_values_0_0,
        'Container_id': container_property_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/Set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/Set_last_automated_action', parameters=parameters, name='cf_local_Set_last_automated_action_1')

    return

def cf_local_Set_last_automated_action_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_Set_last_automated_action_2() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "Resolved",
        ],
    ]

    parameters = []

    literal_values_0_0 = [item[0] for item in literal_values_0]
    container_property_0_0 = [item[0] for item in container_property_0]

    parameters.append({
        'a_status': literal_values_0_0,
        'Container_id': container_property_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/Set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/Set_last_automated_action', parameters=parameters, name='cf_local_Set_last_automated_action_2')

    return

def cf_local_Set_last_automated_action_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_Set_last_automated_action_3() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "Containment Approval Rejected",
        ],
    ]

    parameters = []

    literal_values_0_0 = [item[0] for item in literal_values_0]
    container_property_0_0 = [item[0] for item in container_property_0]

    parameters.append({
        'a_status': literal_values_0_0,
        'Container_id': container_property_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/Set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/Set_last_automated_action', parameters=parameters, name='cf_local_Set_last_automated_action_3')

    return

def decision_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_15() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.requestURL_ContainResult", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        fmt_block_url_success(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    fmt_block_url_fail(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def fmt_block_url_fail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('fmt_block_url_fail() called')
    
    template = """The Request URL {0} is malicious, but containment action fail.

Please further analyse."""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.requestURL",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="fmt_block_url_fail", separator=", ")

    add_note_set_status_19(container=container)

    return

def add_note_set_status_19(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_set_status_19() called')

    formatted_data_1 = phantom.get_format_data(name='fmt_block_url_fail')

    note_title = ""
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    phantom.set_status(container=container, status="In progress")
    cf_local_Set_last_automated_action_4(container=container)

    return

def cf_local_Set_last_automated_action_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_Set_last_automated_action_4() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "Containment Failed",
        ],
    ]

    parameters = []

    literal_values_0_0 = [item[0] for item in literal_values_0]
    container_property_0_0 = [item[0] for item in container_property_0]

    parameters.append({
        'a_status': literal_values_0_0,
        'Container_id': container_property_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/Set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/Set_last_automated_action', parameters=parameters, name='cf_local_Set_last_automated_action_4')

    return

def playbook_local_KTB_Triage_Playbook_for_Generic_Label_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_KTB_Triage_Playbook_for_Generic_Label_1() called')
    
    # call playbook "local/KTB Triage Playbook for Generic Label", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/KTB Triage Playbook for Generic Label", container=container, name="playbook_local_KTB_Triage_Playbook_for_Generic_Label_1", callback=decision_16)

    return

def decision_16(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_16() called')
    
    status_param = container.get('status', None)

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            [status_param, "==", "closed"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        return

    # call connected blocks for 'else' condition 2
    playbook_local_PLAYBOOK_ENRICH_INDICATOR_ALL_01_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def fmt_block_url_success(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('fmt_block_url_success() called')
    
    template = """This is an automated message to inform you of the containment is success.

Case Name: {0}
Case Owner: {1}

Please do not respond to this message."""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
        "container:name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="fmt_block_url_success", separator=", ")

    add_note_set_status_promote_to_case_20(container=container)

    return

def add_note_set_status_promote_to_case_20(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_set_status_promote_to_case_20() called')

    formatted_data_1 = phantom.get_format_data(name='fmt_block_url_success')

    note_title = ""
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    phantom.set_status(container=container, status="Resolved")

    phantom.promote(container=container, template="KTB Workbook")
    cf_local_Set_last_automated_action_2(container=container)

    return

def fmt_block_dest_timeout(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('fmt_block_dest_timeout() called')
    
    template = """The Destination Address {0} is malicious, but no response from approver.

Please further analyse."""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="fmt_block_dest_timeout", separator=", ")

    add_note_set_status_4(container=container)

    return

def decision_17(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_17() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Address_blocked", "in", "artifact:*.tags"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        fmt_block_dest_success(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    fmt_block_dest_fail(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def fmt_block_dest_success(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('fmt_block_dest_success() called')
    
    template = """This is an automated message to inform you of the containment is success.

Case Name: {0}
Case Owner: {1}

Please do not respond to this message."""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
        "container:name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="fmt_block_dest_success", separator=", ")

    add_note_set_status_promote_to_case_21(container=container)

    return

def fmt_block_dest_fail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('fmt_block_dest_fail() called')
    
    template = """The Destination Address {0} is malicious, but containment action fail.

Please further analyse."""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="fmt_block_dest_fail", separator=", ")

    set_status_add_note_22(container=container)

    return

def fmt_not_block_dest(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('fmt_not_block_dest() called')
    
    template = """The Destination Address {0} is malicious, but approver decide to not contain."""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="fmt_not_block_dest", separator=", ")

    add_note_set_status_23(container=container)

    return

def add_note_set_status_promote_to_case_21(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_set_status_promote_to_case_21() called')

    formatted_data_1 = phantom.get_format_data(name='fmt_block_dest_success')

    note_title = ""
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    phantom.set_status(container=container, status="Resolved")

    phantom.promote(container=container, template="KTB Workbook")
    cf_local_Set_last_automated_action_6(container=container)

    return

def set_status_add_note_22(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_add_note_22() called')

    formatted_data_1 = phantom.get_format_data(name='fmt_block_dest_fail')

    phantom.set_status(container=container, status="In progress")

    note_title = ""
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    cf_local_Set_last_automated_action_7(container=container)

    return

def add_note_set_status_23(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_set_status_23() called')

    formatted_data_1 = phantom.get_format_data(name='fmt_not_block_dest')

    note_title = ""
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    phantom.set_status(container=container, status="In progress")
    cf_local_Set_last_automated_action_8(container=container)

    return

def cf_local_Set_last_automated_action_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_Set_last_automated_action_5() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "Request for Containment",
        ],
    ]

    parameters = []

    literal_values_0_0 = [item[0] for item in literal_values_0]
    container_property_0_0 = [item[0] for item in container_property_0]

    parameters.append({
        'a_status': literal_values_0_0,
        'Container_id': container_property_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/Set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/Set_last_automated_action', parameters=parameters, name='cf_local_Set_last_automated_action_5')

    return

def cf_local_Set_last_automated_action_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_Set_last_automated_action_6() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "Resolved -Scheduled-",
        ],
    ]

    parameters = []

    literal_values_0_0 = [item[0] for item in literal_values_0]
    container_property_0_0 = [item[0] for item in container_property_0]

    parameters.append({
        'a_status': literal_values_0_0,
        'Container_id': container_property_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/Set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/Set_last_automated_action', parameters=parameters, name='cf_local_Set_last_automated_action_6')

    return

def cf_local_Set_last_automated_action_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_Set_last_automated_action_7() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "Containment Failed",
        ],
    ]

    parameters = []

    literal_values_0_0 = [item[0] for item in literal_values_0]
    container_property_0_0 = [item[0] for item in container_property_0]

    parameters.append({
        'a_status': literal_values_0_0,
        'Container_id': container_property_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/Set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/Set_last_automated_action', parameters=parameters, name='cf_local_Set_last_automated_action_7')

    return

def cf_local_Set_last_automated_action_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_Set_last_automated_action_8() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "Containment Approval Rejected",
        ],
    ]

    parameters = []

    literal_values_0_0 = [item[0] for item in literal_values_0]
    container_property_0_0 = [item[0] for item in container_property_0]

    parameters.append({
        'a_status': literal_values_0_0,
        'Container_id': container_property_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/Set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/Set_last_automated_action', parameters=parameters, name='cf_local_Set_last_automated_action_8')

    return

def cf_local_Set_last_automated_action_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_Set_last_automated_action_9() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "Enriched",
        ],
    ]

    parameters = []

    literal_values_0_0 = [item[0] for item in literal_values_0]
    container_property_0_0 = [item[0] for item in container_property_0]

    parameters.append({
        'a_status': literal_values_0_0,
        'Container_id': container_property_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/Set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/Set_last_automated_action', parameters=parameters, name='cf_local_Set_last_automated_action_9')

    return

def cf_local_Set_last_automated_action_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_Set_last_automated_action_10() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "Enriched",
        ],
    ]

    parameters = []

    literal_values_0_0 = [item[0] for item in literal_values_0]
    container_property_0_0 = [item[0] for item in container_property_0]

    parameters.append({
        'a_status': literal_values_0_0,
        'Container_id': container_property_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/Set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/Set_last_automated_action', parameters=parameters, name='cf_local_Set_last_automated_action_10')

    return

def add_note_24(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_24() called')

    note_title = ""
    note_content = ""
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    cf_local_Set_last_automated_action_11(container=container)

    return

def cf_local_Set_last_automated_action_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_Set_last_automated_action_11() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "Enriched",
        ],
    ]

    parameters = []

    literal_values_0_0 = [item[0] for item in literal_values_0]
    container_property_0_0 = [item[0] for item in container_property_0]

    parameters.append({
        'a_status': literal_values_0_0,
        'Container_id': container_property_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/Set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/Set_last_automated_action', parameters=parameters, name='cf_local_Set_last_automated_action_11')

    return

def url_not_malicious(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_not_malicious() called')
    
    template = """The Request URL {0} is not malicious.
Please further analyse."""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.requestURL",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="url_not_malicious", separator=", ")

    add_note_24(container=container)

    return

def playbook_local_PLAYBOOK_ENRICH_INDICATOR_VIRUSTOTAL_THREATSTREAM_01_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PLAYBOOK_ENRICH_INDICATOR_VIRUSTOTAL_THREATSTREAM_01_1() called')
    
    # call playbook "local/PLAYBOOK-ENRICH-INDICATOR-VIRUSTOTAL-THREATSTREAM-01", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/PLAYBOOK-ENRICH-INDICATOR-VIRUSTOTAL-THREATSTREAM-01", container=container, name="playbook_local_PLAYBOOK_ENRICH_INDICATOR_VIRUSTOTAL_THREATSTREAM_01_1", callback=query_splunk)

    return

def query_splunk(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('query_splunk() called')
    
    template = """earliest = -5d@d index=ktb_csoc_default sourcetype=cisco:amp:event | spath \"event.computer.network_addresses{{}}.ip\" | search \"event.computer.network_addresses{{}}.ip\"=\"{0}\" | eval time = _time  | convert timeformat=\"%d-%m-%Y %H:%M:%S\" ctime(time) AS time
| table time, event.computer.hostname ,event.computer.network_addresses{{}}.ip ,event.computer.network_addresses{{}}.mac ,event.computer.connector_guid | dedup event.computer.connector_guid"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="query_splunk", separator=", ")

    run_query_hostname(container=container)

    return

def run_query_hostname(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_query_hostname() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_query_hostname' call
    formatted_data_1 = phantom.get_format_data(name='query_splunk')

    parameters = []
    
    # build parameters list for 'run_query_hostname' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=dest_malicious, name="run_query_hostname")

    return

def transform_url_to_send_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('transform_url_to_send_email() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.requestURL', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]

    transform_url_to_send_email__transformURL = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    transformURL = []
    for url in container_item_0:
        transformURL.append(url.replace(".","[dot]"))
    phantom.debug("transformURL = ")
    phantom.debug(transformURL)
    transform_url_to_send_email__transformURL = transformURL    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='transform_url_to_send_email:transformURL', value=json.dumps(transform_url_to_send_email__transformURL))
    format_22(container=container)

    return

def format_21(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_21() called')
    
    template = """This is an automated message to inform you the IOC detected in incident. (No automatic containment is executed by the playbook). 

====================
[Case ID]: {0}
[Case Name]: {1}
[IOC to contain]: {2}
===================="""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
        "container:name",
        "artifact:*.cef.destinationAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_21", separator=", ")

    add_note_25(container=container)

    return

def format_22(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_22() called')
    
    template = """This is an automated message to inform you the IOC detected in incident. (No automatic containment is executed by the playbook). 

====================
[Case ID]: {0}
[Case Name]: {1}
[IOC to contain]: {2}
===================="""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
        "container:name",
        "transform_url_to_send_email:custom_function:transformURL",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_22", separator=", ")

    add_note_26(container=container)

    return

def add_note_25(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_25() called')

    formatted_data_1 = phantom.get_format_data(name='format_21')

    note_title = ""
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    cf_local_ADD_IOC_Containment_LIST_2(container=container)

    return

def add_note_26(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_26() called')

    formatted_data_1 = phantom.get_format_data(name='format_22')

    note_title = ""
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    cf_local_ADD_IOC_Containment_LIST_1(container=container)

    return

def cf_local_Set_last_automated_action_12(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_Set_last_automated_action_12() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "Enriched",
        ],
    ]

    parameters = []

    literal_values_0_0 = [item[0] for item in literal_values_0]
    container_property_0_0 = [item[0] for item in container_property_0]

    parameters.append({
        'a_status': literal_values_0_0,
        'Container_id': container_property_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/Set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/Set_last_automated_action', parameters=parameters, name='cf_local_Set_last_automated_action_12')

    return

def cf_local_Set_last_automated_action_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_Set_last_automated_action_13() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "Enriched",
        ],
    ]

    parameters = []

    literal_values_0_0 = [item[0] for item in literal_values_0]
    container_property_0_0 = [item[0] for item in container_property_0]

    parameters.append({
        'a_status': literal_values_0_0,
        'Container_id': container_property_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/Set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/Set_last_automated_action', parameters=parameters, name='cf_local_Set_last_automated_action_13')

    return

def cf_local_ADD_IOC_Containment_LIST_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_ADD_IOC_Containment_LIST_1() called')
    
    container_data_0 = phantom.collect2(container=container, datapath=['artifact:*.cef.requestURL', 'artifact:*.id'])
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "url",
        ],
    ]

    parameters = []

    for item0 in literal_values_0:
        for item1 in container_data_0:
            for item2 in container_property_0:
                parameters.append({
                    'IOC_Type': item0[0],
                    'input_IOC': item1[0],
                    'Container_id': item2[0],
                })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/ADD_IOC_Containment_LIST", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/ADD_IOC_Containment_LIST', parameters=parameters, name='cf_local_ADD_IOC_Containment_LIST_1', callback=cf_local_Set_last_automated_action_13)

    return

def cf_local_ADD_IOC_Containment_LIST_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_ADD_IOC_Containment_LIST_2() called')
    
    container_data_0 = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "ip",
        ],
    ]

    parameters = []

    for item0 in literal_values_0:
        for item1 in container_data_0:
            for item2 in container_property_0:
                parameters.append({
                    'IOC_Type': item0[0],
                    'input_IOC': item1[0],
                    'Container_id': item2[0],
                })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/ADD_IOC_Containment_LIST", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/ADD_IOC_Containment_LIST', parameters=parameters, name='cf_local_ADD_IOC_Containment_LIST_2', callback=cf_local_Set_last_automated_action_12)

    return

def playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEKTBCS_URL_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEKTBCS_URL_1() called')
    
    # call playbook "local/PLAYBOOK-CONTAIN-INDICATOR-FORTIGATEKTBCS-URL", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/PLAYBOOK-CONTAIN-INDICATOR-FORTIGATEKTBCS-URL", container=container, name="playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEKTBCS_URL_1", callback=decision_15)

    return

def playbook_local_KTB_CONTAIN_EXTERNAL_IP_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_KTB_CONTAIN_EXTERNAL_IP_1() called')
    
    # call playbook "local/KTB CONTAIN EXTERNAL IP", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/KTB CONTAIN EXTERNAL IP", container=container, name="playbook_local_KTB_CONTAIN_EXTERNAL_IP_1", callback=decision_17)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return