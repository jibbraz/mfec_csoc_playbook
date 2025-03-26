"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'decision_15' block
    decision_15(container=container)

    return

def get_events_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_events_1() called')

    # collect data for 'get_events_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_events_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'severity': "High",
                'hours_back': 2,
                'attacker_ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="get events", parameters=parameters, assets=['attivo-csoc'], callback=playbook_local_KTB_Triage_Playbook_for_Generic_Label_1, name="get_events_1")

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_events_1:action_result.status", "==", "success"],
            ["get_events_1:action_result.summary.total_events", ">=", 3],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        Format_query_search_splunk_event(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        decision_14(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def Format_query_search_splunk_event(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_query_search_splunk_event() called')
    
    template = """index=phantom_container name=\"*{0}*\" container_label!=attivo earliest=-2d@d latest=now | dedup id"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_query_search_splunk_event", separator=", ")

    Run_query_search_splunk_event(container=container)

    return

def Run_query_search_splunk_event(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Run_query_search_splunk_event() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Run_query_search_splunk_event' call
    formatted_data_1 = phantom.get_format_data(name='Format_query_search_splunk_event')

    parameters = []
    
    # build parameters list for 'Run_query_search_splunk_event' call
    parameters.append({
        'ph': "",
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'end_time': "",
        'parse_only': "",
        'start_time': "",
        'search_mode': "",
        'attach_result': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=join_decision_6, name="Run_query_search_splunk_event")

    return

def check_critical_and_no_contain_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_critical_and_no_contain_list() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]

    check_critical_and_no_contain_list__InNoContainList = None
    check_critical_and_no_contain_list__InCriticalList = None

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
    ############################################################
    ############################################################
    ############################################################
    ############################################################
    ############################################################
    ############################################################
    ############################################################
    ############################################################
    ############################################################
    ############################################################
    ############################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='check_critical_and_no_contain_list:InNoContainList', value=json.dumps(check_critical_and_no_contain_list__InNoContainList))
    phantom.save_run_data(key='check_critical_and_no_contain_list:InCriticalList', value=json.dumps(check_critical_and_no_contain_list__InCriticalList))
    decision_4(container=container)

    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["check_critical_and_no_contain_list:custom_function:InNoContainList", "==", 0],
            ["check_critical_and_no_contain_list:custom_function:InCriticalList", "==", 0],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        decision_12(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    join_format_no_contain_point_found(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def format_contain_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_contain_email() called')
    
    template = """This is an automated message to inform you of the containment approval request in phantom, please login phantom and approve.

Case Name: {0}
Case Owner: {1}
Contain Point: {2}

Please do not respond to this message."""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:owner_name",
        "artifact:*.cef.sourceAddress_QueryFrom",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_contain_email", separator=", ")

    send_email_2(container=container)

    return

def send_email_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_email_2() called')

    # collect data for 'send_email_2' call
    formatted_data_1 = phantom.get_format_data(name='format_contain_email')

    parameters = []
    
    # build parameters list for 'send_email_2' call
    parameters.append({
        'cc': "",
        'to': "csoc.mdr@ktcs.co.th",
        'bcc': "",
        'body': formatted_data_1,
        'from': "no-reply-phantom@ktbcs.co.th",
        'headers': "",
        'subject': "SOAR - Containment Approval Needed - Notification",
        'attachments': "",
    })

    phantom.act(action="send email", parameters=parameters, assets=['smtp asset'], callback=Check_Before_Contain_ISE, name="send_email_2")

    return

def Check_Before_Contain_ISE(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_Before_Contain_ISE() called')
    
    # set user and message variables for phantom.prompt call
    user = "CSOC Manager"
    message = """***WARNING*** 
Do you want to proceed with containment?

Attacker Info:
Source Address = {0}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="Check_Before_Contain_ISE", separator=", ", parameters=parameters, response_types=response_types, callback=decision_5)

    return

def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_5() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Check_Before_Contain_ISE:action_result.status", "==", "success"],
            ["Check_Before_Contain_ISE:action_result.summary.responses.0", "==", "Yes"],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        playbook_local_KTB_CONTAIN_INTERNAL_IP_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Check_Before_Contain_ISE:action_result.status", "==", "success"],
            ["Check_Before_Contain_ISE:action_result.summary.responses.0", "==", "No"],
        ],
        logical_operator='and')

    # call connected blocks if condition 2 matched
    if matched:
        format_unsuccessful_request(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 3
    format_unsuccessful_request(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def decision_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_6() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Run_query_search_splunk_event:action_result.summary.total_events", ">=", 1],
            ["run_splunk_query_hostname:action_result.summary.total_events", ">=", 1],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        join_promote_to_case_set_status_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Run_query_search_splunk_event:action_result.summary.total_events", ">=", 2],
            ["run_splunk_query_hostname:action_result.summary.total_events", ">=", 2],
        ],
        logical_operator='or')

    # call connected blocks if condition 2 matched
    if matched:
        join_promote_to_case_set_status_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 3
    get_events_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def join_decision_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_decision_6() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['Run_query_search_splunk_event', 'run_splunk_query_hostname']):
        
        # call connected block "decision_6"
        decision_6(container=container, handle=handle)
    
    return

def promote_to_case_set_status_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('promote_to_case_set_status_2() called')

    phantom.promote(container=container, template="KTB Workbook")

    phantom.set_status(container=container, status="In progress")

    container = phantom.get_container(container.get('id', None))
    check_critical_and_no_contain_list(container=container)

    return

def join_promote_to_case_set_status_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_promote_to_case_set_status_2() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_promote_to_case_set_status_2_called'):
        return

    # no callbacks to check, call connected block "promote_to_case_set_status_2"
    phantom.save_run_data(key='join_promote_to_case_set_status_2_called', value='promote_to_case_set_status_2', auto=True)

    promote_to_case_set_status_2(container=container, handle=handle)
    
    return

def get_events_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_events_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_events_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_events_2' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'severity': "Very High",
                'hours_back': 72,
                'attacker_ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="get events", parameters=parameters, assets=['attivo-csoc'], callback=custom_function_9, name="get_events_2")

    return

def custom_function_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('custom_function_9() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['get_events_2:action_result.data.*.attack_name', 'get_events_2:action_result.parameter.attacker_ip'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_1_1 = [item[1] for item in results_data_1]

    custom_function_9__ContainSourceAddress = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    custom_function_9__ContainSourceAddress = []
    for item in results_item_1_0:
        if item  == "Deceptive Credential Usage":
            custom_function_9__ContainSourceAddress.append(results_item_1_1)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='custom_function_9:ContainSourceAddress', value=json.dumps(custom_function_9__ContainSourceAddress))
    decision_8(container=container)

    return

def decision_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_8() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["custom_function_9:custom_function:ContainSourceAddress", "!=", []],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        join_promote_to_case_set_status_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    join_format_no_contain_point_found(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def playbook_local_PLAYBOOK_ENRICH_INDICATOR_ALL_01_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PLAYBOOK_ENRICH_INDICATOR_ALL_01_1() called')
    
    # call playbook "local/PLAYBOOK-ENRICH-INDICATOR-ALL-01", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/PLAYBOOK-ENRICH-INDICATOR-ALL-01", container=container, name="playbook_local_PLAYBOOK_ENRICH_INDICATOR_ALL_01_1", callback=set_status_9)

    return

def format_no_contain_point_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_no_contain_point_found() called')
    
    template = """Detail of Attack:
Event ID: {7}
Event Name: {8}
Source IP: {5}
Time Period: {6} hour(s)

Action: No Contain Point Found. Further  investigation recommended.

%%
###
Attack name:{0}
Target IP: {1}
Severity: {2}
Target OS: {3}
Timestamp: {4}

%%"""

    # parameter list for template variable replacement
    parameters = [
        "get_events_1:action_result.data.*.attack_name",
        "get_events_1:action_result.data.*.target_ip",
        "get_events_1:action_result.data.*.severity",
        "get_events_1:action_result.data.*.target_os",
        "get_events_1:action_result.data.*.timestamp",
        "get_events_1:action_result.parameter.attacker_ip",
        "get_events_1:action_result.parameter.hours_back",
        "container:id",
        "container:name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_no_contain_point_found", separator=", ")

    send_email_4(container=container)

    return

def join_format_no_contain_point_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_format_no_contain_point_found() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_format_no_contain_point_found_called'):
        return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['run_splunk_query_hostname']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_format_no_contain_point_found_called', value='format_no_contain_point_found')
        
        # call connected block "format_no_contain_point_found"
        format_no_contain_point_found(container=container, handle=handle)
    
    return

def send_email_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_email_4() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_4' call
    formatted_data_1 = phantom.get_format_data(name='format_no_contain_point_found')

    parameters = []
    
    # build parameters list for 'send_email_4' call
    parameters.append({
        'cc': "",
        'to': "csoc.mdr@ktcs.co.th",
        'bcc': "",
        'body': formatted_data_1,
        'from': "no-reply-phantom@ktbcs.co.th",
        'headers': "",
        'subject': "SOAR - Attivo Deception Notification",
        'attachments': "",
    })

    phantom.act(action="send email", parameters=parameters, assets=['smtp asset'], callback=add_note_5, name="send_email_4")

    return

def add_note_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_5() called')

    formatted_data_1 = phantom.get_format_data(name='format_no_contain_point_found')

    note_title = "Note from Automation Playbook"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    container = phantom.get_container(container.get('id', None))
    cf_local_Set_last_automated_action_4(container=container)

    return

def format_unsuccessful_request(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_unsuccessful_request() called')
    
    template = """This is an automated message to inform you of the containment approval is denied or timer expired (30 minutes)

Case Name: {0}
Case ID: {1}
Contain Point: {2}

Manual action required. Please do not respond to this message."""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:id",
        "artifact:*.cef.sourceAddress_QueryFrom",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_unsuccessful_request", separator=", ")

    send_email6(container=container)

    return

def send_email6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_email6() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email6' call
    formatted_data_1 = phantom.get_format_data(name='format_unsuccessful_request')

    parameters = []
    
    # build parameters list for 'send_email6' call
    parameters.append({
        'cc': "",
        'to': "csoc.mdr@ktcs.co.th",
        'bcc': "",
        'body': formatted_data_1,
        'from': "no-reply-phantom@ktbcs.co.th",
        'headers': "",
        'subject': "SOAR - Containment Approval Unsuccessful - Notification",
        'attachments': "",
    })

    phantom.act(action="send email", parameters=parameters, assets=['smtp asset'], callback=add_note_8, name="send_email6")

    return

def playbook_local_KTB_CONTAIN_INTERNAL_IP_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_KTB_CONTAIN_INTERNAL_IP_1() called')
    
    # call playbook "local/KTB CONTAIN INTERNAL IP", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/KTB CONTAIN INTERNAL IP", container=container, name="playbook_local_KTB_CONTAIN_INTERNAL_IP_1", callback=decision_11)

    return

def decision_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_11() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.sourceAddress_ContainResult", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        set_status_add_note_6(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    add_note_7(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def set_status_add_note_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_add_note_6() called')

    phantom.set_status(container=container, status="Resolved")

    note_title = "Note from Automate Playbook"
    note_content = "Address Contain Successfully"
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    container = phantom.get_container(container.get('id', None))
    cf_local_Set_last_automated_action_2(container=container)

    return

def add_note_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_7() called')

    note_title = "Note from Automate Playbook"
    note_content = "Internal Address contain  unsuccessful. Manual actionrequired."
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    container = phantom.get_container(container.get('id', None))
    cf_local_Set_last_automated_action_1(container=container)

    return

def add_note_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_8() called')

    formatted_data_1 = phantom.get_format_data(name='format_unsuccessful_request')

    note_title = "Note from Automate Playbook"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    container = phantom.get_container(container.get('id', None))
    cf_local_Set_last_automated_action_3(container=container)

    return

def playbook_local_KTB_Triage_Playbook_for_Generic_Label_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_KTB_Triage_Playbook_for_Generic_Label_1() called')
    
    # call playbook "local/KTB Triage Playbook for Generic Label", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/KTB Triage Playbook for Generic Label", container=container, name="playbook_local_KTB_Triage_Playbook_for_Generic_Label_1", callback=decision_16)

    return

def decision_12(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_12() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.sourceAddress_QueryFrom", "==", "ISE"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        tag_ise_contain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.sourceAddress_QueryFrom", "==", "AMP"],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        join_format_no_contain_point_found(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 3
    tag_amp_contain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

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

def cf_local_Set_last_automated_action_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_Set_last_automated_action_4() called')
    
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
    phantom.custom_function(custom_function='local/Set_last_automated_action', parameters=parameters, name='cf_local_Set_last_automated_action_4')

    return

def decision_14(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_14() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.sourceAddress_hostname", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        format_query_search_hostname(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def format_query_search_hostname(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_query_search_hostname() called')
    
    template = """index=phantom_container name=\"*{0}*\" container_label!=attivo earliest=-2d@d latest=now  | dedup id"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress_hostname",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_query_search_hostname", separator=", ")

    run_splunk_query_hostname(container=container)

    return

def run_splunk_query_hostname(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_splunk_query_hostname() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_splunk_query_hostname' call
    formatted_data_1 = phantom.get_format_data(name='format_query_search_hostname')

    parameters = []
    
    # build parameters list for 'run_splunk_query_hostname' call
    parameters.append({
        'ph': "",
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'end_time': "",
        'parse_only': "",
        'start_time': "",
        'search_mode': "",
        'attach_result': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=join_decision_6, name="run_splunk_query_hostname")

    return

def decision_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_15() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        get_events_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def set_status_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_9() called')

    phantom.set_status(container=container, status="Open")

    container = phantom.get_container(container.get('id', None))
    decision_2(container=container)

    return

def format_contain_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_contain_note() called')
    
    template = """This is an automated message to inform you the IOC detected in incident. (No automatic containment is executed by the playbook). 

Case Name: {0}
Contain Point: {1}
Contain IOC: {2}"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "artifact:*.cef.sourceAddress_QueryFrom",
        "artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_contain_note", separator=", ")

    add_note_11(container=container)

    return

def join_format_contain_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_format_contain_note() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['Run_query_search_splunk_event', 'run_splunk_query_hostname', 'get_events_2']):
        
        # call connected block "format_contain_note"
        format_contain_note(container=container, handle=handle)
    
    return

def add_note_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_11() called')

    formatted_data_1 = phantom.get_format_data(name='format_contain_note')

    note_title = ""
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    container = phantom.get_container(container.get('id', None))
    cf_local_Set_last_automated_action_5(container=container)

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
    phantom.custom_function(custom_function='local/Set_last_automated_action', parameters=parameters, name='cf_local_Set_last_automated_action_5')

    return

def decision_16(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_16() called')
    
    status_param = container.get('status', None)

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            [status_param, "!=", "closed"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        playbook_local_PLAYBOOK_ENRICH_INDICATOR_ALL_01_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2

    return

def tag_amp_contain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('tag_amp_contain() called')

    phantom.add_tags(container=container, tags="amp_contain")

    container = phantom.get_container(container.get('id', None))
    join_format_contain_note(container=container)

    return

def tag_ise_contain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('tag_ise_contain() called')

    phantom.add_tags(container=container, tags="ise_contain")

    container = phantom.get_container(container.get('id', None))
    join_format_contain_note(container=container)

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