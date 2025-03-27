"""
add description
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'decision_2' block
    decision_2(container=container)

    return

@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationUserName", "!=", ""],
            ["artifact:*.cef.search_name", "!=", ""],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        playbook_local_ktb_triage_playbook_for_generic_label_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2

    return

@phantom.playbook_block()
def format_query_destinationusername(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_query_destinationusername() called')
    
    template = """earliest =-3d@d `notable`| search search_name=\"{1}\" user={0}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationUserName",
        "artifact:*.cef.search_name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_query_destinationusername", separator=", ")

    run_query_destinationusername(container=container)

    return

@phantom.playbook_block()
def run_query_destinationusername(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_query_destinationusername() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_query_destinationusername' call
    formatted_data_1 = phantom.get_format_data(name='format_query_destinationusername')

    parameters = []
    
    # build parameters list for 'run_query_destinationusername' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=decision_8, name="run_query_destinationusername")

    return

@phantom.playbook_block()
def decision_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_8() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["run_query_destinationusername:action_result.summary.total_events", ">=", 3],
            ["artifact:*.cef.destinationUserName_AD", "!=", "user not found"],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        check_no_contain_user_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    add_note_set_status_6(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

@phantom.playbook_block()
def add_note_set_status_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_set_status_6() called')

    note_title = "Note from Automation Playbook"
    note_content = "Notable event found from this user is less than 3 is last 24 hours."
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    phantom.set_status(container=container, status="Open")
    cf_local_set_last_automated_action_4(container=container)

    return

@phantom.playbook_block()
def format_email_contain_target_ad(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_email_contain_target_ad() called')
    
    template = """This is an automated message to inform you of the containment approval request in phantom, please login phantom and approve.

Case Name: {0}
Case ID: {1}
User: {2}
Contain Point: {3}

Source: {4}

Destination: {5}

Please do not respond to this message.

Link back to Phantom event
https://phantom.csoc.krungthai.local/mission/{1}/analyst/timeline"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:id",
        "artifact:*.cef.destinationUserName",
        "artifact:*.cef.destinationUserName_AD",
        "query_source_and_destination_by_user:action_result.data.*.src",
        "query_source_and_destination_by_user:action_result.data.*.dest_list",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_email_contain_target_ad", separator=", ")

    send_excessive_fail_contain_email(container=container)

    return

@phantom.playbook_block()
def send_excessive_fail_contain_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_excessive_fail_contain_email() called')

    # collect data for 'send_excessive_fail_contain_email' call
    formatted_data_1 = phantom.get_format_data(name='format_email_contain_target_ad')

    parameters = []
    
    # build parameters list for 'send_excessive_fail_contain_email' call
    parameters.append({
        'cc': "",
        'to': "security-infra@ktbcs.co.th",
        'bcc': "",
        'body': formatted_data_1,
        'from': "no-reply-phantom@ktbcs.co.th",
        'headers': "",
        'subject': "SOAR - Active Directory Containment Approval Needed - Notification",
        'attachments': "",
    })

    phantom.act(action="send email", parameters=parameters, assets=['smtp asset'], callback=join_ad_containment_confirmation, name="send_excessive_fail_contain_email")

    return

@phantom.playbook_block()
def ad_containment_confirmation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ad_containment_confirmation() called')
    
    # set user and message variables for phantom.prompt call
    user = "CSOC Manager"
    message = """***WARNING*** 
Do you want to proceed with containment?

Containment Info:
Case Name: {0}
Case ID: {1}
User: {2}
Contain Point: {3}"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:id",
        "artifact:*.cef.destinationUserName",
        "artifact:*.cef.destinationUserName_AD",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="ad_containment_confirmation", separator=", ", parameters=parameters, response_types=response_types, callback=decision_10)

    return

@phantom.playbook_block()
def join_ad_containment_confirmation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_ad_containment_confirmation() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_ad_containment_confirmation_called'):
        return

    # no callbacks to check, call connected block "ad_containment_confirmation"
    phantom.save_run_data(key='join_ad_containment_confirmation_called', value='ad_containment_confirmation', auto=True)

    ad_containment_confirmation(container=container, handle=handle)
    
    return

@phantom.playbook_block()
def decision_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_10() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["ad_containment_confirmation:action_result.status", "!=", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        format_unsuccessful_containment(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["ad_containment_confirmation:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        playbook_local_ktb_contain_user_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 3
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["ad_containment_confirmation:action_result.summary.responses.0", "==", "No"],
        ])

    # call connected blocks if condition 3 matched
    if matched:
        format_unsuccessful_containment(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def format_unsuccessful_containment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_unsuccessful_containment() called')
    
    template = """This is an automated message to inform you of the containment approval is denied or timer expired (30 minutes)

Case Name: {0}
Case ID: {1}
Contain Point: {2}

Manual action required. Please do not respond to this message."""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:id",
        "artifact:*.cef.destinationUserName_AD",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_unsuccessful_containment", separator=", ")

    send_email_4(container=container)

    return

@phantom.playbook_block()
def send_email_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_email_4() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_4' call
    formatted_data_1 = phantom.get_format_data(name='format_unsuccessful_containment')

    parameters = []
    
    # build parameters list for 'send_email_4' call
    parameters.append({
        'cc': "",
        'to': "security-infra@ktbcs.co.th",
        'bcc': "",
        'body': formatted_data_1,
        'from': "no-reply-phantom@ktbcs.co.th",
        'headers': "",
        'subject': "SOAR - Containment Approval Unsuccessful - Notification",
        'attachments': "",
    })

    phantom.act(action="send email", parameters=parameters, assets=['smtp asset'], callback=add_note_set_status_8, name="send_email_4")

    return

@phantom.playbook_block()
def add_note_set_status_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_set_status_8() called')

    formatted_data_1 = phantom.get_format_data(name='format_unsuccessful_containment')

    note_title = "Note from Automate Playbook"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    phantom.set_status(container=container, status="Pending")
    cf_local_set_last_automated_action_3(container=container)

    return

@phantom.playbook_block()
def playbook_local_ktb_contain_user_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_ktb_contain_user_1() called')
    
    # call playbook "local/KTB CONTAIN USER", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/KTB CONTAIN USER", container=container, name="playbook_local_ktb_contain_user_1", callback=decision_11)

    return

@phantom.playbook_block()
def decision_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_11() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationUserName_ContainResult", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        set_status_add_note_9(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    set_status_add_note_10(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

@phantom.playbook_block()
def set_status_add_note_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_add_note_9() called')

    phantom.set_status(container=container, status="Resolved")

    note_title = "Note from Automate Playbook"
    note_content = "Containment successful."
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    cf_local_set_last_automated_action_1(container=container)

    return

@phantom.playbook_block()
def set_status_add_note_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_add_note_10() called')

    phantom.set_status(container=container, status="Pending")

    note_title = "Note from Automate Playbook"
    note_content = "Containment unsuccessful. Manual investigation recommended."
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    cf_local_set_last_automated_action_2(container=container)

    return

@phantom.playbook_block()
def set_status_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_11() called')

    phantom.set_status(container=container, status="In progress")
    format_query_destinationusername(container=container)

    return

@phantom.playbook_block()
def playbook_local_ktb_triage_playbook_for_generic_label_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_ktb_triage_playbook_for_generic_label_1() called')
    
    # call playbook "local/KTB Triage Playbook for Generic Label", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/KTB Triage Playbook for Generic Label", container=container, name="playbook_local_ktb_triage_playbook_for_generic_label_1", callback=decision_12)

    return

@phantom.playbook_block()
def promote_to_case_12(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('promote_to_case_12() called')

    phantom.promote(container=container, template="KTB Workbook")
    join_decision_13(container=container)

    return

@phantom.playbook_block()
def cf_local_set_last_automated_action_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_set_last_automated_action_1() called')
    
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

    # call custom function "local/set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_last_automated_action', parameters=parameters, name='cf_local_set_last_automated_action_1')

    return

@phantom.playbook_block()
def cf_local_set_last_automated_action_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_set_last_automated_action_2() called')
    
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

    # call custom function "local/set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_last_automated_action', parameters=parameters, name='cf_local_set_last_automated_action_2')

    return

@phantom.playbook_block()
def cf_local_set_last_automated_action_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_set_last_automated_action_3() called')
    
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

    # call custom function "local/set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_last_automated_action', parameters=parameters, name='cf_local_set_last_automated_action_3')

    return

@phantom.playbook_block()
def cf_local_set_last_automated_action_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_set_last_automated_action_4() called')
    
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

    # call custom function "local/set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_last_automated_action', parameters=parameters, name='cf_local_set_last_automated_action_4')

    return

@phantom.playbook_block()
def decision_12(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_12() called')
    
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
        format_source_and_destination_by_user(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2

    return

@phantom.playbook_block()
def playbook_local_PLAYBOOK_ENRICH_INDICATOR_ALL_01_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PLAYBOOK_ENRICH_INDICATOR_ALL_01_1() called')
    
    # call playbook "local/playbook-enrich-indicator-all-01", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/playbook-enrich-indicator-all-01", container=container, name="playbook_local_PLAYBOOK_ENRICH_INDICATOR_ALL_01_1", callback=set_status_11)

    return

@phantom.playbook_block()
def format_source_and_destination_by_user(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_source_and_destination_by_user() called')
    
    template = """summariesonly=true values(\"Authentication.tag\") as \"tag\",dc(\"Authentication.dest\") as \"dest_count\",values(\"Authentication.dest\") as dest_list ,count dc(Authentication.src) AS src_count ,values(Authentication.src) AS src from datamodel=\"Authentication\".\"Authentication\" where nodename=\"Authentication.Failed_Authentication\" Authentication.user!=unknown (Authentication.app=\"win:*\" AND Authentication.user!=\"*\\$\") earliest=-1d latest= now() by \"Authentication.user\" \"Authentication.app\"
| rename Authentication.* AS *
| where  count>=1000 and user =\"{0}\""""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationUserName",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_source_and_destination_by_user", separator=", ")

    query_source_and_destination_by_user(container=container)

    return

"""
Query user to enrich source and destination
"""
@phantom.playbook_block()
def query_source_and_destination_by_user(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('query_source_and_destination_by_user() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'query_source_and_destination_by_user' call
    formatted_data_1 = phantom.get_format_data(name='format_source_and_destination_by_user')

    parameters = []
    
    # build parameters list for 'query_source_and_destination_by_user' call
    parameters.append({
        'query': formatted_data_1,
        'command': "tstats",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=join_decision_13, name="query_source_and_destination_by_user")

    return

@phantom.playbook_block()
def decision_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_13() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.search_name", "==", "Access - Brute Force Access Behavior Detected - Rule"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        format_16(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["run_query_destinationusername:artifact:*.cef.search_name", "==", "Access - Excessive Failed Logins by user - Rule"],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        format_15(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def join_decision_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_decision_13() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['run_query_destinationusername', 'query_source_and_destination_by_user']):
        
        # call connected block "decision_13"
        decision_13(container=container, handle=handle)
    
    return

@phantom.playbook_block()
def format_brute_force_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_brute_force_email() called')
    
    template = """This is an automated message to inform you of the containment approval request in phantom, please login phantom and approve.

Case Name: {0}
Case ID: {1}
User: {2}
Contain Point: {3}

Source: {4}

Destination: {5}

Please do not respond to this message.

Link back to Phantom event
https://phantom.csoc.krungthai.local/mission/{1}/analyst/timeline"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:id",
        "artifact:*.cef.destinationUserName",
        "artifact:*.cef.destinationUserName_AD",
        "query_source_and_destination_by_user:action_result.data.*.src",
        "query_source_and_destination_by_user:action_result.data.*.dest_list",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_brute_force_email", separator=", ")

    send_brute_force_contain_email(container=container)

    return

@phantom.playbook_block()
def send_brute_force_contain_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_brute_force_contain_email() called')

    # collect data for 'send_brute_force_contain_email' call
    formatted_data_1 = phantom.get_format_data(name='format_brute_force_email')

    parameters = []
    
    # build parameters list for 'send_brute_force_contain_email' call
    parameters.append({
        'cc': "",
        'to': "security-infra@ktbcs.co.th",
        'bcc': "",
        'body': formatted_data_1,
        'from': "no-reply-phantom@ktbcs.co.th",
        'headers': "",
        'subject': "SOAR - Active Directory Containment Approval Needed - Notification",
        'attachments': "",
    })

    phantom.act(action="send email", parameters=parameters, assets=['smtp asset'], callback=join_ad_containment_confirmation, name="send_brute_force_contain_email")

    return

@phantom.playbook_block()
def add_note_set_status_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_set_status_13() called')

    note_title = "Note from Automation Playbook"
    note_content = "User in no contain list."
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    phantom.set_status(container=container, status="Open")
    cf_local_set_last_automated_action_5(container=container)

    return

@phantom.playbook_block()
def cf_local_set_last_automated_action_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_set_last_automated_action_5() called')
    
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

    # call custom function "local/set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_last_automated_action', parameters=parameters, name='cf_local_set_last_automated_action_5')

    return

@phantom.playbook_block()
def check_no_contain_user_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_no_contain_user_list() called')
    
    id_value = container.get('id', None)
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationUserName', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]

    check_no_contain_user_list__cancontain = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    cancontain = True
    success, message, nocontainuser = phantom.get_list(list_name='nocontainuser')
    for user in container_item_0:
        if any(user in sublist for sublist in nocontainuser):
            cancontain = False
        if cancontain:
            phantom.debug("can contain")
        else:
            phantom.debug("cannot contain")
    check_no_contain_user_list__cancontain = cancontain
    ##########################################
    ##########################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='check_no_contain_user_list:cancontain', value=json.dumps(check_no_contain_user_list__cancontain))
    decision_15(container=container)

    return

@phantom.playbook_block()
def decision_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_15() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["check_no_contain_user_list:custom_function:cancontain", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        promote_to_case_12(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    add_note_set_status_13(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

@phantom.playbook_block()
def format_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_15() called')
    
    template = """This is an automated message to inform you the IOC detected in incident. (No automatic containment is executed by the playbook). 

Case Name: {0}
Case ID: {1}
User: {2}
Contain Point: {3}

Source: {4}

Destination: {5}"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:id",
        "artifact:*.cef.destinationUserName",
        "artifact:*.cef.destinationUserName_AD",
        "query_source_and_destination_by_user:artifact:*.cef.src",
        "query_source_and_destination_by_user:action_result.data.*.dest_list",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_15", separator=", ")

    add_note_15(container=container)

    return

@phantom.playbook_block()
def format_16(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_16() called')
    
    template = """This is an automated message to inform you the IOC detected in incident. (No automatic containment is executed by the playbook). 

Case Name: {0}
Case ID: {1}
User: {2}
Contain Point: {3}

Source: {4}

Destination: {5}"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:id",
        "artifact:*.cef.destinationUserName",
        "artifact:*.cef.destinationUserName_AD",
        "query_source_and_destination_by_user:artifact:*.cef.src",
        "query_source_and_destination_by_user:action_result.data.*.dest_list",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_16", separator=", ")

    add_note_14(container=container)

    return

@phantom.playbook_block()
def add_note_14(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_14() called')

    formatted_data_1 = phantom.get_format_data(name='format_16')

    note_title = ""
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    cf_local_set_last_automated_action_7(container=container)

    return

@phantom.playbook_block()
def add_note_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_15() called')

    formatted_data_1 = phantom.get_format_data(name='format_15')

    note_title = ""
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    cf_local_set_last_automated_action_6(container=container)

    return

@phantom.playbook_block()
def cf_local_set_last_automated_action_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_set_last_automated_action_6() called')
    
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

    # call custom function "local/set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_last_automated_action', parameters=parameters, name='cf_local_set_last_automated_action_6')

    return

@phantom.playbook_block()
def cf_local_set_last_automated_action_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_set_last_automated_action_7() called')
    
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

    # call custom function "local/set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_last_automated_action', parameters=parameters, name='cf_local_set_last_automated_action_7')

    return

@phantom.playbook_block()
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