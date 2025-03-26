"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'playbook_local_KTB_ENRICH_EMAIL_1' block
    playbook_local_KTB_ENRICH_EMAIL_1(container=container)

    return

def playbook_local_KTB_ENRICH_EMAIL_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_KTB_ENRICH_EMAIL_1() called')
    
    # call playbook "local/KTB-ENRICH-EMAIL", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/KTB-ENRICH-EMAIL", container=container, name="playbook_local_KTB_ENRICH_EMAIL_1", callback=Get_email_artifacts)

    return

"""
Check if there are malicious artifacts
"""
def Check_if_there_are_malicious_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_if_there_are_malicious_artifacts() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.requestURL_malicious", "!=", ""],
            ["artifact:*.cef.destinationDnsDomain_malicious", "!=", ""],
            ["artifact:*.cef.fileHash_malicious", "!=", ""],
            ["artifact:*.cef.fromEmail_actual_sender_malicious", "!=", ""],
        ],
        scope="all",
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        Check_each_artifact_and_add_note(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    Filter_out_email_contains_SPF(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Check each artifact and add note
"""
def Check_each_artifact_and_add_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_each_artifact_and_add_note() called')
    
    input_parameter_0 = ""

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['artifact:*.cef.requestURL', 'artifact:*.cef.requestURL_malicious'])
    filtered_artifacts_data_2 = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationDnsDomain', 'artifact:*.cef.destinationDnsDomain_malicious'])
    filtered_artifacts_data_3 = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHashSha256', 'artifact:*.cef.fileHash_malicious'])
    filtered_artifacts_data_4 = phantom.collect2(container=container, datapath=['artifact:*.cef.fromEmail_actual_sender', 'artifact:*.cef.fromEmail_actual_sender_malicious'])
    malicious_urls = [item[0] for item in filtered_artifacts_data_1]
    malicious_domains = [item[0] for item in filtered_artifacts_data_2]
    malicious_files = [item[0] for item in filtered_artifacts_data_3]
    malicious_mails = [item[0] for item in filtered_artifacts_data_4]

    is_malicious_urls = [item[1] for item in filtered_artifacts_data_1]
    is_malicious_domains = [item[1] for item in filtered_artifacts_data_2]
    is_malicious_files = [item[1] for item in filtered_artifacts_data_3]
    is_malicious_mails = [item[1] for item in filtered_artifacts_data_4]
    
    content = ""
    
    if malicious_urls:
        content += "**List of malicious URL(s):**\n"
        for i in range(len(malicious_urls)):
            if is_malicious_urls[i]:
                content += f"- `{malicious_urls[i]}`\n"
        content += "\n\n"
    if malicious_domains:
        content += "**List of malicious domain(s):**\n"
        for i in range(len(malicious_domains)):
            if is_malicious_domains[i]:
                content += f"- `{malicious_domains[i]}`\n"
        content += "\n\n"
    if malicious_files:
        content += "**List of malicious file(s):**\n"
        for i in range(len(malicious_files)):
            if is_malicious_files[i]:
                content += f"- `{malicious_files[i]}`\n"
        content += "\n\n"
    if malicious_mails:
        content += "**List of malicious e-mail address(es):**\n"
        for i in range(len(malicious_mails)):
            if is_malicious_mails[i]:
                content += f"- `{malicious_mails[i]}`\n"
        content += "\n\n"
        
    parameters = []
    
    # build parameters list for 'add_note_2' call
    parameters.append({
        'title': "Playbook Summary: Found malicious artifact(s) on this e-mail",
        'content': content,
        'container_id': "",
        'phase_id': "",
    })

    phantom.act(action="add note", parameters=parameters, assets=['phantom asset'], name="add_note_summary")

    ################################################################################
    ## Custom Code End
    ################################################################################
    join_Format_user_email_being_sent(container=container)

    return

"""
Send email to affected user
"""
def Send_email_to_affected_user(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Send_email_to_affected_user() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    Distinguish_email_artifacts__user_email_address = json.loads(phantom.get_run_data(key='Distinguish_email_artifacts:user_email_address'))
    # collect data for 'Send_email_to_affected_user' call
    formatted_data_1 = phantom.get_format_data(name='Format_user_email_being_sent')

    parameters = []
    
    # build parameters list for 'Send_email_to_affected_user' call
    parameters.append({
        'cc': "",
        'to': Distinguish_email_artifacts__user_email_address,
        'bcc': "",
        'body': formatted_data_1,
        'from': "no-reply-phantom@ktbcs.co.th",
        'headers': "",
        'subject': "[SOAR] Suspicious E-mail Notification",
        'attachments': "",
    })

    phantom.act(action="send email", parameters=parameters, assets=['smtp asset'], callback=set_status_set_severity_promote_to_case_1, name="Send_email_to_affected_user")

    return

def set_status_set_severity_promote_to_case_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_set_severity_promote_to_case_1() called')

    phantom.set_status(container=container, status="In progress")

    phantom.set_severity(container=container, severity="Low")

    phantom.promote(container=container, template="KTB Workbook")
    join_cf_local_Set_last_automated_action_1(container=container)

    return

"""
Get email artifacts
"""
def Get_email_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Get_email_artifacts() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.fromEmail_actual_sender", "!=", ""],
        ],
        name="Get_email_artifacts:condition_1",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Distinguish_email_artifacts(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Format user email being sent
"""
def Format_user_email_being_sent(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_user_email_being_sent() called')
    
    template = """This is an automated message to inform you regarding the e-mail you reported to us recently.
The e-mail you reported (sent by `{0}`) is malicious and you should not open any attachments or click any links."""

    # parameter list for template variable replacement
    parameters = [
        "Distinguish_email_artifacts:custom_function:suspected_sender_email_address",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_user_email_being_sent", separator=", ")

    Send_email_to_affected_user(container=container)

    return

def join_Format_user_email_being_sent(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_Format_user_email_being_sent() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_Format_user_email_being_sent_called'):
        return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(playbook_names=['playbook_local_KTB_ENRICH_EMAIL_1']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_Format_user_email_being_sent_called', value='Format_user_email_being_sent')
        
        # call connected block "Format_user_email_being_sent"
        Format_user_email_being_sent(container=container, handle=handle)
    
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
    phantom.custom_function(custom_function='local/Set_last_automated_action', parameters=parameters, name='cf_local_Set_last_automated_action_1')

    return

def join_cf_local_Set_last_automated_action_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_cf_local_Set_last_automated_action_1() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_cf_local_Set_last_automated_action_1_called'):
        return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['Send_email_to_affected_user', 'Add_Note_non_malicious']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_cf_local_Set_last_automated_action_1_called', value='cf_local_Set_last_automated_action_1')
        
        # call connected block "cf_local_Set_last_automated_action_1"
        cf_local_Set_last_automated_action_1(container=container, handle=handle)
    
    return

"""
Format note non malicious 
"""
def Format_note_non_malicious(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_note_non_malicious() called')
    
    template = """No malicious artifacts were found on this e-mail and SPF validation is pass."""

    # parameter list for template variable replacement
    parameters = [
        "0",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_note_non_malicious", separator=", ")

    Add_Note_non_malicious(container=container)

    return

"""
Add Note non malicious
"""
def Add_Note_non_malicious(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_Note_non_malicious() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Add_Note_non_malicious' call
    formatted_data_1 = phantom.get_format_data(name='Format_note_non_malicious')

    parameters = []
    
    # build parameters list for 'Add_Note_non_malicious' call
    parameters.append({
        'title': "Playbook Summary: Non-malicious",
        'content': formatted_data_1,
        'phase_id': "",
        'container_id': "",
    })

    phantom.act(action="add note", parameters=parameters, assets=['phantom asset'], callback=set_status_set_severity_2, name="Add_Note_non_malicious")

    return

def set_status_set_severity_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_set_severity_2() called')

    phantom.set_status(container=container, status="Open")

    phantom.set_severity(container=container, severity="Low")
    join_cf_local_Set_last_automated_action_1(container=container)

    return

def SPF_check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('SPF_check() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["pass (", "not in", "filtered-data:Filter_out_email_contains_SPF:condition_1:artifact:*.cef.emailHeaders.Received-SPF"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Prepare_for_SPF_failed_result(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    Format_note_non_malicious(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Filter out email contains SPF
"""
def Filter_out_email_contains_SPF(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_out_email_contains_SPF() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:Get_email_artifacts:condition_1:artifact:*.cef.fromEmail_actual_sender", "==", "Distinguish_email_artifacts:custom_function:suspected_sender_email_address"],
        ],
        name="Filter_out_email_contains_SPF:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        SPF_check(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Distinguish email artifacts
"""
def Distinguish_email_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Distinguish_email_artifacts() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Get_email_artifacts:condition_1:artifact:*.id', 'filtered-data:Get_email_artifacts:condition_1:artifact:*.cef.fromEmail_actual_sender', 'filtered-data:Get_email_artifacts:condition_1:artifact:*.cef.emailHeaders.Date'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_2 = [item[2] for item in filtered_artifacts_data_1]

    Distinguish_email_artifacts__suspected_sender_email_address = None
    Distinguish_email_artifacts__user_email_address = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    from datetime import datetime 
    # datetime format: "Wed, 1 Jun 2022 15:37:58 +0700"
    artifact_ids = filtered_artifacts_item_1_0
    sender_emails = filtered_artifacts_item_1_1
    timestamps = [datetime.strptime(datetime_str, '%a, %d %b %Y %H:%M:%S %z') for datetime_str in filtered_artifacts_item_1_2]
    
    # init variables
    suspected_sender_email_address = sender_emails[0]
    user_email_address = sender_emails[0]
    max_timestamp = timestamps[0]
    min_timestamp = timestamps[0]
    
    #timestamps =  [ datetime_str.split("+") for datetime_str in filtered_artifacts_item_1_2]
    
    #phantom.debug(artifact_ids)
    #phantom.debug(sender_emails)
    #for timestamp in timestamps:
    #    phantom.debug(timestamp)
    #phantom.debug(timestamps[0] > timestamps[1])
    for i in range(len(artifact_ids)):
        if timestamps[i] > max_timestamp:
            user_email_address = sender_emails[i]
            max_timestamp = timestamps[i]
        
        if timestamps[i] < min_timestamp:
            suspected_sender_email_address = sender_emails[i]
            min_timestamp = timestamps[i]
    
    #phantom.debug(f"User: {user_email_address}")
    #phantom.debug(f"Suspect: {suspected_sender_email_address}")
    Distinguish_email_artifacts__suspected_sender_email_address = suspected_sender_email_address
    Distinguish_email_artifacts__user_email_address = user_email_address

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Distinguish_email_artifacts:suspected_sender_email_address', value=json.dumps(Distinguish_email_artifacts__suspected_sender_email_address))
    phantom.save_run_data(key='Distinguish_email_artifacts:user_email_address', value=json.dumps(Distinguish_email_artifacts__user_email_address))
    Check_if_there_are_malicious_artifacts(container=container)

    return

"""
Prepare for SPF failed result
"""
def Prepare_for_SPF_failed_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Prepare_for_SPF_failed_result() called')
    
    template = """This e-mail (sent by `{0}`) is suspected to be MALICIOUS as it didn't pass SPF validation."""

    # parameter list for template variable replacement
    parameters = [
        "Distinguish_email_artifacts:custom_function:suspected_sender_email_address",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Prepare_for_SPF_failed_result", separator=", ")

    Add_note_for_SPF_failed(container=container)

    return

"""
Add note for SPF failed
"""
def Add_note_for_SPF_failed(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_for_SPF_failed() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Add_note_for_SPF_failed' call
    formatted_data_1 = phantom.get_format_data(name='Prepare_for_SPF_failed_result')

    parameters = []
    
    # build parameters list for 'Add_note_for_SPF_failed' call
    parameters.append({
        'title': "Playbook Summary: SPF validation flagged this e-mail as malicious",
        'content': formatted_data_1,
        'phase_id': "",
        'container_id': "",
    })

    phantom.act(action="add note", parameters=parameters, assets=['phantom asset'], callback=join_Format_user_email_being_sent, name="Add_note_for_SPF_failed")

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