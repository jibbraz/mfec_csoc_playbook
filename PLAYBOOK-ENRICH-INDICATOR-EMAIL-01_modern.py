"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'playbook_local_KTB_ENRICH_EMAIL_1' block
    playbook_local_KTB_ENRICH_EMAIL_1(container=container)

    return

@phantom.playbook_block()
def playbook_local_KTB_ENRICH_EMAIL_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_KTB_ENRICH_EMAIL_1() called')
    
    # call playbook "local/ktb-enrich-email", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/ktb-enrich-email", container=container, name="playbook_local_KTB_ENRICH_EMAIL_1", callback=get_email_artifacts)

    return

"""
Check if there are malicious artifacts
"""
@phantom.playbook_block()
def check_if_there_are_malicious_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_if_there_are_malicious_artifacts() called')

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
        check_each_artifact_and_add_note(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    filter_out_email_contains_spf(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Check each artifact and add note
"""
@phantom.playbook_block()
def check_each_artifact_and_add_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_each_artifact_and_add_note() called')
    
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
    join_format_user_email_being_sent(container=container)

    return

"""
Send email to affected user
"""
@phantom.playbook_block()
def send_email_to_affected_user(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_email_to_affected_user() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    distinguish_email_artifacts__user_email_address = json.loads(phantom.get_run_data(key='distinguish_email_artifacts:user_email_address'))
    # collect data for 'send_email_to_affected_user' call
    formatted_data_1 = phantom.get_format_data(name='format_user_email_being_sent')

    parameters = []
    
    # build parameters list for 'send_email_to_affected_user' call
    parameters.append({
        'cc': "",
        'to': distinguish_email_artifacts__user_email_address,
        'bcc': "",
        'body': formatted_data_1,
        'from': "no-reply-phantom@ktbcs.co.th",
        'headers': "",
        'subject': "[SOAR] Suspicious E-mail Notification",
        'attachments': "",
    })

    phantom.act(action="send email", parameters=parameters, assets=['smtp asset'], callback=set_status_set_severity_promote_to_case_1, name="send_email_to_affected_user")

    return

@phantom.playbook_block()
def set_status_set_severity_promote_to_case_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_set_severity_promote_to_case_1() called')

    phantom.set_status(container=container, status="In progress")

    phantom.set_severity(container=container, severity="Low")

    phantom.promote(container=container, template="KTB Workbook")
    join_cf_local_set_last_automated_action_1(container=container)

    return

"""
Get email artifacts
"""
@phantom.playbook_block()
def get_email_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_email_artifacts() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.fromEmail_actual_sender", "!=", ""],
        ],
        name="get_email_artifacts:condition_1",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        distinguish_email_artifacts(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Format user email being sent
"""
@phantom.playbook_block()
def format_user_email_being_sent(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_user_email_being_sent() called')
    
    template = """This is an automated message to inform you regarding the e-mail you reported to us recently.
The e-mail you reported (sent by `{0}`) is malicious and you should not open any attachments or click any links."""

    # parameter list for template variable replacement
    parameters = [
        "distinguish_email_artifacts:custom_function:suspected_sender_email_address",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_user_email_being_sent", separator=", ")

    send_email_to_affected_user(container=container)

    return

@phantom.playbook_block()
def join_format_user_email_being_sent(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_format_user_email_being_sent() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_format_user_email_being_sent_called'):
        return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(playbook_names=['playbook_local_KTB_ENRICH_EMAIL_1']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_format_user_email_being_sent_called', value='format_user_email_being_sent')
        
        # call connected block "format_user_email_being_sent"
        format_user_email_being_sent(container=container, handle=handle)
    
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
def join_cf_local_set_last_automated_action_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_cf_local_set_last_automated_action_1() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_cf_local_set_last_automated_action_1_called'):
        return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['send_email_to_affected_user', 'add_note_non_malicious']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_cf_local_set_last_automated_action_1_called', value='cf_local_set_last_automated_action_1')
        
        # call connected block "cf_local_set_last_automated_action_1"
        cf_local_set_last_automated_action_1(container=container, handle=handle)
    
    return

"""
Format note non malicious 
"""
@phantom.playbook_block()
def format_note_non_malicious(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_note_non_malicious() called')
    
    template = """No malicious artifacts were found on this e-mail and SPF validation is pass."""

    # parameter list for template variable replacement
    parameters = [
        "0",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_note_non_malicious", separator=", ")

    add_note_non_malicious(container=container)

    return

"""
Add Note non malicious
"""
@phantom.playbook_block()
def add_note_non_malicious(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_non_malicious() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_note_non_malicious' call
    formatted_data_1 = phantom.get_format_data(name='format_note_non_malicious')

    parameters = []
    
    # build parameters list for 'add_note_non_malicious' call
    parameters.append({
        'title': "Playbook Summary: Non-malicious",
        'content': formatted_data_1,
        'phase_id': "",
        'container_id': "",
    })

    phantom.act(action="add note", parameters=parameters, assets=['phantom asset'], callback=set_status_set_severity_2, name="add_note_non_malicious")

    return

@phantom.playbook_block()
def set_status_set_severity_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_set_severity_2() called')

    phantom.set_status(container=container, status="Open")

    phantom.set_severity(container=container, severity="Low")
    join_cf_local_set_last_automated_action_1(container=container)

    return

@phantom.playbook_block()
def spf_check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('spf_check() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["pass (", "not in", "filtered-data:filter_out_email_contains_spf:condition_1:artifact:*.cef.emailHeaders.Received-SPF"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        prepare_for_spf_failed_result(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    format_note_non_malicious(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Filter out email contains SPF
"""
@phantom.playbook_block()
def filter_out_email_contains_spf(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_out_email_contains_spf() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:get_email_artifacts:condition_1:artifact:*.cef.fromEmail_actual_sender", "==", "distinguish_email_artifacts:custom_function:suspected_sender_email_address"],
        ],
        name="filter_out_email_contains_spf:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        spf_check(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Distinguish email artifacts
"""
@phantom.playbook_block()
def distinguish_email_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('distinguish_email_artifacts() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:get_email_artifacts:condition_1:artifact:*.id', 'filtered-data:get_email_artifacts:condition_1:artifact:*.cef.fromEmail_actual_sender', 'filtered-data:get_email_artifacts:condition_1:artifact:*.cef.emailHeaders.Date'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_2 = [item[2] for item in filtered_artifacts_data_1]

    distinguish_email_artifacts__suspected_sender_email_address = None
    distinguish_email_artifacts__user_email_address = None

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
    distinguish_email_artifacts__suspected_sender_email_address = suspected_sender_email_address
    distinguish_email_artifacts__user_email_address = user_email_address

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='distinguish_email_artifacts:suspected_sender_email_address', value=json.dumps(distinguish_email_artifacts__suspected_sender_email_address))
    phantom.save_run_data(key='distinguish_email_artifacts:user_email_address', value=json.dumps(distinguish_email_artifacts__user_email_address))
    check_if_there_are_malicious_artifacts(container=container)

    return

"""
Prepare for SPF failed result
"""
@phantom.playbook_block()
def prepare_for_spf_failed_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prepare_for_spf_failed_result() called')
    
    template = """This e-mail (sent by `{0}`) is suspected to be MALICIOUS as it didn't pass SPF validation."""

    # parameter list for template variable replacement
    parameters = [
        "distinguish_email_artifacts:custom_function:suspected_sender_email_address",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="prepare_for_spf_failed_result", separator=", ")

    add_note_for_spf_failed(container=container)

    return

"""
Add note for SPF failed
"""
@phantom.playbook_block()
def add_note_for_spf_failed(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_for_spf_failed() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_note_for_spf_failed' call
    formatted_data_1 = phantom.get_format_data(name='prepare_for_spf_failed_result')

    parameters = []
    
    # build parameters list for 'add_note_for_spf_failed' call
    parameters.append({
        'title': "Playbook Summary: SPF validation flagged this e-mail as malicious",
        'content': formatted_data_1,
        'phase_id': "",
        'container_id': "",
    })

    phantom.act(action="add note", parameters=parameters, assets=['phantom asset'], callback=join_format_user_email_being_sent, name="add_note_for_spf_failed")

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