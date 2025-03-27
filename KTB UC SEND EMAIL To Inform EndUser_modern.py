"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'decision_1' block
    decision_1(container=container)

    return

@phantom.playbook_block()
def format_mail_body(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_mail_body() called')
    
    template = """Hello ,

This is containment notification,  your host may be compromised.  your AMP account or IP/MAC will be isolated.

Case Name: {0}
Case  ID: {1}
Device Hostname: {2}

thanks"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:id",
        "artifact:*.cef.deviceHostname",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_mail_body", separator=", ")

    join_filter_1(container=container)

    return

@phantom.playbook_block()
def format_custom_fields(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_custom_fields() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.username', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]

    format_custom_fields__email_address = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    str = container_item_0[0]
    strnew = str.partition("@")
    email_address = strnew[0] + "@ktbcs.co.th"
    format_custom_fields__email_address = email_address
    
    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='format_custom_fields:email_address', value=json.dumps(format_custom_fields__email_address))
    format_mail_body(container=container)
    format_mail_subject(container=container)

    return

@phantom.playbook_block()
def format_mail_subject(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_mail_subject() called')
    
    template = """Containment Notification"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_mail_subject", separator=", ")

    join_filter_1(container=container)

    return

@phantom.playbook_block()
def send_email_to_inform_logged_user(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_email_to_inform_logged_user() called')

    # collect data for 'send_email_to_inform_logged_user' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.user_mail', 'artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='format_mail_body')
    formatted_data_2 = phantom.get_format_data(name='format_mail_subject')

    parameters = []
    
    # build parameters list for 'send_email_to_inform_logged_user' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'cc': "",
                'to': container_item[0],
                'bcc': "",
                'body': formatted_data_1,
                'from': "no-reply-phantom@ktbcs.co.th",
                'headers': "",
                'subject': formatted_data_2,
                'attachments': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="send email", parameters=parameters, assets=['smtp asset'], name="send_email_to_inform_logged_user")

    return

@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["format_mail_body:formatted_data", "!=", ""],
            ["format_mail_subject:formatted_data", "!=", ""],
        ],
        logical_operator='and',
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        send_email_to_inform_logged_user(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def join_filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_filter_1() called')

    # no callbacks to check, call connected block "filter_1"
    phantom.save_run_data(key='join_filter_1_called', value='filter_1', auto=True)

    filter_1(container=container, handle=handle)
    
    return

@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["contain_approved", "in", "artifact:*.tags"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        decision_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    add_note_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

@phantom.playbook_block()
def add_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_1() called')

    note_title = "Email notification - Contain approve notes"
    note_content = "Not Approved"
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.username", "!=", ""],
            ["", "!=", "unknown"],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        format_custom_fields(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

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