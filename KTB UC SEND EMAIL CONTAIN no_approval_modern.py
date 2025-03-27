"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'format_custom_fields' block
    format_custom_fields(container=container)

    return

@phantom.playbook_block()
def format_mail_body(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_mail_body() called')
    
    template = """This is an automated message to inform you that  the containment request  was not approved, you need a manual containment. 

Case Name: {0}
Case number: {1}
Device Hostname: {2}
Case Severity: {3}
Signature: {4}
Host MacAddress: {5}

Please do not respond to this message."""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:id",
        "artifact:*.cef.deviceHostname",
        "container:severity",
        "artifact:*.cef.signature",
        "artifact:*.cef.host_mac",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_mail_body", separator=", ")

    join_filter_1(container=container)

    return

@phantom.playbook_block()
def format_custom_fields(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_custom_fields() called')
    
    create_time_value = container.get('create_time', None)

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################
    format_mail_body(container=container)
    format_mail_subject(container=container)

    return

@phantom.playbook_block()
def format_mail_subject(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_mail_subject() called')
    
    template = """SOAR - Containment Request Not Approval- Notification"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_mail_subject", separator=", ")

    join_filter_1(container=container)

    return

@phantom.playbook_block()
def send_email_contain_approval(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_email_contain_approval() called')

    # collect data for 'send_email_contain_approval' call
    formatted_data_1 = phantom.get_format_data(name='format_mail_body')
    formatted_data_2 = phantom.get_format_data(name='format_mail_subject')

    parameters = []
    
    # build parameters list for 'send_email_contain_approval' call
    parameters.append({
        'cc': "",
        'to': "security-infra@ktbcs.co.th",
        'bcc': "",
        'body': formatted_data_1,
        'from': "no-reply-phantom@ktbcs.co.th",
        'headers': "",
        'subject': formatted_data_2,
        'attachments': "",
    })

    phantom.act(action="send email", parameters=parameters, assets=['smtp asset'], name="send_email_contain_approval")

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
        send_email_contain_approval(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def join_filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_filter_1() called')

    # no callbacks to check, call connected block "filter_1"
    phantom.save_run_data(key='join_filter_1_called', value='filter_1', auto=True)

    filter_1(container=container, handle=handle)
    
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