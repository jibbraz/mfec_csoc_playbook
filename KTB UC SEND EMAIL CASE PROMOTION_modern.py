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
    
    template = """Case Name: {0}
Case Owner: {1}
Case Status: {2}
Case Severity: {3}
Case Sensitivty: {4}
Create Time: {5}
Container URL: {7}"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "container:owner_name",
        "container:status",
        "container:severity",
        "container:sensitivity",
        "cf_local_datetime_modify_1:custom_function_result.data.datetime_string",
        "container:due_time",
        "container:url",
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
    format_mail_subject(container=container)
    cf_local_datetime_modify_1(container=container)

    return

@phantom.playbook_block()
def format_mail_subject(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_mail_subject() called')
    
    template = """Event {0} has been promoted to case"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_mail_subject", separator=", ")

    join_filter_1(container=container)

    return

@phantom.playbook_block()
def send_email_case_promotion(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_email_case_promotion() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_case_promotion' call
    formatted_data_1 = phantom.get_format_data(name='format_mail_body')
    formatted_data_2 = phantom.get_format_data(name='format_mail_subject')

    parameters = []
    
    # build parameters list for 'send_email_case_promotion' call
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

    phantom.act(action="send email", parameters=parameters, assets=['smtp asset'], name="send_email_case_promotion")

    return

@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["format_mail_body:formatted_data", "!=", ""],
            ["format_mail_subject:formatted_data", "!=", ""],
        ],
        logical_operator='and',
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        send_email_case_promotion(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def join_filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_filter_1() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(custom_function_names=['cf_local_datetime_modify_1']):
        
        # call connected block "filter_1"
        filter_1(container=container, handle=handle)
    
    return

@phantom.playbook_block()
def cf_local_datetime_modify_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_datetime_modify_1() called')
    
    container_property_0 = [
        [
            container.get("create_time"),
        ],
    ]
    literal_values_0 = [
        [
            7,
            "hours",
            "%Y-%m-%d  %H:%M:%S.%f+00",
            "%Y-%m-%dT%H:%M:%S.%f+07",
        ],
    ]

    parameters = []

    for item0 in container_property_0:
        for item1 in literal_values_0:
            parameters.append({
                'input_datetime': item0[0],
                'amount_to_modify': item1[0],
                'modification_unit': item1[1],
                'input_format_string': item1[2],
                'output_format_string': item1[3],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/datetime_modify", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/datetime_modify', parameters=parameters, name='cf_local_datetime_modify_1', callback=format_mail_body)

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