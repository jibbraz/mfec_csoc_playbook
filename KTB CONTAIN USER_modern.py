"""
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
        ])

    # call connected blocks if condition 1 matched
    if matched:
        format_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2

    return

@phantom.playbook_block()
def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationUserName_AD", "==", "CSOC AD"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        disable_account_csoc(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationUserName_AD", "==", "KTB AD"],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        disable_account_ktb(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 3
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationUserName_AD", "==", "KTBCS AD"],
        ])

    # call connected blocks if condition 3 matched
    if matched:
        disable_account_ktbcs(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_1() called')
    
    template = """(samaccountname={0})"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationUserName",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1", separator=", ")

    decision_3(container=container)

    return

@phantom.playbook_block()
def disable_account_csoc(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('disable_account_csoc() called')

    # collect data for 'disable_account_csoc' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationUserName', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'disable_account_csoc' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'user': container_item[0],
                'use_samaccountname': True,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="disable account", parameters=parameters, assets=['csoc ad ldap asset containment'], callback=join_decision_4, name="disable_account_csoc")

    return

@phantom.playbook_block()
def disable_account_ktb(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('disable_account_ktb() called')

    # collect data for 'disable_account_ktb' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationUserName', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'disable_account_ktb' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'use_samaccountname': True,
                'user': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="disable account", parameters=parameters, assets=['csoc ad ldap asset containment'], callback=join_decision_4, name="disable_account_ktb")

    return

@phantom.playbook_block()
def disable_account_ktbcs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('disable_account_ktbcs() called')

    # collect data for 'disable_account_ktbcs' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationUserName', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'disable_account_ktbcs' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'use_samaccountname': True,
                'user': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="disable account", parameters=parameters, assets=['csoc ad ldap asset containment'], callback=join_decision_4, name="disable_account_ktbcs")

    return

@phantom.playbook_block()
def set_artifact_contain_successful(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_artifact_contain_successful() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    parameters = []
    
    cef_json = {"destinationUserName_ContainResult" : "True" }
                    
    # build parameters list for 'update_result' call
    parameters.append({
    'artifact_id': container_item_0[0],
    'name': "",
    'label': "",
    'severity': "",
    'cef_json': cef_json,
    'cef_types_json': "",
    'tags': "",
    'overwrite': "",
    'artifact_json': "",
    })
    
    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_update_result")
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    return

@phantom.playbook_block()
def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["disable_account_csoc:action_result.summary.account_status", "==", "disabled"],
            ["disable_account_ktb:action_result.summary.account_status", "==", "disabled"],
            ["disable_account_ktbcs:action_result.summary.account_status", "==", "disabled"],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        set_artifact_contain_successful(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    set_artifact_contain_unsuccessful(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

@phantom.playbook_block()
def join_decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_decision_4() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_decision_4_called'):
        return

    # no callbacks to check, call connected block "decision_4"
    phantom.save_run_data(key='join_decision_4_called', value='decision_4', auto=True)

    decision_4(container=container, handle=handle)
    
    return

@phantom.playbook_block()
def set_artifact_contain_unsuccessful(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_artifact_contain_unsuccessful() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    parameters = []
    
    cef_json = {"destinationUserName_ContainResult" : "False" }
                    
    # build parameters list for 'update_result' call
    parameters.append({
    'artifact_id': container_item_0[0],
    'name': "",
    'label': "",
    'severity': "",
    'cef_json': cef_json,
    'cef_types_json': "",
    'tags': "",
    'overwrite': "",
    'artifact_json': "",
    })
    
    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_update_result")
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

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