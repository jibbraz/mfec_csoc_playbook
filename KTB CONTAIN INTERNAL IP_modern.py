"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'update_pre_contain_status' block
    update_pre_contain_status(container=container)

    return

@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress_QueryFrom", "==", "ISE"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        disable_macaddress_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress_QueryFrom", "==", "AMP"],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        move_computer_to_group_by_hostname_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 3

    return

@phantom.playbook_block()
def update_pre_contain_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_pre_contain_status() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    parameters = []
    
    cef_json = {"sourceAddress_ContainResult" : "False" }
                    
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
    ## Custom Code End
    ################################################################################
    decision_1(container=container)

    return

@phantom.playbook_block()
def update_ise_contain_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_ise_contain_status() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.id'])
    results_data_1 = phantom.collect2(container=container, datapath=['disable_macaddress_1:action_result.status'], action_results=results)
    container_item_0 = [item[0] for item in container_data]
    results_item_1_0 = [item[0] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    parameters = []
    
    phantom.debug(results_item_1_0)
    
    if results_item_1_0[0] == "success":
        cef_json = {"sourceAddress_ContainResult" : "True" }
    else:
        cef_json = {"sourceAddress_ContainResult" : "False" }

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
    ## Custom Code End
    ################################################################################

    return

@phantom.playbook_block()
def update_amp_contain_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_amp_contain_status() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.id'])
    results_data_1 = phantom.collect2(container=container, datapath=['move_computer_to_group_by_hostname_2:action_result.status'], action_results=results)
    container_item_0 = [item[0] for item in container_data]
    results_item_1_0 = [item[0] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    parameters = []
    
    phantom.debug(results_item_1_0)
    
    if results_item_1_0[0] == "success":
        cef_json = {"sourceAddress_ContainResult" : "True" }
    else:
        cef_json = {"sourceAddress_ContainResult" : "False" }

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
    ## Custom Code End
    ################################################################################

    return

@phantom.playbook_block()
def disable_macaddress_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('disable_macaddress_1() called')

    # collect data for 'disable_macaddress_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress_MacAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'disable_macaddress_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'macaddress': container_item[0],
                'policyname': "xxx_Protected",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="disable_macaddress", parameters=parameters, assets=['new-ise-test'], callback=update_ise_contain_status, name="disable_macaddress_1")

    return

@phantom.playbook_block()
def move_computer_to_group_by_hostname_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('move_computer_to_group_by_hostname_2() called')

    # collect data for 'move_computer_to_group_by_hostname_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress_fullhostname', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'move_computer_to_group_by_hostname_2' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hostName': container_item[0],
                'groupName': "xxx_Protected",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="move_computer_to_group_by_hostname", parameters=parameters, assets=['amp-test'], callback=update_amp_contain_status, name="move_computer_to_group_by_hostname_2")

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