"""
USE CASE: This playbook is used to contain the threat on External IP address in regular time set by Timer App
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

MAIN_PLAYBOOK_SRC_IP_FAILED = False

# End - Global Code block
##############################

@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'playbook_local_KTB_CHILD_SCHEDULED_CONTAIN_EXTERNAL_IP_PALOALTO_SRC_1' block
    playbook_local_KTB_CHILD_SCHEDULED_CONTAIN_EXTERNAL_IP_PALOALTO_SRC_1(container=container)

    return

@phantom.playbook_block()
def playbook_local_KTB_CHILD_SCHEDULED_CONTAIN_EXTERNAL_IP_PALOALTO_SRC_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_KTB_CHILD_SCHEDULED_CONTAIN_EXTERNAL_IP_PALOALTO_SRC_1() called')
    
    # call playbook "local/KTB CHILD SCHEDULED CONTAIN EXTERNAL IP - PALOALTO SRC", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/KTB CHILD SCHEDULED CONTAIN EXTERNAL IP - PALOALTO SRC", container=container, name="playbook_local_KTB_CHILD_SCHEDULED_CONTAIN_EXTERNAL_IP_PALOALTO_SRC_1", callback=decision_1)

    return

@phantom.playbook_block()
def playbook_local_KTB_CHILD_SCHEDULED_CONTAIN_EXTERNAL_IP_PALOALTO_DEST_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_KTB_CHILD_SCHEDULED_CONTAIN_EXTERNAL_IP_PALOALTO_DEST_1() called')
    
    # call playbook "local/KTB CHILD SCHEDULED CONTAIN EXTERNAL IP - PALOALTO DEST", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/KTB CHILD SCHEDULED CONTAIN EXTERNAL IP - PALOALTO DEST", container=container, name="playbook_local_KTB_CHILD_SCHEDULED_CONTAIN_EXTERNAL_IP_PALOALTO_DEST_1", callback=get_src_ip_containment_status)

    return

@phantom.playbook_block()
def join_playbook_local_KTB_CHILD_SCHEDULED_CONTAIN_EXTERNAL_IP_PALOALTO_DEST_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_playbook_local_KTB_CHILD_SCHEDULED_CONTAIN_EXTERNAL_IP_PALOALTO_DEST_1() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    #if phantom.completed(playbook_names=['playbook_local_KTB_CHILD_SCHEDULED_CONTAIN_EXTERNAL_IP_PALOALTO_SRC_1']):
        
    # call connected block "playbook_local_KTB_CHILD_SCHEDULED_CONTAIN_EXTERNAL_IP_PALOALTO_DEST_1"
    playbook_local_KTB_CHILD_SCHEDULED_CONTAIN_EXTERNAL_IP_PALOALTO_DEST_1(container=container, handle=handle)
    
    return

"""
Flag src IP failed
"""
@phantom.playbook_block()
def flag_src_ip_failed(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('flag_src_ip_failed() called')
    
    input_parameter_0 = ""

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    global MAIN_PLAYBOOK_SRC_IP_FAILED
    MAIN_PLAYBOOK_SRC_IP_FAILED = True

    ################################################################################
    ## Custom Code End
    ################################################################################
    join_playbook_local_KTB_CHILD_SCHEDULED_CONTAIN_EXTERNAL_IP_PALOALTO_DEST_1(container=container)

    return

@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')
    
    status_param = container.get('status', None)

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            [status_param, "==", "Open"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        flag_src_ip_failed(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    join_playbook_local_KTB_CHILD_SCHEDULED_CONTAIN_EXTERNAL_IP_PALOALTO_DEST_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_src_ip_containment_status:custom_function:is_src_ip_contain_failed", "==", False],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        return

    # call connected blocks for 'else' condition 2
    set_status_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

@phantom.playbook_block()
def set_status_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_1() called')

    phantom.set_status(container=container, status="Open")

    return

"""
Get src IP containment status
"""
@phantom.playbook_block()
def get_src_ip_containment_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_src_ip_containment_status() called')
    
    input_parameter_0 = ""

    get_src_ip_containment_status__is_src_ip_contain_failed = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    global MAIN_PLAYBOOK_SRC_IP_FAILED
    get_src_ip_containment_status__is_src_ip_contain_failed = MAIN_PLAYBOOK_SRC_IP_FAILED

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='get_src_ip_containment_status:is_src_ip_contain_failed', value=json.dumps(get_src_ip_containment_status__is_src_ip_contain_failed))
    decision_2(container=container)

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