"""
USE CASE: This playbook is used to contain the threat
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

import ipaddress

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'decision_20' block
    decision_20(container=container)

    return

"""
Safety check before executing Containment 
"""
def Safety_check_before_Containment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Safety_check_before_Containment() called')
    
    # set user and message variables for phantom.prompt call
    user = "Tier2 Analyst"
    message = """***WARNING Event ID {0}*** 
The host {1} may be compromised.  {2} will be isolated.

Do you want to proceed with containment ?"""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
        "artifact:*.cef.deviceHostname",
        "custom_function_1:custom_function:who_was_contained",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=1, name="Safety_check_before_Containment", separator=", ", parameters=parameters, response_types=response_types, callback=decision_19)

    return

"""
Check containment decision
"""
def Check_containment_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_containment_decision() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Safety_check_before_Containment:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_community_artifact_update_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    cf_local_Set_last_automated_action_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def decision_19(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_19() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Safety_check_before_Containment:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Check_containment_decision(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Safety_check_before_Containment:action_result.status", "==", "failed"],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        cf_local_Set_last_automated_action_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def playbook_local_KTB_UC_SEND_EMAIL_CONTAIN_APPROVAL_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_KTB_UC_SEND_EMAIL_CONTAIN_APPROVAL_1() called')
    
    # call playbook "local/KTB UC SEND EMAIL CONTAIN APPROVAL", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/KTB UC SEND EMAIL CONTAIN APPROVAL", container=container, name="playbook_local_KTB_UC_SEND_EMAIL_CONTAIN_APPROVAL_1", callback=cf_local_Containment_Precheck_1)

    return

def cf_local_Containment_Precheck_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_Containment_Precheck_1() called')
    
    parameters = [{}]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/Containment_Precheck", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/Containment_Precheck', parameters=parameters, name='cf_local_Containment_Precheck_1', callback=custom_function_1)

    return

def cf_community_artifact_update_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_artifact_update_1() called')
    
    container_data_0 = phantom.collect2(container=container, datapath=['artifact:*.id'])
    literal_values_0 = [
        [
            "indicator_malicious,contain_approved",
        ],
    ]

    parameters = []

    for item0 in literal_values_0:
        for item1 in container_data_0:
            parameters.append({
                'name': None,
                'tags': item0[0],
                'label': None,
                'severity': None,
                'cef_field': None,
                'cef_value': None,
                'input_json': None,
                'artifact_id': item1[0],
                'cef_data_type': None,
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/artifact_update", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/artifact_update', parameters=parameters, name='cf_community_artifact_update_1')

    return

def decision_20(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_20() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["contain_approved", "in", "artifact:*.tags"],
            ["device_quarantined", "in", "artifact:*.tags"],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        add_note_6(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    playbook_local_KTB_UC_SEND_EMAIL_CONTAIN_APPROVAL_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def add_note_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_6() called')

    note_title = "Contain Approve Notes"
    note_content = "Approved Or Contained it before."
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

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
    phantom.custom_function(custom_function='local/Set_last_automated_action', parameters=parameters, name='cf_local_Set_last_automated_action_1', callback=playbook_local_KTB_UC_SEND_EMAIL_CONTAIN_no_approval_1)

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
            "Containment Approval Timeout",
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
    phantom.custom_function(custom_function='local/Set_last_automated_action', parameters=parameters, name='cf_local_Set_last_automated_action_2', callback=playbook_local_KTB_UC_SEND_EMAIL_CONTAIN_timeout_1)

    return

def custom_function_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('custom_function_1() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.host_mac', 'artifact:*.cef.deviceHostname', 'artifact:*.cef.destinationAddress', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]
    container_item_1 = [item[1] for item in container_data]
    container_item_2 = [item[2] for item in container_data]

    custom_function_1__who_was_contained = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    tempstr = "" 
    phantom.debug(container_item_0[0])
    phantom.debug('=-------------==')
    phantom.debug(container_item_1[0])
    
    if container_item_0[0] != None :
       tempstr = "Host Mac Address " + container_item_0[0]
    elif container_item_1[0] != None :
       tempstr = "AMP host " + container_item_1[0]
    else :
       tempstr = str(container_item_2[0])
        
    custom_function_1__who_was_contained = tempstr
    
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='custom_function_1:who_was_contained', value=json.dumps(custom_function_1__who_was_contained))
    Safety_check_before_Containment(container=container)

    return

def playbook_local_KTB_UC_SEND_EMAIL_CONTAIN_no_approval_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_KTB_UC_SEND_EMAIL_CONTAIN_no_approval_1() called')
    
    # call playbook "local/KTB UC SEND EMAIL CONTAIN no_approval", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/KTB UC SEND EMAIL CONTAIN no_approval", container=container, name="playbook_local_KTB_UC_SEND_EMAIL_CONTAIN_no_approval_1")

    return

def playbook_local_KTB_UC_SEND_EMAIL_CONTAIN_timeout_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_KTB_UC_SEND_EMAIL_CONTAIN_timeout_1() called')
    
    # call playbook "local/KTB UC SEND EMAIL CONTAIN timeout", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/KTB UC SEND EMAIL CONTAIN timeout", container=container, name="playbook_local_KTB_UC_SEND_EMAIL_CONTAIN_timeout_1")

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