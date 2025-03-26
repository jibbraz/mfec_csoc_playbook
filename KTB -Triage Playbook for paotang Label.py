"""
USE CASE: This playbook will perform triage tasks for label events, identify false positive and set timestamp for T0, T1.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'cf_local_ADD_T0_T1_1' block
    cf_local_ADD_T0_T1_1(container=container)

    return

"""
Adding Timestamp of T0, T1
"""
def cf_local_ADD_T0_T1_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_ADD_T0_T1_1() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]

    parameters = []

    for item0 in container_property_0:
        parameters.append({
            'container_id_now': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/ADD_T0_T1", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/ADD_T0_T1', parameters=parameters, name='cf_local_ADD_T0_T1_1', callback=cf_local_Set_Incident_Type_1)

    return

def cf_local_Set_last_automated_action_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_Set_last_automated_action_3() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "Closed",
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
    phantom.custom_function(custom_function='local/Set_last_automated_action', parameters=parameters, name='cf_local_Set_last_automated_action_3')

    return

def set_status_to_closed(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_to_closed() called')

    phantom.set_status(container=container, status="Closed")

    note_title = "Notes from Triage playbook - set status to closed"
    note_content = "Notes from Triage playbook - set status to closed"
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    cf_local_Set_last_automated_action_3(container=container)

    return

def cf_local_Set_Detection_Technology_Incident_Type_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_Set_Detection_Technology_Incident_Type_1() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]

    parameters = []

    for item0 in container_property_0:
        parameters.append({
            'container_id': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    update_data = {"custom_fields":{"Detection Technology":"Splunk ES"}}
    success, message = phantom.update(container, update_data)

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/Set_Detection_Technology_Incident_Type", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/Set_Detection_Technology_Incident_Type', parameters=parameters, name='cf_local_Set_Detection_Technology_Incident_Type_1', callback=cf_local_Set_Fault_Positive_No_1)

    return

def cf_local_Set_Incident_Type_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_Set_Incident_Type_1() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]

    parameters = []

    for item0 in container_property_0:
        parameters.append({
            'container_id': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    update_data = {"custom_fields":{"Incident Type":"Unauthorized Access "}}
    success, message = phantom.update(container, update_data)

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/Set_Incident_Type", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/Set_Incident_Type', parameters=parameters, name='cf_local_Set_Incident_Type_1', callback=cf_local_Set_Detection_Technology_Incident_Type_1)

    return

def cf_local_Set_Assigned_To_Playbook_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_Set_Assigned_To_Playbook_1() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]

    parameters = []

    for item0 in container_property_0:
        parameters.append({
            'container_id': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/Set_Assigned_To_Playbook", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/Set_Assigned_To_Playbook', parameters=parameters, name='cf_local_Set_Assigned_To_Playbook_1', callback=set_status_to_closed)

    return

def cf_local_Set_Fault_Positive_No_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_Set_Fault_Positive_No_1() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]

    parameters = []

    for item0 in container_property_0:
        parameters.append({
            'container_id': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/Set_Fault_Positive_No", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/Set_Fault_Positive_No', parameters=parameters, name='cf_local_Set_Fault_Positive_No_1', callback=cf_local_Set_Assigned_To_Playbook_1)

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