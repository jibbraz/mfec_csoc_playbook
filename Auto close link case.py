"""
auto close
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Auto_Close_Confirmation' block
    Auto_Close_Confirmation(container=container)

    return

def Auto_Close_Confirmation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Auto_Close_Confirmation() called')
    
    # set user and message variables for phantom.prompt call
    user = "ktanalyst"
    message = """Please Enter Child ID"""

    #responses:
    response_types = [
        {
            "prompt": "Enter Case ID",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "Enter List of Child ID",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="Auto_Close_Confirmation", separator=", ", response_types=response_types, callback=decision_1)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Auto_Close_Confirmation:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_community_string_split_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2

    return

def cf_community_string_split_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_string_split_1() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['Auto_Close_Confirmation:action_result.summary.responses.1', 'Auto_Close_Confirmation:action_result.parameter.context.artifact_id'], action_results=results )
    literal_values_0 = [
        [
            ",",
            "True",
        ],
    ]

    parameters = []

    for item0 in literal_values_0:
        for item1 in action_results_data_0:
            parameters.append({
                'delimiter': item0[0],
                'input_string': item1[0],
                'strip_whitespace': item0[1],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/string_split", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/string_split', parameters=parameters, name='cf_community_string_split_1', callback=custom_function_1)

    return

def custom_function_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('custom_function_1() called')
    
    status_value = container.get('status', None)
    id_value = container.get('id', None)
    results_data_1 = phantom.collect2(container=container, datapath=['Auto_Close_Confirmation:action_result.status', 'Auto_Close_Confirmation:action_result.parameter.message', 'Auto_Close_Confirmation:action_result.summary.responses.0'], action_results=results)
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_community_string_split_1:custom_function_result.data.*.item'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_1_1 = [item[1] for item in results_data_1]
    results_item_1_2 = [item[2] for item in results_data_1]
    custom_function_results_item_1_0 = [item[0] for item in custom_function_results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    for container_id in custom_function_results_item_1_0:
        try:
            target_container = phantom.get_container(container_id)
            phantom.set_status(container=target_container, status="Closed")
            phantom.update(target_container,  {'custom_fields':{'Assigned To':  "Playbook"}})
            #note_content += "event : " + str(container_id) + "success\n\n"
            note_content = "This event closed by main event " + str(custom_function_results_data_1)
        except:
            note_content += "event : " + str(container_id) + "fail. \n\n"    
        success, message, note_id = phantom.add_note(container=target_container, note_type='general', title='Closed by Automation Playbook', content=note_content)   
        
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

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