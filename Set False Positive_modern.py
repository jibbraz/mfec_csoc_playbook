"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'cf_local_add_t0_t3_falsepositive_1' block
    cf_local_add_t0_t3_falsepositive_1(container=container)

    return

@phantom.playbook_block()
def cf_local_add_t0_t3_falsepositive_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_add_t0_t3_falsepositive_1() called')
    
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

    # call custom function "local/add_t0_t3_falsepositive", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/add_t0_t3_falsepositive', parameters=parameters, name='cf_local_add_t0_t3_falsepositive_1')

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