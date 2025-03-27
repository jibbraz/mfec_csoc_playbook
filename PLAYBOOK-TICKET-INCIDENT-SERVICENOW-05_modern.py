"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'cf_local_set_phantom_custom_field_4' block
    cf_local_set_phantom_custom_field_4(container=container)

    return

@phantom.playbook_block()
def cf_local_get_settings_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_get_settings_1() called')
    
    parameters = [{}]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/get_settings", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/get_settings', parameters=parameters, name='cf_local_get_settings_1', callback=decision_1)

    return

@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_get_settings_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_get_mapping_fields_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def cf_local_get_mapping_fields_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_get_mapping_fields_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data.key_mapping_list_name'], action_results=results )

    parameters = []

    for item0 in custom_function_result_0:
        parameters.append({
            'key_mapping_list_name': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/get_mapping_fields", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/get_mapping_fields', parameters=parameters, name='cf_local_get_mapping_fields_1', callback=decision_2)

    return

@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_get_mapping_fields_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        get_phantom_based_field(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def get_phantom_based_field(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_phantom_based_field() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data.phantom_based_list_name'], action_results=results )

    parameters = []

    for item0 in custom_function_result_0:
        parameters.append({
            'custom_list_name': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/get_list_item", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/get_list_item', parameters=parameters, name='get_phantom_based_field', callback=decision_3)

    return

@phantom.playbook_block()
def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_phantom_based_field:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        get_servicenow_based_field(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def get_servicenow_based_field(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_servicenow_based_field() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data.servicenow_based_list_name'], action_results=results )

    parameters = []

    for item0 in custom_function_result_0:
        parameters.append({
            'custom_list_name': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/get_list_item", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/get_list_item', parameters=parameters, name='get_servicenow_based_field', callback=decision_4)

    return

@phantom.playbook_block()
def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_servicenow_based_field:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        get_origin_based_field(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def get_origin_based_field(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_origin_based_field() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data.origin_based_list_name'], action_results=results )

    parameters = []

    for item0 in custom_function_result_0:
        parameters.append({
            'custom_list_name': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/get_list_item", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/get_list_item', parameters=parameters, name='get_origin_based_field', callback=decision_5)

    return

@phantom.playbook_block()
def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_5() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_origin_based_field:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_get_timestamp_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def cf_local_get_timestamp_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_get_timestamp_1() called')
    
    parameters = [{}]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/get_timestamp", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/get_timestamp', parameters=parameters, name='cf_local_get_timestamp_1', callback=decision_6)

    return

@phantom.playbook_block()
def decision_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_6() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_get_timestamp_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        get_active_phantom_case(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def get_active_phantom_case(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_active_phantom_case() called')
    
    literal_values_0 = [
        [
            780,
        ],
    ]

    parameters = []

    for item0 in literal_values_0:
        parameters.append({
            'minute_ago': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/get_updated_phantom_case", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/get_updated_phantom_case', parameters=parameters, name='get_active_phantom_case', callback=decision_9)

    return

@phantom.playbook_block()
def decision_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_9() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_active_phantom_case:custom_function_result.data.success", "==", True],
            ["get_active_phantom_case:custom_function_result.data.data", "!=", []],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        get_ticket_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_active_phantom_case:custom_function_result.data.success", "==", True],
            ["get_active_phantom_case:custom_function_result.data.data", "==", []],
        ],
        logical_operator='and')

    # call connected blocks if condition 2 matched
    if matched:
        cf_local_add_phantom_note_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def get_ticket_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_ticket_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_ticket_2' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['get_active_phantom_case:custom_function_result.data.data.*.custom_fields.servicenow_case_id'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data.servicenow_case_table'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_ticket_2' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        for custom_function_results_item_2 in custom_function_results_data_2:
            if custom_function_results_item_1[0]:
                parameters.append({
                    'id': custom_function_results_item_1[0],
                    'table': custom_function_results_item_2[0],
                    'is_sys_id': True,
                })

    phantom.act(action="get ticket", parameters=parameters, assets=['kcs-csoc-servicenow'], callback=filter_6, name="get_ticket_2")

    return

@phantom.playbook_block()
def debug_servicenow_get_ticket(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('debug_servicenow_get_ticket() called')
    
    filtered_action_results_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_6:condition_1:get_ticket_2:action_result.data.0'])

    parameters = []

    for item0 in filtered_action_results_data_0:
        parameters.append({
            'something': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/log_debug", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/log_debug', parameters=parameters, name='debug_servicenow_get_ticket', callback=cf_local_process_phantom_and_servicenow_case_1)

    return

@phantom.playbook_block()
def cf_local_process_phantom_and_servicenow_case_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_process_phantom_and_servicenow_case_1() called')
    
    filtered_action_results_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_6:condition_1:get_ticket_2:action_result.data.0.u_phantom_case_id', 'filtered-data:filter_6:condition_1:get_ticket_2:action_result.data.0'])
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_mapping_fields_1:custom_function_result.data.data'], action_results=results )

    parameters = []

    for item0 in filtered_action_results_data_0:
        for item1 in custom_function_result_0:
            parameters.append({
                'container_input': item0[0],
                'servicenow_case': item0[1],
                'container_key_mapping': item1[0],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/process_phantom_and_servicenow_case", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/process_phantom_and_servicenow_case', parameters=parameters, name='cf_local_process_phantom_and_servicenow_case_1', callback=decision_11)

    return

@phantom.playbook_block()
def decision_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_11() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_process_phantom_and_servicenow_case_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        compare_case(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def compare_case(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('compare_case() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_process_phantom_and_servicenow_case_1:custom_function_result.data.data'], action_results=results )
    custom_function_result_1 = phantom.collect2(container=container, datapath=['get_origin_based_field:custom_function_result.data.data'], action_results=results )
    custom_function_result_2 = phantom.collect2(container=container, datapath=['get_phantom_based_field:custom_function_result.data.data'], action_results=results )
    custom_function_result_3 = phantom.collect2(container=container, datapath=['get_servicenow_based_field:custom_function_result.data.data'], action_results=results )

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in custom_function_result_1:
            for item2 in custom_function_result_2:
                for item3 in custom_function_result_3:
                    parameters.append({
                        'processed_case': item0[0],
                        'origin_based_field': item1[0],
                        'phantom_based_field': item2[0],
                        'servicenow_based_field': item3[0],
                    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/compare_phantom_and_servicenow_case", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/compare_phantom_and_servicenow_case', parameters=parameters, name='compare_case', callback=filter_5)

    return

@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_5:condition_1:compare_case:custom_function_result.data.data.phantom_based_diff", "==", True],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        generate_snow_info(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_5:condition_1:compare_case:custom_function_result.data.data.phantom_based_diff", "==", False],
        ],
        name="filter_1:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        join_cf_local_get_phantom_case_worknote_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

@phantom.playbook_block()
def generate_snow_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('generate_snow_info() called')
    
    filtered_custom_function_results_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:compare_case:custom_function_result.data.data.phantom_case_id', 'filtered-data:filter_1:condition_1:compare_case:custom_function_result.data.data.phantom_override_field', 'filtered-data:filter_1:condition_1:compare_case:custom_function_result.data.data.assignment_group_update', 'filtered-data:filter_1:condition_1:compare_case:custom_function_result.data.data.cancel_case', 'filtered-data:filter_1:condition_1:compare_case:custom_function_result.data.data.incident_type_update'])
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_mapping_fields_1:custom_function_result.data.data'], action_results=results )
    custom_function_result_1 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data'], action_results=results )
    literal_values_0 = [
        [
            "no",
        ],
    ]

    parameters = []

    for item0 in filtered_custom_function_results_data_0:
        for item1 in custom_function_result_0:
            for item2 in literal_values_0:
                for item3 in custom_function_result_1:
                    parameters.append({
                        'container_input': item0[0],
                        'container_key_mapping': item1[0],
                        'is_new_case': item2[0],
                        'phantom_based_field': item0[1],
                        'origin_based_field': None,
                        'assignment_group_update': item0[2],
                        'cancel_case': item0[3],
                        'servicenow_settings': item3[0],
                        'incident_type_update': item0[4],
                        'new_case_assignment_group_allowed_list': None,
                    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/generate_servicenow_case_info", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/generate_servicenow_case_info', parameters=parameters, name='generate_snow_info', callback=decision_13)

    return

@phantom.playbook_block()
def decision_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_13() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["generate_snow_info:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        update_ticket_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def update_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_ticket_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'update_ticket_1' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['generate_snow_info:custom_function_result.data.data.servicenow_case_id', 'generate_snow_info:custom_function_result.data.data.field'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data.servicenow_case_table'], action_results=results)

    parameters = []
    
    # build parameters list for 'update_ticket_1' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        for custom_function_results_item_2 in custom_function_results_data_2:
            if custom_function_results_item_1[0]:
                parameters.append({
                    'id': custom_function_results_item_1[0],
                    'table': custom_function_results_item_2[0],
                    'fields': custom_function_results_item_1[1],
                    'vault_id': "",
                    'is_sys_id': True,
                })

    phantom.act(action="update ticket", parameters=parameters, assets=['kcs-csoc-servicenow'], callback=decision_14, name="update_ticket_1")

    return

@phantom.playbook_block()
def decision_14(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_14() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["update_ticket_1:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        debug_servicenow_update_case(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def cf_local_generate_servicenow_frontend_query_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_generate_servicenow_frontend_query_1() called')
    
    filtered_custom_function_results_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_5:condition_1:compare_case:custom_function_result.data.data.servicenow_case_id'])

    parameters = []

    for item0 in filtered_custom_function_results_data_0:
        parameters.append({
            'servicenow_case_id': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/generate_servicenow_frontend_query", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/generate_servicenow_frontend_query', parameters=parameters, name='cf_local_generate_servicenow_frontend_query_1', callback=decision_15)

    return

@phantom.playbook_block()
def join_cf_local_generate_servicenow_frontend_query_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_cf_local_generate_servicenow_frontend_query_1() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_cf_local_generate_servicenow_frontend_query_1_called'):
        return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(custom_function_names=['update_servicenow_timestamp_from_phantom']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_cf_local_generate_servicenow_frontend_query_1_called', value='cf_local_generate_servicenow_frontend_query_1')
        
        # call connected block "cf_local_generate_servicenow_frontend_query_1"
        cf_local_generate_servicenow_frontend_query_1(container=container, handle=handle)
    
    return

@phantom.playbook_block()
def decision_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_15() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_generate_servicenow_frontend_query_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        get_servicenow_worknote(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def get_servicenow_worknote(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_servicenow_worknote() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_servicenow_worknote' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_generate_servicenow_frontend_query_1:custom_function_result.data.data'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data.servicenow_case_table'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_servicenow_worknote' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        for custom_function_results_item_2 in custom_function_results_data_2:
            if custom_function_results_item_1[0]:
                parameters.append({
                    'id': custom_function_results_item_1[0],
                    'table': custom_function_results_item_2[0],
                    'is_sys_id': True,
                })

    phantom.act(action="get ticket", parameters=parameters, assets=['kcs-csoc-servicenow'], callback=decision_16, name="get_servicenow_worknote")

    return

@phantom.playbook_block()
def decision_16(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_16() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_servicenow_worknote:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        debug_servicenow_case_note(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def cf_local_get_phantom_case_worknote_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_get_phantom_case_worknote_1() called')
    
    filtered_custom_function_results_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_5:condition_1:compare_case:custom_function_result.data.data.phantom_case_id'])

    parameters = []

    for item0 in filtered_custom_function_results_data_0:
        parameters.append({
            'container_input': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/get_phantom_case_worknote", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/get_phantom_case_worknote', parameters=parameters, name='cf_local_get_phantom_case_worknote_1', callback=decision_17)

    return

@phantom.playbook_block()
def join_cf_local_get_phantom_case_worknote_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_cf_local_get_phantom_case_worknote_1() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_cf_local_get_phantom_case_worknote_1_called'):
        return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(custom_function_names=['compare_case']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_cf_local_get_phantom_case_worknote_1_called', value='cf_local_get_phantom_case_worknote_1')
        
        # call connected block "cf_local_get_phantom_case_worknote_1"
        cf_local_get_phantom_case_worknote_1(container=container, handle=handle)
    
    return

@phantom.playbook_block()
def decision_17(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_17() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_get_phantom_case_worknote_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_process_phantom_note_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def cf_local_process_phantom_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_process_phantom_note_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data.note_message_from_phantom'], action_results=results )
    custom_function_result_1 = phantom.collect2(container=container, datapath=['cf_local_get_phantom_case_worknote_1:custom_function_result.data.data'], action_results=results )

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in custom_function_result_1:
            parameters.append({
                'add_text': item0[0],
                'raw_phantom_note': item1[0],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/process_phantom_note", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/process_phantom_note', parameters=parameters, name='cf_local_process_phantom_note_1', callback=decision_18)

    return

@phantom.playbook_block()
def decision_18(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_18() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_process_phantom_note_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_filter_new_worknote_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def cf_local_filter_new_worknote_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_filter_new_worknote_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data'], action_results=results )
    custom_function_result_1 = phantom.collect2(container=container, datapath=['cf_local_process_phantom_note_1:custom_function_result.data.data'], action_results=results )
    literal_values_0 = [
        [
            "phantom",
        ],
    ]

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in custom_function_result_1:
            for item2 in literal_values_0:
                parameters.append({
                    'settings': item0[0],
                    'note_list': item1[0],
                    'filter_from': item2[0],
                })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/filter_new_worknote", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/filter_new_worknote', parameters=parameters, name='cf_local_filter_new_worknote_1', callback=filter_2)

    return

@phantom.playbook_block()
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_filter_new_worknote_1:custom_function_result.data.success", "==", True],
            ["cf_local_filter_new_worknote_1:custom_function_result.data.data", "!=", []],
        ],
        logical_operator='and',
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_note_to_servicenow(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_filter_new_worknote_1:custom_function_result.data.success", "==", True],
            ["cf_local_filter_new_worknote_1:custom_function_result.data.data", "==", []],
        ],
        logical_operator='and',
        name="filter_2:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        join_update_phantom_timestamp_to_servicenow(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

@phantom.playbook_block()
def add_note_to_servicenow(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_to_servicenow() called')
    
    filtered_custom_function_results_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_1:cf_local_filter_new_worknote_1:custom_function_result.data.data.*.note_info.content', 'filtered-data:filter_2:condition_1:cf_local_filter_new_worknote_1:custom_function_result.data.data.*.note_info.servicenow_case_id'])
    literal_values_0 = [
        [
            "work_notes",
        ],
    ]

    parameters = []

    for item0 in filtered_custom_function_results_data_0:
        for item1 in literal_values_0:
            parameters.append({
                'value': item0[0],
                'field_name': item1[0],
                'servicenow_case_id': item0[1],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/set_servicenow_field", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_servicenow_field', parameters=parameters, name='add_note_to_servicenow', callback=decision_20)

    return

@phantom.playbook_block()
def decision_20(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_20() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["add_note_to_servicenow:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        join_update_phantom_timestamp_to_servicenow(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def update_phantom_timestamp_to_servicenow(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_phantom_timestamp_to_servicenow() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_timestamp_1:custom_function_result.data.data'], action_results=results )
    filtered_custom_function_results_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_5:condition_1:compare_case:custom_function_result.data.data.phantom_case_id'])
    literal_values_0 = [
        [
            "last_update_to_servicenow",
        ],
    ]

    parameters = []

    for item0 in literal_values_0:
        for item1 in custom_function_result_0:
            for item2 in filtered_custom_function_results_data_0:
                parameters.append({
                    'field': item0[0],
                    'value': item1[0],
                    'container_input': item2[0],
                })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/set_phantom_custom_field", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_phantom_custom_field', parameters=parameters, name='update_phantom_timestamp_to_servicenow', callback=decision_21)

    return

@phantom.playbook_block()
def join_update_phantom_timestamp_to_servicenow(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_update_phantom_timestamp_to_servicenow() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_update_phantom_timestamp_to_servicenow_called'):
        return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(custom_function_names=['cf_local_filter_new_worknote_1']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_update_phantom_timestamp_to_servicenow_called', value='update_phantom_timestamp_to_servicenow')
        
        # call connected block "update_phantom_timestamp_to_servicenow"
        update_phantom_timestamp_to_servicenow(container=container, handle=handle)
    
    return

@phantom.playbook_block()
def decision_21(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_21() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["update_phantom_timestamp_to_servicenow:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_generate_servicenow_datetime_update_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def update_servicenow_timestamp_from_phantom(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_servicenow_timestamp_from_phantom() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_generate_servicenow_datetime_update_1:custom_function_result.data.data.formatted_datetime_str', 'cf_local_generate_servicenow_datetime_update_1:custom_function_result.data.data.servicenow_case_id'], action_results=results )
    literal_values_0 = [
        [
            "u_last_update_from_phantom",
        ],
    ]

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in literal_values_0:
            parameters.append({
                'value': item0[0],
                'field_name': item1[0],
                'servicenow_case_id': item0[1],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/set_servicenow_field", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_servicenow_field', parameters=parameters, name='update_servicenow_timestamp_from_phantom', callback=filter_3)

    return

@phantom.playbook_block()
def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_5:condition_1:compare_case:custom_function_result.data.data.servicenow_based_diff", "==", False],
        ],
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        join_cf_local_generate_servicenow_frontend_query_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_5:condition_1:compare_case:custom_function_result.data.data.servicenow_based_diff", "==", True],
        ],
        name="filter_3:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        cf_local_generate_phantom_case_info_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

@phantom.playbook_block()
def debug_servicenow_update_case(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('debug_servicenow_update_case() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['update_ticket_1:action_result.data.0', 'update_ticket_1:action_result.parameter.context.artifact_id'], action_results=results )

    parameters = []

    for item0 in action_results_data_0:
        parameters.append({
            'something': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/log_debug", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/log_debug', parameters=parameters, name='debug_servicenow_update_case', callback=cf_local_generate_servicenow_assigned_to_params_1)

    return

@phantom.playbook_block()
def cf_local_generate_phantom_case_info_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_generate_phantom_case_info_1() called')
    
    filtered_custom_function_results_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_3:condition_2:compare_case:custom_function_result.data.data.cancel_case', 'filtered-data:filter_3:condition_2:compare_case:custom_function_result.data.data.raw_servicenow', 'filtered-data:filter_3:condition_2:compare_case:custom_function_result.data.data.servicenow_override_field'])
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_mapping_fields_1:custom_function_result.data.data'], action_results=results )
    literal_values_0 = [
        [
            "no",
        ],
    ]

    parameters = []

    for item0 in filtered_custom_function_results_data_0:
        for item1 in literal_values_0:
            for item2 in custom_function_result_0:
                parameters.append({
                    'cancel_case': item0[0],
                    'is_new_case': item1[0],
                    'servicenow_case': item0[1],
                    'assignment_group': None,
                    'origin_based_field': None,
                    'container_key_mapping': item2[0],
                    'servicenow_based_field': item0[2],
                })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/generate_phantom_case_info", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/generate_phantom_case_info', parameters=parameters, name='cf_local_generate_phantom_case_info_1', callback=decision_22)

    return

@phantom.playbook_block()
def decision_22(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_22() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_generate_phantom_case_info_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_update_phantom_case_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def cf_local_update_phantom_case_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_update_phantom_case_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_generate_phantom_case_info_1:custom_function_result.data.data.formatted', 'cf_local_generate_phantom_case_info_1:custom_function_result.data.data.formatted.id'], action_results=results )

    parameters = []

    for item0 in custom_function_result_0:
        parameters.append({
            'updating_info': item0[0],
            'container_input': item0[1],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/update_phantom_case", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/update_phantom_case', parameters=parameters, name='cf_local_update_phantom_case_1', callback=decision_23)

    return

@phantom.playbook_block()
def decision_23(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_23() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_update_phantom_case_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_add_phantom_artifact_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def cf_local_add_phantom_artifact_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_add_phantom_artifact_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data.phantom_artifact_name'], action_results=results )
    custom_function_result_1 = phantom.collect2(container=container, datapath=['cf_local_generate_phantom_case_info_1:custom_function_result.data.data.raw', 'cf_local_generate_phantom_case_info_1:custom_function_result.data.data.formatted.id'], action_results=results )

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in custom_function_result_1:
            parameters.append({
                'name': item0[0],
                'label': None,
                'artifact': item1[0],
                'severity': None,
                'container_input': item1[1],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/add_phantom_artifact", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/add_phantom_artifact', parameters=parameters, name='cf_local_add_phantom_artifact_1', callback=decision_24)

    return

@phantom.playbook_block()
def cf_local_limit_phantom_artifact_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_limit_phantom_artifact_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data.phantom_artifact_name', 'cf_local_get_settings_1:custom_function_result.data.data.maximum_artifact'], action_results=results )
    custom_function_result_1 = phantom.collect2(container=container, datapath=['cf_local_add_phantom_artifact_1:custom_function_result.data.data.container_id'], action_results=results )

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in custom_function_result_1:
            parameters.append({
                'artifact_name': item0[0],
                'container_input': item1[0],
                'maximum_artifact': item0[1],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/limit_phantom_artifact", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/limit_phantom_artifact', parameters=parameters, name='cf_local_limit_phantom_artifact_1', callback=decision_25)

    return

@phantom.playbook_block()
def decision_24(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_24() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_add_phantom_artifact_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_limit_phantom_artifact_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def decision_25(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_25() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_limit_phantom_artifact_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        join_cf_local_generate_servicenow_frontend_query_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def debug_servicenow_case_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('debug_servicenow_case_note() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['get_servicenow_worknote:action_result.data.0', 'get_servicenow_worknote:action_result.parameter.context.artifact_id'], action_results=results )

    parameters = []

    for item0 in action_results_data_0:
        parameters.append({
            'something': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/log_debug", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/log_debug', parameters=parameters, name='debug_servicenow_case_note', callback=cf_local_process_servicenow_note_1)

    return

@phantom.playbook_block()
def cf_local_process_servicenow_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_process_servicenow_note_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data.note_title_from_servicenow'], action_results=results )
    action_results_data_0 = phantom.collect2(container=container, datapath=['get_servicenow_worknote:action_result.data.0', 'get_servicenow_worknote:action_result.parameter.context.artifact_id'], action_results=results )

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in action_results_data_0:
            parameters.append({
                'note_title': item0[0],
                'raw_servicenow_response': item1[0],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/process_servicenow_note", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/process_servicenow_note', parameters=parameters, name='cf_local_process_servicenow_note_1', callback=decision_26)

    return

@phantom.playbook_block()
def decision_26(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_26() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_process_servicenow_note_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_filter_new_worknote_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def cf_local_filter_new_worknote_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_filter_new_worknote_2() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data'], action_results=results )
    custom_function_result_1 = phantom.collect2(container=container, datapath=['cf_local_process_servicenow_note_1:custom_function_result.data.data'], action_results=results )
    literal_values_0 = [
        [
            "servicenow",
        ],
    ]

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in custom_function_result_1:
            for item2 in literal_values_0:
                parameters.append({
                    'settings': item0[0],
                    'note_list': item1[0],
                    'filter_from': item2[0],
                })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/filter_new_worknote", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/filter_new_worknote', parameters=parameters, name='cf_local_filter_new_worknote_2', callback=filter_4)

    return

@phantom.playbook_block()
def cf_local_add_phantom_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_add_phantom_note_1() called')
    
    filtered_custom_function_results_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_4:condition_1:cf_local_filter_new_worknote_2:custom_function_result.data.data.*.note_info.title', 'filtered-data:filter_4:condition_1:cf_local_filter_new_worknote_2:custom_function_result.data.data.*.note_info.content', 'filtered-data:filter_4:condition_1:cf_local_filter_new_worknote_2:custom_function_result.data.data.*.note_info.phantom_case_id'])

    parameters = []

    for item0 in filtered_custom_function_results_data_0:
        parameters.append({
            'title': item0[0],
            'content': item0[1],
            'container_input': item0[2],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/add_phantom_note", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/add_phantom_note', parameters=parameters, name='cf_local_add_phantom_note_1', callback=decision_28)

    return

@phantom.playbook_block()
def filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_4() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_filter_new_worknote_2:custom_function_result.data.success", "==", True],
            ["cf_local_filter_new_worknote_2:custom_function_result.data.data", "!=", []],
        ],
        logical_operator='and',
        name="filter_4:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        cf_local_add_phantom_note_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_filter_new_worknote_2:custom_function_result.data.success", "==", True],
            ["cf_local_filter_new_worknote_2:custom_function_result.data.data", "==", []],
        ],
        logical_operator='and',
        name="filter_4:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        join_update_phantom_timestamp_from_servicenow(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

@phantom.playbook_block()
def decision_28(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_28() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_add_phantom_note_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        join_update_phantom_timestamp_from_servicenow(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def update_phantom_timestamp_from_servicenow(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_phantom_timestamp_from_servicenow() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_timestamp_1:custom_function_result.data.data'], action_results=results )
    filtered_custom_function_results_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_5:condition_1:compare_case:custom_function_result.data.data.phantom_case_id'])
    literal_values_0 = [
        [
            "last_update_from_servicenow",
        ],
    ]

    parameters = []

    for item0 in literal_values_0:
        for item1 in custom_function_result_0:
            for item2 in filtered_custom_function_results_data_0:
                parameters.append({
                    'field': item0[0],
                    'value': item1[0],
                    'container_input': item2[0],
                })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/set_phantom_custom_field", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_phantom_custom_field', parameters=parameters, name='update_phantom_timestamp_from_servicenow', callback=decision_29)

    return

@phantom.playbook_block()
def join_update_phantom_timestamp_from_servicenow(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_update_phantom_timestamp_from_servicenow() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_update_phantom_timestamp_from_servicenow_called'):
        return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(custom_function_names=['cf_local_filter_new_worknote_2']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_update_phantom_timestamp_from_servicenow_called', value='update_phantom_timestamp_from_servicenow')
        
        # call connected block "update_phantom_timestamp_from_servicenow"
        update_phantom_timestamp_from_servicenow(container=container, handle=handle)
    
    return

@phantom.playbook_block()
def decision_29(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_29() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["update_phantom_timestamp_from_servicenow:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_generate_servicenow_datetime_update_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def update_servicenow_timestamp_to_phantom(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_servicenow_timestamp_to_phantom() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_generate_servicenow_datetime_update_2:custom_function_result.data.data.formatted_datetime_str', 'cf_local_generate_servicenow_datetime_update_2:custom_function_result.data.data.servicenow_case_id'], action_results=results )
    literal_values_0 = [
        [
            "u_last_update_to_phantom",
        ],
    ]

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in literal_values_0:
            parameters.append({
                'value': item0[0],
                'field_name': item1[0],
                'servicenow_case_id': item0[1],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/set_servicenow_field", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_servicenow_field', parameters=parameters, name='update_servicenow_timestamp_to_phantom', callback=decision_30)

    return

@phantom.playbook_block()
def decision_30(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_30() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["update_servicenow_timestamp_to_phantom:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_generate_phantom_and_servicenow_diff_report_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def cf_local_generate_phantom_and_servicenow_diff_report_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_generate_phantom_and_servicenow_diff_report_1() called')
    
    filtered_custom_function_results_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_5:condition_1:compare_case:custom_function_result.data.data'])

    parameters = []

    for item0 in filtered_custom_function_results_data_0:
        parameters.append({
            'comparison_result': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/generate_phantom_and_servicenow_diff_report", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/generate_phantom_and_servicenow_diff_report', parameters=parameters, name='cf_local_generate_phantom_and_servicenow_diff_report_1', callback=decision_31)

    return

@phantom.playbook_block()
def decision_31(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_31() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_generate_phantom_and_servicenow_diff_report_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        format_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_2() called')
    
    template = """Daily Report at {0}

%%
{1}
----------------------------------------
%%"""

    # parameter list for template variable replacement
    parameters = [
        "cf_local_get_timestamp_1:custom_function_result.data.data",
        "cf_local_generate_phantom_and_servicenow_diff_report_1:custom_function_result.data.data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_2", separator=", ")

    cf_local_add_phantom_note_2(container=container)

    return

@phantom.playbook_block()
def cf_local_add_phantom_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_add_phantom_note_2() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    formatted_data_0 = [
        [
            phantom.get_format_data(name="format_2"),
        ],
    ]
    literal_values_0 = [
        [
            "Daily report",
        ],
    ]

    parameters = []

    for item0 in literal_values_0:
        for item1 in formatted_data_0:
            for item2 in container_property_0:
                parameters.append({
                    'title': item0[0],
                    'content': item1[0],
                    'container_input': item2[0],
                })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/add_phantom_note", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/add_phantom_note', parameters=parameters, name='cf_local_add_phantom_note_2')

    return

@phantom.playbook_block()
def cf_local_add_phantom_note_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_add_phantom_note_3() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data.system_debug_note_title'], action_results=results )
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "There are no active cases today",
        ],
    ]

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in literal_values_0:
            for item2 in container_property_0:
                parameters.append({
                    'title': item0[0],
                    'content': item1[0],
                    'container_input': item2[0],
                })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/add_phantom_note", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/add_phantom_note', parameters=parameters, name='cf_local_add_phantom_note_3')

    return

@phantom.playbook_block()
def cf_local_generate_servicenow_datetime_update_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_generate_servicenow_datetime_update_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_timestamp_1:custom_function_result.data.data'], action_results=results )
    filtered_custom_function_results_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_5:condition_1:compare_case:custom_function_result.data.data.servicenow_case_id'])

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in filtered_custom_function_results_data_0:
            parameters.append({
                'datetime_str': item0[0],
                'servicenow_case_id': item1[0],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/generate_servicenow_datetime_update", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/generate_servicenow_datetime_update', parameters=parameters, name='cf_local_generate_servicenow_datetime_update_1', callback=decision_32)

    return

@phantom.playbook_block()
def decision_32(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_32() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_generate_servicenow_datetime_update_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        update_servicenow_timestamp_from_phantom(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def cf_local_generate_servicenow_datetime_update_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_generate_servicenow_datetime_update_2() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_timestamp_1:custom_function_result.data.data'], action_results=results )
    filtered_custom_function_results_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_5:condition_1:compare_case:custom_function_result.data.data.servicenow_case_id'])

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in filtered_custom_function_results_data_0:
            parameters.append({
                'datetime_str': item0[0],
                'servicenow_case_id': item1[0],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/generate_servicenow_datetime_update", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/generate_servicenow_datetime_update', parameters=parameters, name='cf_local_generate_servicenow_datetime_update_2', callback=decision_33)

    return

@phantom.playbook_block()
def decision_33(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_33() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_generate_servicenow_datetime_update_2:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        update_servicenow_timestamp_to_phantom(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def filter_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_5() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["compare_case:custom_function_result.data.success", "==", True],
            ["compare_case:custom_function_result.data.data.skip", "==", False],
        ],
        logical_operator='and',
        name="filter_5:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def filter_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_6() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_ticket_2:action_result.status", "==", "success"],
            ["get_ticket_2:action_result.data.0.category", "in", "custom_list:phantom_case_category_to_update_servicenow"],
            ["get_ticket_2:action_result.data.0.assignment_group.value", "in", "custom_list:phantom_assignment_group_to_update_servicenow"],
        ],
        logical_operator='and',
        name="filter_6:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        debug_servicenow_get_ticket(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def cf_local_generate_servicenow_assigned_to_params_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_generate_servicenow_assigned_to_params_1() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['update_ticket_1:action_result.parameter.id', 'update_ticket_1:action_result.parameter.fields', 'update_ticket_1:action_result.parameter.table', 'update_ticket_1:action_result.parameter.context.artifact_id'], action_results=results )
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data'], action_results=results )

    parameters = []

    for item0 in action_results_data_0:
        for item1 in custom_function_result_0:
            parameters.append({
                'servicenow_case_id': item0[0],
                'servicenow_settings': item1[0],
                'servicenow_case_info': item0[1],
                'servicenow_case_table': item0[2],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/generate_servicenow_assigned_to_params", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/generate_servicenow_assigned_to_params', parameters=parameters, name='cf_local_generate_servicenow_assigned_to_params_1', callback=decision_34)

    return

@phantom.playbook_block()
def update_ticket_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_ticket_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'update_ticket_2' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_generate_servicenow_assigned_to_params_1:custom_function_result.data.data.servicenow_case_id', 'cf_local_generate_servicenow_assigned_to_params_1:custom_function_result.data.data.servicenow_case_table', 'cf_local_generate_servicenow_assigned_to_params_1:custom_function_result.data.data.field'], action_results=results)

    parameters = []
    
    # build parameters list for 'update_ticket_2' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'id': custom_function_results_item_1[0],
                'table': custom_function_results_item_1[1],
                'fields': custom_function_results_item_1[2],
                'vault_id': "",
                'is_sys_id': True,
            })

    phantom.act(action="update ticket", parameters=parameters, assets=['kcs-csoc-servicenow'], callback=decision_35, name="update_ticket_2")

    return

@phantom.playbook_block()
def decision_34(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_34() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_generate_servicenow_assigned_to_params_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        update_ticket_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def decision_35(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_35() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["update_ticket_2:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        join_cf_local_get_phantom_case_worknote_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def set_status_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_1() called')

    phantom.set_status(container=container, status="Cancelled")

    container = phantom.get_container(container.get('id', None))
    cf_community_container_update_1(container=container)

    return

@phantom.playbook_block()
def cf_local_set_phantom_custom_field_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_set_phantom_custom_field_3() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "Incident Type",
            "Operation",
        ],
    ]

    parameters = []

    for item0 in literal_values_0:
        for item1 in container_property_0:
            parameters.append({
                'field': item0[0],
                'value': item0[1],
                'container_input': item1[0],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/set_phantom_custom_field", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_phantom_custom_field', parameters=parameters, name='cf_local_set_phantom_custom_field_3', callback=cf_local_get_settings_1)

    return

@phantom.playbook_block()
def cf_community_container_update_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_container_update_1() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "(ServiceNow Reconcile)",
        ],
    ]

    parameters = []

    for item0 in literal_values_0:
        for item1 in container_property_0:
            parameters.append({
                'name': None,
                'tags': None,
                'label': None,
                'owner': None,
                'status': None,
                'severity': None,
                'input_json': None,
                'description': item0[0],
                'sensitivity': None,
                'container_input': item1[0],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/container_update", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/container_update', parameters=parameters, name='cf_community_container_update_1', callback=cf_local_set_phantom_custom_field_3)

    return

@phantom.playbook_block()
def cf_local_set_phantom_custom_field_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_set_phantom_custom_field_4() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "Detection Technology",
            "Others",
        ],
    ]

    parameters = []

    for item0 in container_property_0:
        for item1 in literal_values_0:
            parameters.append({
                'container_input': item0[0],
                'field': item1[0],
                'value': item1[1],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/set_phantom_custom_field", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_phantom_custom_field', parameters=parameters, name='cf_local_set_phantom_custom_field_4', callback=cf_local_set_phantom_custom_field_5)

    return

@phantom.playbook_block()
def cf_local_set_phantom_custom_field_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_set_phantom_custom_field_5() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "Assigned To",
            "SOAR System",
        ],
    ]

    parameters = []

    for item0 in container_property_0:
        for item1 in literal_values_0:
            parameters.append({
                'container_input': item0[0],
                'field': item1[0],
                'value': item1[1],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/set_phantom_custom_field", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_phantom_custom_field', parameters=parameters, name='cf_local_set_phantom_custom_field_5', callback=cf_local_set_phantom_custom_field_6)

    return

@phantom.playbook_block()
def cf_local_set_phantom_custom_field_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_set_phantom_custom_field_6() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "False Positive",
            "Yes",
        ],
    ]

    parameters = []

    for item0 in container_property_0:
        for item1 in literal_values_0:
            parameters.append({
                'container_input': item0[0],
                'field': item1[0],
                'value': item1[1],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/set_phantom_custom_field", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_phantom_custom_field', parameters=parameters, name='cf_local_set_phantom_custom_field_6', callback=set_status_1)

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