"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'cf_local_get_settings_1' block
    cf_local_get_settings_1(container=container)

    return

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
        get_phantom_based(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def get_phantom_based(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_phantom_based() called')
    
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
    phantom.custom_function(custom_function='local/get_list_item', parameters=parameters, name='get_phantom_based', callback=decision_3)

    return

def get_origin_based(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_origin_based() called')
    
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
    phantom.custom_function(custom_function='local/get_list_item', parameters=parameters, name='get_origin_based', callback=decision_4)

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_phantom_based:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        get_origin_based(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_origin_based:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_get_timestamp_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

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
    phantom.custom_function(custom_function='local/get_timestamp', parameters=parameters, name='cf_local_get_timestamp_1', callback=decision_5)

    return

def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_5() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_get_timestamp_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_get_updated_phantom_case_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def cf_local_get_updated_phantom_case_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_get_updated_phantom_case_1() called')
    
    literal_values_0 = [
        [
            480,
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
    phantom.custom_function(custom_function='local/get_updated_phantom_case', parameters=parameters, name='cf_local_get_updated_phantom_case_1', callback=decision_6)

    return

def decision_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_6() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_get_updated_phantom_case_1:custom_function_result.data.success", "==", True],
            ["cf_local_get_updated_phantom_case_1:custom_function_result.data.data", "!=", []],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_generate_servicenow_frontend_query_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    cf_local_log_debug_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_ticket_2:action_result.status", "==", "success"],
            ["get_ticket_2:action_result.data.0.category", "in", "custom_list:phantom_case_category_to_update_servicenow"],
            ["get_ticket_2:action_result.data.0.assignment_group.display_value", "in", "custom_list:phantom_assignment_group_to_update_servicenow"],
        ],
        logical_operator='and',
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        compare_case_fields(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_ticket_2:action_result.status", "==", "success"],
            ["get_ticket_2:action_result.data.0.category", "not in", "custom_list:phantom_case_category_to_update_servicenow"],
        ],
        logical_operator='and',
        name="filter_1:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        cf_local_add_phantom_note_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def cf_local_log_debug_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_log_debug_3() called')
    
    literal_values_0 = [
        [
            "There is no updated Phantom case",
        ],
    ]

    parameters = []

    for item0 in literal_values_0:
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
    phantom.custom_function(custom_function='local/log_debug', parameters=parameters, name='cf_local_log_debug_3')

    return

def cf_local_add_phantom_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_add_phantom_note_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data.system_debug_note_title', 'cf_local_get_settings_1:custom_function_result.data.data.category_not_allowed_message'], action_results=results )
    filtered_action_results_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_2:get_ticket_2:action_result.data.0.u_phantom_case_id'])

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in filtered_action_results_data_0:
            parameters.append({
                'title': item0[0],
                'content': item0[1],
                'container_input': item1[0],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/add_phantom_note", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/add_phantom_note', parameters=parameters, name='cf_local_add_phantom_note_1')

    return

def generate_SNOW_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('generate_SNOW_info() called')
    
    filtered_custom_function_results_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_12:condition_1:compare_case_fields:custom_function_result.data.data.raw_phantom', 'filtered-data:filter_12:condition_1:compare_case_fields:custom_function_result.data.data.assignment_group_update', 'filtered-data:filter_12:condition_1:compare_case_fields:custom_function_result.data.data.cancel_case', 'filtered-data:filter_12:condition_1:compare_case_fields:custom_function_result.data.data.incident_type_update'])
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_mapping_fields_1:custom_function_result.data.data'], action_results=results )
    custom_function_result_1 = phantom.collect2(container=container, datapath=['get_phantom_based:custom_function_result.data.data'], action_results=results )
    custom_function_result_2 = phantom.collect2(container=container, datapath=['get_origin_based:custom_function_result.data.data'], action_results=results )
    custom_function_result_3 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data'], action_results=results )
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
                    for item4 in custom_function_result_2:
                        for item5 in custom_function_result_3:
                            parameters.append({
                                'container_input': item0[0],
                                'container_key_mapping': item1[0],
                                'is_new_case': item2[0],
                                'phantom_based_field': item3[0],
                                'origin_based_field': item4[0],
                                'assignment_group_update': item0[1],
                                'cancel_case': item0[2],
                                'servicenow_settings': item5[0],
                                'incident_type_update': item0[3],
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
    phantom.custom_function(custom_function='local/generate_servicenow_case_info', parameters=parameters, name='generate_SNOW_info', callback=decision_10)

    return

def update_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_ticket_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'update_ticket_1' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['generate_SNOW_info:custom_function_result.data.data.servicenow_case_id', 'generate_SNOW_info:custom_function_result.data.data.servicenow_case_table', 'generate_SNOW_info:custom_function_result.data.data.field'], action_results=results)

    parameters = []
    
    # build parameters list for 'update_ticket_1' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'id': custom_function_results_item_1[0],
                'table': custom_function_results_item_1[1],
                'fields': custom_function_results_item_1[2],
                'vault_id': "",
                'is_sys_id': True,
            })

    phantom.act(action="update ticket", parameters=parameters, assets=['kcs-csoc-servicenow'], callback=cf_local_log_debug_4, name="update_ticket_1")

    return

def cf_local_get_phantom_case_worknote_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_get_phantom_case_worknote_1() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['update_ticket_2:action_result.data.0.u_phantom_case_id', 'update_ticket_2:action_result.parameter.context.artifact_id'], action_results=results )

    parameters = []

    for item0 in action_results_data_0:
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
    phantom.custom_function(custom_function='local/get_phantom_case_worknote', parameters=parameters, name='cf_local_get_phantom_case_worknote_1', callback=decision_15)

    return

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
    phantom.custom_function(custom_function='local/process_phantom_note', parameters=parameters, name='cf_local_process_phantom_note_1', callback=decision_12)

    return

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
    phantom.custom_function(custom_function='local/filter_new_worknote', parameters=parameters, name='cf_local_filter_new_worknote_1', callback=filter_11)

    return

def add_note_to_servicenow(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_to_servicenow() called')
    
    filtered_custom_function_results_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_11:condition_1:cf_local_filter_new_worknote_1:custom_function_result.data.data.*.note_info.content', 'filtered-data:filter_11:condition_1:cf_local_filter_new_worknote_1:custom_function_result.data.data.*.note_info.servicenow_case_id'])
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
    phantom.custom_function(custom_function='local/set_servicenow_field', parameters=parameters, name='add_note_to_servicenow', callback=decision_14)

    return

def update_servicenow_timestamp(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_servicenow_timestamp() called')
    
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
    phantom.custom_function(custom_function='local/set_servicenow_field', parameters=parameters, name='update_servicenow_timestamp')

    return

def update_phantom_timestamp(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_phantom_timestamp() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_timestamp_1:custom_function_result.data.data'], action_results=results )
    action_results_data_0 = phantom.collect2(container=container, datapath=['update_ticket_2:action_result.data.0.u_phantom_case_id', 'update_ticket_2:action_result.parameter.context.artifact_id'], action_results=results )
    literal_values_0 = [
        [
            "last_update_to_servicenow",
        ],
    ]

    parameters = []

    for item0 in literal_values_0:
        for item1 in custom_function_result_0:
            for item2 in action_results_data_0:
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
    phantom.custom_function(custom_function='local/set_phantom_custom_field', parameters=parameters, name='update_phantom_timestamp', callback=decision_16)

    return

def join_update_phantom_timestamp(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_update_phantom_timestamp() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_update_phantom_timestamp_called'):
        return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(custom_function_names=['cf_local_filter_new_worknote_1']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_update_phantom_timestamp_called', value='update_phantom_timestamp')
        
        # call connected block "update_phantom_timestamp"
        update_phantom_timestamp(container=container, handle=handle)
    
    return

def decision_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_10() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["generate_SNOW_info:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        update_ticket_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def decision_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_11() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["update_ticket_1:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_generate_servicenow_assigned_to_params_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def decision_12(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_12() called')

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

def decision_14(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_14() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["add_note_to_servicenow:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        join_update_phantom_timestamp(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def decision_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_15() called')

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

def filter_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_11() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_filter_new_worknote_1:custom_function_result.data.success", "==", True],
            ["cf_local_filter_new_worknote_1:custom_function_result.data.data", "!=", []],
        ],
        logical_operator='and',
        name="filter_11:condition_1")

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
        name="filter_11:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        join_update_phantom_timestamp(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def decision_16(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_16() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["update_phantom_timestamp:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_generate_servicenow_datetime_update_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def cf_local_log_debug_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_log_debug_4() called')
    
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
    phantom.custom_function(custom_function='local/log_debug', parameters=parameters, name='cf_local_log_debug_4', callback=decision_11)

    return

def cf_local_generate_servicenow_datetime_update_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_generate_servicenow_datetime_update_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_timestamp_1:custom_function_result.data.data'], action_results=results )
    action_results_data_0 = phantom.collect2(container=container, datapath=['update_ticket_2:action_result.data.0.sys_id', 'update_ticket_2:action_result.parameter.context.artifact_id'], action_results=results )

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in action_results_data_0:
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
    phantom.custom_function(custom_function='local/generate_servicenow_datetime_update', parameters=parameters, name='cf_local_generate_servicenow_datetime_update_1', callback=decision_25)

    return

def decision_25(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_25() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_generate_servicenow_datetime_update_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        update_servicenow_timestamp(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def cf_local_log_debug_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_log_debug_5() called')
    
    literal_values_0 = [
        [
            "Case status is cancelled or resolved on both Phantom and ServiceNow, No action required",
        ],
    ]

    parameters = []

    for item0 in literal_values_0:
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
    phantom.custom_function(custom_function='local/log_debug', parameters=parameters, name='cf_local_log_debug_5')

    return

def compare_case_fields(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('compare_case_fields() called')
    
    filtered_action_results_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:get_ticket_2:action_result.data.0'])

    parameters = []

    for item0 in filtered_action_results_data_0:
        parameters.append({
            'servicenow_case_obj': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/compare_assignment_group_and_status", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/compare_assignment_group_and_status', parameters=parameters, name='compare_case_fields', callback=filter_12)

    return

def filter_12(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_12() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["compare_case_fields:custom_function_result.data.success", "==", True],
            ["compare_case_fields:custom_function_result.data.data.skip", "==", False],
        ],
        logical_operator='and',
        name="filter_12:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        generate_SNOW_info(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["compare_case_fields:custom_function_result.data.success", "==", True],
            ["compare_case_fields:custom_function_result.data.data.skip", "==", True],
        ],
        logical_operator='and',
        name="filter_12:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        cf_local_log_debug_5(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

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
    phantom.custom_function(custom_function='local/generate_servicenow_assigned_to_params', parameters=parameters, name='cf_local_generate_servicenow_assigned_to_params_1', callback=decision_27)

    return

def get_ticket_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_ticket_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_ticket_2' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_generate_servicenow_frontend_query_1:custom_function_result.data.data'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_ticket_2' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'id': custom_function_results_item_1[0],
                'table': "incident",
                'is_sys_id': True,
            })

    phantom.act(action="get ticket", parameters=parameters, assets=['kcs-csoc-servicenow'], callback=filter_1, name="get_ticket_2")

    return

def cf_local_generate_servicenow_frontend_query_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_generate_servicenow_frontend_query_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_updated_phantom_case_1:custom_function_result.data.data.*.custom_fields.servicenow_case_id'], action_results=results )

    parameters = []

    for item0 in custom_function_result_0:
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
    phantom.custom_function(custom_function='local/generate_servicenow_frontend_query', parameters=parameters, name='cf_local_generate_servicenow_frontend_query_1', callback=decision_26)

    return

def decision_26(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_26() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_generate_servicenow_frontend_query_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        get_ticket_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

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

    phantom.act(action="update ticket", parameters=parameters, assets=['kcs-csoc-servicenow'], callback=decision_28, name="update_ticket_2")

    return

def decision_27(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_27() called')

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

def decision_28(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_28() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["update_ticket_2:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_get_phantom_case_worknote_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

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