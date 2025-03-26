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
        get_servicenow_based_field(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

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
    phantom.custom_function(custom_function='local/get_list_item', parameters=parameters, name='get_servicenow_based_field', callback=decision_3)

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

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
    phantom.custom_function(custom_function='local/get_list_item', parameters=parameters, name='get_origin_based_field', callback=decision_4)

    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_4() called')

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
        get_servicenow_updated_case(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def get_servicenow_updated_case(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_servicenow_updated_case() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_servicenow_updated_case' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data.servicenow_updated_case_query', 'cf_local_get_settings_1:custom_function_result.data.data.servicenow_case_table'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_servicenow_updated_case' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0] and custom_function_results_item_1[1]:
            parameters.append({
                'query': custom_function_results_item_1[0],
                'max_results': 100,
                'query_table': custom_function_results_item_1[1],
            })

    phantom.act(action="run query", parameters=parameters, assets=['kcs-csoc-servicenow'], callback=decision_6, name="get_servicenow_updated_case")

    return

def decision_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_6() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_servicenow_updated_case:action_result.status", "==", "success"],
            ["get_servicenow_updated_case:action_result.data", "!=", []],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_generate_servicenow_frontend_query_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_servicenow_updated_case:action_result.status", "==", "success"],
            ["get_servicenow_updated_case:action_result.data", "==", []],
        ],
        logical_operator='and')

    # call connected blocks if condition 2 matched
    if matched:
        cf_local_log_debug_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def cf_local_log_debug_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_log_debug_2() called')
    
    literal_values_0 = [
        [
            "There is no updated ServiceNow case",
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
    phantom.custom_function(custom_function='local/log_debug', parameters=parameters, name='cf_local_log_debug_2')

    return

def get_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_ticket_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_ticket_1' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_generate_servicenow_frontend_query_1:custom_function_result.data.data'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data.servicenow_case_table'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_ticket_1' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        for custom_function_results_item_2 in custom_function_results_data_2:
            if custom_function_results_item_1[0]:
                parameters.append({
                    'id': custom_function_results_item_1[0],
                    'table': custom_function_results_item_2[0],
                    'is_sys_id': True,
                })

    phantom.act(action="get ticket", parameters=parameters, assets=['kcs-csoc-servicenow'], callback=decision_11, name="get_ticket_1")

    return

def cf_local_generate_phantom_case_info_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_generate_phantom_case_info_3() called')
    
    filtered_custom_function_results_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_5:condition_1:cf_local_compare_assignment_group_and_status_1:custom_function_result.data.data.raw_servicenow', 'filtered-data:filter_5:condition_1:cf_local_compare_assignment_group_and_status_1:custom_function_result.data.data.cancel_case'])
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_mapping_fields_1:custom_function_result.data.data'], action_results=results )
    custom_function_result_1 = phantom.collect2(container=container, datapath=['get_servicenow_based_field:custom_function_result.data.data'], action_results=results )
    custom_function_result_2 = phantom.collect2(container=container, datapath=['get_origin_based_field:custom_function_result.data.data'], action_results=results )
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
                        parameters.append({
                            'servicenow_case': item0[0],
                            'container_key_mapping': item1[0],
                            'is_new_case': item2[0],
                            'servicenow_based_field': item3[0],
                            'origin_based_field': item4[0],
                            'assignment_group': None,
                            'cancel_case': item0[1],
                        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/generate_phantom_case_info", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/generate_phantom_case_info', parameters=parameters, name='cf_local_generate_phantom_case_info_3', callback=decision_8)

    return

def cf_local_update_phantom_case_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_update_phantom_case_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_generate_phantom_case_info_3:custom_function_result.data.data.formatted.id', 'cf_local_generate_phantom_case_info_3:custom_function_result.data.data.formatted'], action_results=results )

    parameters = []

    for item0 in custom_function_result_0:
        parameters.append({
            'container_input': item0[0],
            'updating_info': item0[1],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/update_phantom_case", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/update_phantom_case', parameters=parameters, name='cf_local_update_phantom_case_1', callback=decision_7)

    return

def cf_local_add_phantom_artifact_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_add_phantom_artifact_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_generate_phantom_case_info_3:custom_function_result.data.data.formatted.id', 'cf_local_generate_phantom_case_info_3:custom_function_result.data.data.raw'], action_results=results )
    custom_function_result_1 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data.phantom_artifact_name'], action_results=results )
    literal_values_0 = [
        [
            "low",
        ],
    ]

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in custom_function_result_1:
            for item2 in literal_values_0:
                parameters.append({
                    'container_input': item0[0],
                    'artifact': item0[1],
                    'name': item1[0],
                    'label': None,
                    'severity': item2[0],
                })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/add_phantom_artifact", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/add_phantom_artifact', parameters=parameters, name='cf_local_add_phantom_artifact_1', callback=decision_9)

    return

def decision_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_7() called')

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

def decision_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_8() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_generate_phantom_case_info_3:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_update_phantom_case_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def cf_local_limit_phantom_artifact_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_limit_phantom_artifact_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_add_phantom_artifact_1:custom_function_result.data.data.container_id'], action_results=results )
    custom_function_result_1 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data.maximum_artifact', 'cf_local_get_settings_1:custom_function_result.data.data.phantom_artifact_name'], action_results=results )

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in custom_function_result_1:
            parameters.append({
                'container_input': item0[0],
                'maximum_artifact': item1[0],
                'artifact_name': item1[1],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/limit_phantom_artifact", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/limit_phantom_artifact', parameters=parameters, name='cf_local_limit_phantom_artifact_1', callback=decision_10)

    return

def decision_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_9() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_add_phantom_artifact_1:custom_function_result.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_limit_phantom_artifact_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def decision_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_10() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_limit_phantom_artifact_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_process_servicenow_note_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def decision_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_11() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_ticket_1:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_log_debug_5(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def cf_local_generate_servicenow_frontend_query_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_generate_servicenow_frontend_query_1() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['get_servicenow_updated_case:action_result.data.*.sys_id', 'get_servicenow_updated_case:action_result.parameter.context.artifact_id'], action_results=results )

    parameters = []

    for item0 in action_results_data_0:
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
    phantom.custom_function(custom_function='local/generate_servicenow_frontend_query', parameters=parameters, name='cf_local_generate_servicenow_frontend_query_1', callback=decision_12)

    return

def decision_12(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_12() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_generate_servicenow_frontend_query_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        get_ticket_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def cf_local_process_servicenow_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_process_servicenow_note_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_add_phantom_artifact_1:custom_function_result.data.data.artifact_raw'], action_results=results )
    custom_function_result_1 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data.note_title_from_servicenow'], action_results=results )

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in custom_function_result_1:
            parameters.append({
                'raw_servicenow_response': item0[0],
                'note_title': item1[0],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/process_servicenow_note", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/process_servicenow_note', parameters=parameters, name='cf_local_process_servicenow_note_1', callback=decision_13)

    return

def decision_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_13() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_process_servicenow_note_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_filter_new_worknote_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def cf_local_filter_new_worknote_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_filter_new_worknote_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_process_servicenow_note_1:custom_function_result.data.data'], action_results=results )
    custom_function_result_1 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data'], action_results=results )
    literal_values_0 = [
        [
            "servicenow",
        ],
    ]

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in literal_values_0:
            for item2 in custom_function_result_1:
                parameters.append({
                    'note_list': item0[0],
                    'filter_from': item1[0],
                    'settings': item2[0],
                })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/filter_new_worknote", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/filter_new_worknote', parameters=parameters, name='cf_local_filter_new_worknote_1', callback=filter_4)

    return

def cf_local_add_phantom_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_add_phantom_note_1() called')
    
    filtered_custom_function_results_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_4:condition_1:cf_local_filter_new_worknote_1:custom_function_result.data.data.*.note_info.phantom_case_id', 'filtered-data:filter_4:condition_1:cf_local_filter_new_worknote_1:custom_function_result.data.data.*.note_info.title', 'filtered-data:filter_4:condition_1:cf_local_filter_new_worknote_1:custom_function_result.data.data.*.note_info.content'])

    parameters = []

    for item0 in filtered_custom_function_results_data_0:
        parameters.append({
            'container_input': item0[0],
            'title': item0[1],
            'content': item0[2],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/add_phantom_note", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/add_phantom_note', parameters=parameters, name='cf_local_add_phantom_note_1', callback=decision_15)

    return

def decision_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_15() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_add_phantom_note_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        join_update_phantom_timestamp(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def update_phantom_timestamp(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_phantom_timestamp() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_add_phantom_artifact_1:custom_function_result.data.data.container_id'], action_results=results )
    custom_function_result_1 = phantom.collect2(container=container, datapath=['cf_local_get_timestamp_1:custom_function_result.data.data'], action_results=results )
    literal_values_0 = [
        [
            "last_update_from_servicenow",
        ],
    ]

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in literal_values_0:
            for item2 in custom_function_result_1:
                parameters.append({
                    'container_input': item0[0],
                    'field': item1[0],
                    'value': item2[0],
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

def update_servicenow_timestamp(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_servicenow_timestamp() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_generate_servicenow_datetime_update_1:custom_function_result.data.data.servicenow_case_id', 'cf_local_generate_servicenow_datetime_update_1:custom_function_result.data.data.formatted_datetime_str'], action_results=results )
    literal_values_0 = [
        [
            "u_last_update_to_phantom",
        ],
    ]

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in literal_values_0:
            parameters.append({
                'servicenow_case_id': item0[0],
                'field_name': item1[0],
                'value': item0[1],
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

def filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_4() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_filter_new_worknote_1:custom_function_result.data.success", "==", True],
            ["cf_local_filter_new_worknote_1:custom_function_result.data.data", "!=", []],
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
            ["cf_local_filter_new_worknote_1:custom_function_result.data.success", "==", True],
            ["cf_local_filter_new_worknote_1:custom_function_result.data.data", "==", []],
        ],
        logical_operator='and',
        name="filter_4:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        join_update_phantom_timestamp(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def cf_local_log_debug_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_log_debug_5() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['get_ticket_1:action_result.data.0', 'get_ticket_1:action_result.parameter.context.artifact_id'], action_results=results )

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
    phantom.custom_function(custom_function='local/log_debug', parameters=parameters, name='cf_local_log_debug_5', callback=cf_local_compare_assignment_group_and_status_1)

    return

def cf_local_generate_servicenow_datetime_update_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_generate_servicenow_datetime_update_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_add_phantom_artifact_1:custom_function_result.data.data.artifact_raw.sys_id'], action_results=results )
    custom_function_result_1 = phantom.collect2(container=container, datapath=['cf_local_get_timestamp_1:custom_function_result.data.data'], action_results=results )

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in custom_function_result_1:
            parameters.append({
                'servicenow_case_id': item0[0],
                'datetime_str': item1[0],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/generate_servicenow_datetime_update", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/generate_servicenow_datetime_update', parameters=parameters, name='cf_local_generate_servicenow_datetime_update_1', callback=decision_17)

    return

def decision_17(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_17() called')

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

def cf_local_compare_assignment_group_and_status_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_compare_assignment_group_and_status_1() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['get_ticket_1:action_result.data.0', 'get_ticket_1:action_result.parameter.context.artifact_id'], action_results=results )

    parameters = []

    for item0 in action_results_data_0:
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
    phantom.custom_function(custom_function='local/compare_assignment_group_and_status', parameters=parameters, name='cf_local_compare_assignment_group_and_status_1', callback=filter_5)

    return

def filter_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_5() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_compare_assignment_group_and_status_1:custom_function_result.data.success", "==", True],
            ["cf_local_compare_assignment_group_and_status_1:custom_function_result.data.data.skip", "==", False],
        ],
        logical_operator='and',
        name="filter_5:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        cf_local_generate_phantom_case_info_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_compare_assignment_group_and_status_1:custom_function_result.data.success", "==", True],
            ["cf_local_compare_assignment_group_and_status_1:custom_function_result.data.data.skip", "==", True],
        ],
        logical_operator='and',
        name="filter_5:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        cf_local_log_debug_6(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def cf_local_log_debug_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_log_debug_6() called')
    
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
    phantom.custom_function(custom_function='local/log_debug', parameters=parameters, name='cf_local_log_debug_6')

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