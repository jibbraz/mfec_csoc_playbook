"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'get_allowed_assignment_group' block
    get_allowed_assignment_group(container=container)

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
        get_incident_type_allowed_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def get_incident_type_allowed_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_incident_type_allowed_list() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data.Incident_type_allow_list_name'], action_results=results )

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
    phantom.custom_function(custom_function='local/get_list_item', parameters=parameters, name='get_incident_type_allowed_list', callback=decision_3)

    return

@phantom.playbook_block()
def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_incident_type_allowed_list:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_get_timestamp_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def cf_local_get_new_phantom_case_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_get_new_phantom_case_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data.start_datetime'], action_results=results )
    literal_values_0 = [
        [
            60,
        ],
    ]

    parameters = []

    for item0 in literal_values_0:
        for item1 in custom_function_result_0:
            parameters.append({
                'minute_ago': item0[0],
                'start_datetime': item1[0],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/get_new_phantom_case", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/get_new_phantom_case', parameters=parameters, name='cf_local_get_new_phantom_case_1', callback=decision_4)

    return

@phantom.playbook_block()
def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_get_new_phantom_case_1:custom_function_result.data.success", "==", True],
            ["cf_local_get_new_phantom_case_1:custom_function_result.data.data", "!=", []],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_filter_phantom_allowed_case_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    cf_local_log_debug_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

@phantom.playbook_block()
def cf_local_filter_phantom_allowed_case_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_filter_phantom_allowed_case_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['get_incident_type_allowed_list:custom_function_result.data.data'], action_results=results )
    custom_function_result_1 = phantom.collect2(container=container, datapath=['cf_local_get_new_phantom_case_1:custom_function_result.data.data'], action_results=results )

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in custom_function_result_1:
            parameters.append({
                'allow_list': item0[0],
                'container_list': item1[0],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/filter_phantom_allowed_case", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/filter_phantom_allowed_case', parameters=parameters, name='cf_local_filter_phantom_allowed_case_1', callback=decision_6)

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
    phantom.custom_function(custom_function='local/get_timestamp', parameters=parameters, name='cf_local_get_timestamp_1', callback=decision_5)

    return

@phantom.playbook_block()
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
        cf_local_get_new_phantom_case_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def decision_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_6() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_filter_phantom_allowed_case_1:custom_function_result.data.success", "==", True],
            ["cf_local_filter_phantom_allowed_case_1:custom_function_result.data.data", "!=", []],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_generate_servicenow_case_info_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    cf_local_log_debug_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

@phantom.playbook_block()
def cf_local_generate_servicenow_case_info_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_generate_servicenow_case_info_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_filter_phantom_allowed_case_1:custom_function_result.data.data.*.id'], action_results=results )
    custom_function_result_1 = phantom.collect2(container=container, datapath=['cf_local_get_mapping_fields_1:custom_function_result.data.data'], action_results=results )
    custom_function_result_2 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data'], action_results=results )
    custom_function_result_3 = phantom.collect2(container=container, datapath=['get_allowed_assignment_group:custom_function_result.data.data'], action_results=results )
    literal_values_0 = [
        [
            "yes",
        ],
    ]

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in custom_function_result_1:
            for item2 in literal_values_0:
                for item3 in custom_function_result_2:
                    for item4 in custom_function_result_3:
                        parameters.append({
                            'container_input': item0[0],
                            'container_key_mapping': item1[0],
                            'is_new_case': item2[0],
                            'phantom_based_field': None,
                            'origin_based_field': None,
                            'assignment_group_update': None,
                            'cancel_case': None,
                            'servicenow_settings': item3[0],
                            'incident_type_update': None,
                            'new_case_assignment_group_allowed_list': item4[0],
                        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/generate_servicenow_case_info", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/generate_servicenow_case_info', parameters=parameters, name='cf_local_generate_servicenow_case_info_1', callback=decision_7)

    return

@phantom.playbook_block()
def cf_local_log_debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_log_debug_1() called')
    
    literal_values_0 = [
        [
            "There is no allowed incident type phantom case",
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
    phantom.custom_function(custom_function='local/log_debug', parameters=parameters, name='cf_local_log_debug_1')

    return

@phantom.playbook_block()
def cf_local_log_debug_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_log_debug_2() called')
    
    literal_values_0 = [
        [
            "There is no new phantom case",
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

@phantom.playbook_block()
def create_ticket_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_ticket_3() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_ticket_3' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data.servicenow_case_table'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_generate_servicenow_case_info_1:custom_function_result.data.data.field'], action_results=results)

    parameters = []
    
    # build parameters list for 'create_ticket_3' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        for custom_function_results_item_2 in custom_function_results_data_2:
            parameters.append({
                'table': custom_function_results_item_1[0],
                'fields': custom_function_results_item_2[0],
                'vault_id': "",
                'description': "",
                'short_description': "",
            })

    phantom.act(action="create ticket", parameters=parameters, assets=['kcs-csoc-servicenow'], callback=decision_8, name="create_ticket_3")

    return

@phantom.playbook_block()
def update_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_ticket_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'update_ticket_1' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_generate_servicenow_assigned_to_params_1:custom_function_result.data.data.servicenow_case_id', 'cf_local_generate_servicenow_assigned_to_params_1:custom_function_result.data.data.servicenow_case_table', 'cf_local_generate_servicenow_assigned_to_params_1:custom_function_result.data.data.field'], action_results=results)

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

    phantom.act(action="update ticket", parameters=parameters, assets=['kcs-csoc-servicenow'], callback=decision_9, name="update_ticket_1")

    return

@phantom.playbook_block()
def cf_local_get_phantom_case_worknote_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_get_phantom_case_worknote_1() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['create_ticket_3:action_result.data.0.u_phantom_case_id', 'create_ticket_3:action_result.parameter.context.artifact_id'], action_results=results )

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
    phantom.custom_function(custom_function='local/get_phantom_case_worknote', parameters=parameters, name='cf_local_get_phantom_case_worknote_1', callback=decision_11)

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
    phantom.custom_function(custom_function='local/process_phantom_note', parameters=parameters, name='cf_local_process_phantom_note_1', callback=filter_6)

    return

@phantom.playbook_block()
def filter_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_6() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_process_phantom_note_1:custom_function_result.data.success", "==", True],
            ["cf_local_process_phantom_note_1:custom_function_result.data.data", "!=", []],
        ],
        logical_operator='and',
        name="filter_6:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_note_to_servicenow(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_process_phantom_note_1:custom_function_result.data.success", "==", True],
            ["cf_local_process_phantom_note_1:custom_function_result.data.data", "==", []],
        ],
        logical_operator='and',
        name="filter_6:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        join_cf_local_generate_servicenow_datetime_update_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

@phantom.playbook_block()
def add_note_to_servicenow(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_to_servicenow() called')
    
    filtered_custom_function_results_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_6:condition_1:cf_local_process_phantom_note_1:custom_function_result.data.data.*.note_info.content', 'filtered-data:filter_6:condition_1:cf_local_process_phantom_note_1:custom_function_result.data.data.*.note_info.servicenow_case_id'])
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
    phantom.custom_function(custom_function='local/set_servicenow_field', parameters=parameters, name='add_note_to_servicenow', callback=decision_12)

    return

@phantom.playbook_block()
def set_servicenow_timestamp(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_servicenow_timestamp() called')
    
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
    phantom.custom_function(custom_function='local/set_servicenow_field', parameters=parameters, name='set_servicenow_timestamp', callback=decision_13)

    return

@phantom.playbook_block()
def set_phantom_timestamp(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_phantom_timestamp() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_timestamp_1:custom_function_result.data.data'], action_results=results )
    action_results_data_0 = phantom.collect2(container=container, datapath=['update_ticket_1:action_result.data.0.u_phantom_case_id', 'update_ticket_1:action_result.parameter.context.artifact_id'], action_results=results )
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
    phantom.custom_function(custom_function='local/set_phantom_custom_field', parameters=parameters, name='set_phantom_timestamp', callback=decision_14)

    return

@phantom.playbook_block()
def set_phantom_originate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_phantom_originate() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['update_ticket_1:action_result.data.0.u_phantom_case_id', 'update_ticket_1:action_result.parameter.context.artifact_id'], action_results=results )
    literal_values_0 = [
        [
            "originate_from",
            "Phantom",
        ],
    ]

    parameters = []

    for item0 in literal_values_0:
        for item1 in action_results_data_0:
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
    phantom.custom_function(custom_function='local/set_phantom_custom_field', parameters=parameters, name='set_phantom_originate')

    return

@phantom.playbook_block()
def assign_servicenow_case_id(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('assign_servicenow_case_id() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['create_ticket_3:action_result.summary.created_ticket_id', 'create_ticket_3:action_result.data.0.u_phantom_case_id', 'create_ticket_3:action_result.parameter.context.artifact_id'], action_results=results )
    literal_values_0 = [
        [
            "servicenow_case_id",
        ],
    ]

    parameters = []

    for item0 in literal_values_0:
        for item1 in action_results_data_0:
            parameters.append({
                'field': item0[0],
                'value': item1[0],
                'container_input': item1[1],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/set_phantom_custom_field", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_phantom_custom_field', parameters=parameters, name='assign_servicenow_case_id', callback=decision_10)

    return

@phantom.playbook_block()
def decision_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_7() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_generate_servicenow_case_info_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        create_ticket_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def decision_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_8() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["create_ticket_3:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_generate_servicenow_assigned_to_params_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def decision_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_9() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["update_ticket_1:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        assign_servicenow_case_id(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def decision_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_10() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["assign_servicenow_case_id:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        assign_servicenow_case_number(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def decision_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_11() called')

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
def decision_12(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_12() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["add_note_to_servicenow:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        join_cf_local_generate_servicenow_datetime_update_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def decision_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_13() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["set_servicenow_timestamp:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        set_phantom_timestamp(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def decision_14(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_14() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["set_phantom_timestamp:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        set_phantom_originate(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def cf_local_generate_servicenow_datetime_update_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_generate_servicenow_datetime_update_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_timestamp_1:custom_function_result.data.data'], action_results=results )
    action_results_data_0 = phantom.collect2(container=container, datapath=['update_ticket_1:action_result.data.0.sys_id', 'update_ticket_1:action_result.parameter.context.artifact_id'], action_results=results )

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
    phantom.custom_function(custom_function='local/generate_servicenow_datetime_update', parameters=parameters, name='cf_local_generate_servicenow_datetime_update_1', callback=decision_15)

    return

@phantom.playbook_block()
def join_cf_local_generate_servicenow_datetime_update_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_cf_local_generate_servicenow_datetime_update_1() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_cf_local_generate_servicenow_datetime_update_1_called'):
        return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(custom_function_names=['cf_local_process_phantom_note_1']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_cf_local_generate_servicenow_datetime_update_1_called', value='cf_local_generate_servicenow_datetime_update_1')
        
        # call connected block "cf_local_generate_servicenow_datetime_update_1"
        cf_local_generate_servicenow_datetime_update_1(container=container, handle=handle)
    
    return

@phantom.playbook_block()
def decision_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_15() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_generate_servicenow_datetime_update_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        set_servicenow_timestamp(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def assign_servicenow_case_number(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('assign_servicenow_case_number() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['create_ticket_3:action_result.data.0.number', 'create_ticket_3:action_result.data.0.u_phantom_case_id', 'create_ticket_3:action_result.parameter.context.artifact_id'], action_results=results )
    literal_values_0 = [
        [
            "servicenow_case_number",
        ],
    ]

    parameters = []

    for item0 in literal_values_0:
        for item1 in action_results_data_0:
            parameters.append({
                'field': item0[0],
                'value': item1[0],
                'container_input': item1[1],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/set_phantom_custom_field", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_phantom_custom_field', parameters=parameters, name='assign_servicenow_case_number', callback=decision_16)

    return

@phantom.playbook_block()
def decision_16(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_16() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["assign_servicenow_case_number:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_get_phantom_case_worknote_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def cf_local_generate_servicenow_assigned_to_params_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_generate_servicenow_assigned_to_params_1() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['create_ticket_3:action_result.summary.created_ticket_id', 'create_ticket_3:action_result.parameter.fields', 'create_ticket_3:action_result.parameter.table', 'create_ticket_3:action_result.parameter.context.artifact_id'], action_results=results )
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
    phantom.custom_function(custom_function='local/generate_servicenow_assigned_to_params', parameters=parameters, name='cf_local_generate_servicenow_assigned_to_params_1', callback=decision_17)

    return

@phantom.playbook_block()
def decision_17(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_17() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_generate_servicenow_assigned_to_params_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        update_ticket_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def get_allowed_assignment_group(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_allowed_assignment_group() called')
    
    literal_values_0 = [
        [
            "phantom_assignment_group_to_update_servicenow",
        ],
    ]

    parameters = []

    for item0 in literal_values_0:
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
    phantom.custom_function(custom_function='local/get_list_item', parameters=parameters, name='get_allowed_assignment_group', callback=decision_18)

    return

@phantom.playbook_block()
def decision_18(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_18() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_allowed_assignment_group:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_get_settings_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

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