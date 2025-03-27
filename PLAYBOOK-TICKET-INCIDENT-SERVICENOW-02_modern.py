"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'cf_local_get_settings_1' block
    cf_local_get_settings_1(container=container)

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
    phantom.custom_function(custom_function='local/get_settings', parameters=parameters, name='cf_local_get_settings_1', callback=decision_10)

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
    phantom.custom_function(custom_function='local/get_mapping_fields', parameters=parameters, name='cf_local_get_mapping_fields_1', callback=decision_11)

    return

@phantom.playbook_block()
def get_allowed_inc(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_allowed_inc() called')
    
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
    phantom.custom_function(custom_function='local/get_list_item', parameters=parameters, name='get_allowed_inc', callback=decision_12)

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
    phantom.custom_function(custom_function='local/get_timestamp', parameters=parameters, name='cf_local_get_timestamp_1', callback=decision_13)

    return

@phantom.playbook_block()
def decision_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_10() called')

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
def decision_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_11() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_get_mapping_fields_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        get_allowed_inc(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
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
            ["get_allowed_inc:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_get_timestamp_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
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
            ["cf_local_get_timestamp_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_get_latest_artifact_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def cf_local_get_latest_artifact_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_get_latest_artifact_1() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]

    parameters = []

    for item0 in container_property_0:
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

    # call custom function "local/get_latest_artifact", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/get_latest_artifact', parameters=parameters, name='cf_local_get_latest_artifact_1', callback=decision_14)

    return

@phantom.playbook_block()
def decision_14(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_14() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_get_latest_artifact_1:custom_function_result.data.data.subcategory", "in", "custom_list:servicenow_incident_type_allow_list"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        promote_to_case_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    format_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

@phantom.playbook_block()
def cf_local_log_debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_log_debug_1() called')
    
    formatted_data_0 = [
        [
            phantom.get_format_data(name="format_1"),
        ],
    ]

    parameters = []

    for item0 in formatted_data_0:
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
    phantom.custom_function(custom_function='local/log_debug', parameters=parameters, name='cf_local_log_debug_1', callback=cf_local_add_phantom_note_1)

    return

@phantom.playbook_block()
def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_1() called')
    
    template = """{0}. ({1})"""

    # parameter list for template variable replacement
    parameters = [
        "cf_local_get_settings_1:custom_function_result.data.data.subcategory_not_allowed_message",
        "cf_local_get_latest_artifact_1:custom_function_result.data.data.subcategory",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1", separator=", ")

    cf_local_log_debug_1(container=container)

    return

@phantom.playbook_block()
def promote_to_case_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('promote_to_case_1() called')

    phantom.promote(container=container, template="NIST 800-61")

    container = phantom.get_container(container.get('id', None))
    cf_local_query_servicenow_1(container=container)

    return

@phantom.playbook_block()
def cf_local_add_phantom_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_add_phantom_note_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data.system_debug_note_title'], action_results=results )
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    formatted_data_0 = [
        [
            phantom.get_format_data(name="format_1"),
        ],
    ]

    parameters = []

    for item0 in container_property_0:
        for item1 in custom_function_result_0:
            for item2 in formatted_data_0:
                parameters.append({
                    'container_input': item0[0],
                    'title': item1[0],
                    'content': item2[0],
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

@phantom.playbook_block()
def cf_local_generate_phantom_case_info_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_generate_phantom_case_info_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_latest_artifact_1:custom_function_result.data.data'], action_results=results )
    custom_function_result_1 = phantom.collect2(container=container, datapath=['cf_local_get_mapping_fields_1:custom_function_result.data.data'], action_results=results )
    custom_function_result_2 = phantom.collect2(container=container, datapath=['cf_local_query_servicenow_1:custom_function_result.data.data.name'], action_results=results )
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
                    parameters.append({
                        'servicenow_case': item0[0],
                        'container_key_mapping': item1[0],
                        'is_new_case': item2[0],
                        'servicenow_based_field': None,
                        'origin_based_field': None,
                        'assignment_group': item3[0],
                        'cancel_case': None,
                    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/generate_phantom_case_info", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/generate_phantom_case_info', parameters=parameters, name='cf_local_generate_phantom_case_info_1', callback=decision_16)

    return

@phantom.playbook_block()
def decision_16(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_16() called')

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
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_generate_phantom_case_info_1:custom_function_result.data.data.formatted'], action_results=results )
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]

    parameters = []

    for item0 in container_property_0:
        for item1 in custom_function_result_0:
            parameters.append({
                'container_input': item0[0],
                'updating_info': item1[0],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/update_phantom_case", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/update_phantom_case', parameters=parameters, name='cf_local_update_phantom_case_1', callback=decision_17)

    return

@phantom.playbook_block()
def decision_17(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_17() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_update_phantom_case_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        assign_serviecnow_case_number(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def set_phantom_case_id_to_servicenow(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_phantom_case_id_to_servicenow() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_latest_artifact_1:custom_function_result.data.data.sys_id'], action_results=results )
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "u_phantom_case_id",
        ],
    ]

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in literal_values_0:
            for item2 in container_property_0:
                parameters.append({
                    'servicenow_case_id': item0[0],
                    'field_name': item1[0],
                    'value': item2[0],
                })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/set_servicenow_field", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_servicenow_field', parameters=parameters, name='set_phantom_case_id_to_servicenow', callback=decision_18)

    return

@phantom.playbook_block()
def decision_18(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_18() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["set_phantom_case_id_to_servicenow:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        generate_servicenow_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def generate_servicenow_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('generate_servicenow_query() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_latest_artifact_1:custom_function_result.data.data.sys_id'], action_results=results )

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
    phantom.custom_function(custom_function='local/generate_servicenow_frontend_query', parameters=parameters, name='generate_servicenow_query', callback=decision_19)

    return

@phantom.playbook_block()
def decision_19(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_19() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["generate_servicenow_query:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        get_ticket_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def get_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_ticket_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_ticket_1' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['generate_servicenow_query:custom_function_result.data.data'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_ticket_1' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'id': custom_function_results_item_1[0],
                'table': "incident",
                'is_sys_id': True,
            })

    phantom.act(action="get ticket", parameters=parameters, assets=['kcs-csoc-servicenow'], callback=decision_21, name="get_ticket_1")

    return

@phantom.playbook_block()
def decision_21(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_21() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_ticket_1:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_process_servicenow_note_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def cf_local_process_servicenow_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_process_servicenow_note_1() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['get_ticket_1:action_result.data.0', 'get_ticket_1:action_result.parameter.context.artifact_id'], action_results=results )
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_settings_1:custom_function_result.data.data.note_title_from_servicenow'], action_results=results )

    parameters = []

    for item0 in action_results_data_0:
        for item1 in custom_function_result_0:
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
    phantom.custom_function(custom_function='local/process_servicenow_note', parameters=parameters, name='cf_local_process_servicenow_note_1', callback=decision_22)

    return

@phantom.playbook_block()
def cf_local_add_phantom_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_add_phantom_note_2() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_process_servicenow_note_1:custom_function_result.data.data.*.note_info.title', 'cf_local_process_servicenow_note_1:custom_function_result.data.data.*.note_info.content'], action_results=results )
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]

    parameters = []

    for item0 in container_property_0:
        for item1 in custom_function_result_0:
            parameters.append({
                'container_input': item0[0],
                'title': item1[0],
                'content': item1[1],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/add_phantom_note", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/add_phantom_note', parameters=parameters, name='cf_local_add_phantom_note_2', callback=decision_27)

    return

@phantom.playbook_block()
def decision_22(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_22() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_process_servicenow_note_1:custom_function_result.data.success", "==", True],
            ["cf_local_process_servicenow_note_1:custom_function_result.data.data", "!=", []],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_add_phantom_note_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_process_servicenow_note_1:custom_function_result.data.success", "==", True],
            ["cf_local_process_servicenow_note_1:custom_function_result.data.data", "==", []],
        ],
        logical_operator='and')

    # call connected blocks if condition 2 matched
    if matched:
        join_update_phantom_timestamp(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def update_phantom_timestamp(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_phantom_timestamp() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_timestamp_1:custom_function_result.data.data'], action_results=results )
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "last_update_from_servicenow",
        ],
    ]

    parameters = []

    for item0 in container_property_0:
        for item1 in literal_values_0:
            for item2 in custom_function_result_0:
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
    phantom.custom_function(custom_function='local/set_phantom_custom_field', parameters=parameters, name='update_phantom_timestamp', callback=decision_24)

    return

@phantom.playbook_block()
def join_update_phantom_timestamp(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_update_phantom_timestamp() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_update_phantom_timestamp_called'):
        return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(custom_function_names=['cf_local_process_servicenow_note_1']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_update_phantom_timestamp_called', value='update_phantom_timestamp')
        
        # call connected block "update_phantom_timestamp"
        update_phantom_timestamp(container=container, handle=handle)
    
    return

@phantom.playbook_block()
def decision_24(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_24() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["update_phantom_timestamp:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        set_origin(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def set_origin(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_origin() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "originate_from",
            "ServiceNow",
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
    phantom.custom_function(custom_function='local/set_phantom_custom_field', parameters=parameters, name='set_origin', callback=decision_25)

    return

@phantom.playbook_block()
def decision_25(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_25() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["set_origin:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_generate_servicenow_datetime_update_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
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

@phantom.playbook_block()
def decision_27(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_27() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_add_phantom_note_2:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        join_update_phantom_timestamp(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def cf_local_query_servicenow_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_query_servicenow_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_latest_artifact_1:custom_function_result.data.data.assignment_group'], action_results=results )
    literal_values_0 = [
        [
            "sys_user_group",
        ],
    ]

    parameters = []

    for item0 in literal_values_0:
        for item1 in custom_function_result_0:
            parameters.append({
                'table': item0[0],
                'sys_id': item1[0],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/query_servicenow", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/query_servicenow', parameters=parameters, name='cf_local_query_servicenow_1', callback=decision_29)

    return

@phantom.playbook_block()
def decision_29(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_29() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_query_servicenow_1:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_generate_phantom_case_info_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def cf_local_generate_servicenow_datetime_update_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_generate_servicenow_datetime_update_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_latest_artifact_1:custom_function_result.data.data.sys_id'], action_results=results )
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
    phantom.custom_function(custom_function='local/generate_servicenow_datetime_update', parameters=parameters, name='cf_local_generate_servicenow_datetime_update_1', callback=decision_30)

    return

@phantom.playbook_block()
def decision_30(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_30() called')

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

@phantom.playbook_block()
def assign_serviecnow_case_number(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('assign_serviecnow_case_number() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_get_latest_artifact_1:custom_function_result.data.data.number'], action_results=results )
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "servicenow_case_number",
        ],
    ]

    parameters = []

    for item0 in container_property_0:
        for item1 in literal_values_0:
            for item2 in custom_function_result_0:
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
    phantom.custom_function(custom_function='local/set_phantom_custom_field', parameters=parameters, name='assign_serviecnow_case_number', callback=decision_31)

    return

@phantom.playbook_block()
def decision_31(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_31() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["assign_serviecnow_case_number:custom_function_result.data.success", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        set_phantom_case_id_to_servicenow(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
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