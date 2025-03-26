"""
USE CASE: This playbook will perform triage tasks, identify false positive; else perform enrichment,
containment and notification
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Filter_for_selecting_severity' block
    Filter_for_selecting_severity(container=container)

    return

"""
Check for hostname in artifact
"""
def Check_for_hostname_in_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_for_hostname_in_artifact() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            [1, "==", 1],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Format_data_to_run_query_get_number_and(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def join_Check_for_hostname_in_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_Check_for_hostname_in_artifact() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_Check_for_hostname_in_artifact_called'):
        return

    # no callbacks to check, call connected block "Check_for_hostname_in_artifact"
    phantom.save_run_data(key='join_Check_for_hostname_in_artifact_called', value='Check_for_hostname_in_artifact', auto=True)

    Check_for_hostname_in_artifact(container=container, handle=handle)
    
    return

"""
Format data to run query
get number and type of
notable events related to
hostname
"""
def Format_data_to_run_query_get_number_and(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_data_to_run_query_get_number_and() called')
    
    template = """{1}  {0} earliest=-48h@h  latest=now `notable`"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
        "artifact:*.cef.destinationHostName",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_data_to_run_query_get_number_and", separator=", ")

    Run_query_get_number_and_type_of_notable(container=container)

    return

"""
Run query
get number and type of
notable events related to
hostname
"""
def Run_query_get_number_and_type_of_notable(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Run_query_get_number_and_type_of_notable() called')

    # collect data for 'Run_query_get_number_and_type_of_notable' call
    formatted_data_1 = phantom.get_format_data(name='Format_data_to_run_query_get_number_and')

    parameters = []
    
    # build parameters list for 'Run_query_get_number_and_type_of_notable' call
    parameters.append({
        'ph': "",
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'end_time': "",
        'parse_only': "",
        'start_time': "",
        'search_mode': "",
        'attach_result': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=Add_note_for_run_query_results, name="Run_query_get_number_and_type_of_notable")

    return

"""
Add note for run query results
"""
def Add_note_for_run_query_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_for_run_query_results() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['Run_query_get_number_and_type_of_notable:action_result.summary.total_events'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    note_title = "Number of notables related to deviceHostname/source IP"
    note_content = results_item_1_0
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    ################################################################################
    ## Custom Code End
    ################################################################################
    Format_data_to_run_query_get_similar_eve(container=container)

    return

"""
Format data to run query
get similar events found
in last 7 days and are
false positive
"""
def Format_data_to_run_query_get_similar_eve(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_data_to_run_query_get_similar_eve() called')
    
    template = """index=phantom_container  earliest=-7d@d latest=now 
| eval ctime = strptime(container_update_time,\"%FT%T.%6QZ\")
| sort 0 - ctime
| dedup id
| search \"custom_fields.False Positive\"=Yes
| search name = \"{0}\"
| dedup id 
| dedup \"custom_fields.Assigned To\"
| rename \"custom_fields.Assigned To\" as assigned_to
| search assigned_to != \"Playbook\""""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_data_to_run_query_get_similar_eve", separator=", ")

    Run_query_get_similar_events_found_in_la(container=container)

    return

"""
Run query
get similar events found
in last 7 days and are
false positive
"""
def Run_query_get_similar_events_found_in_la(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Run_query_get_similar_events_found_in_la() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Run_query_get_similar_events_found_in_la' call
    formatted_data_1 = phantom.get_format_data(name='Format_data_to_run_query_get_similar_eve')

    parameters = []
    
    # build parameters list for 'Run_query_get_similar_events_found_in_la' call
    parameters.append({
        'ph': "",
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'end_time': "",
        'parse_only': "",
        'start_time': "",
        'search_mode': "",
        'attach_result': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=If_similar_events_found_in_last_7_days_a, name="Run_query_get_similar_events_found_in_la")

    return

"""
If similar
events found
in last 7 days
and are false
positive
"""
def If_similar_events_found_in_last_7_days_a(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('If_similar_events_found_in_last_7_days_a() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Run_query_get_similar_events_found_in_la:action_result.summary.total_events", ">=", 2],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        add_note_12(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        cf_local_Set_last_automated_action_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2

    return

"""
Set custom fields
-False Positive = True
-Closure Type = auto
"""
def Set_custom_fields_False_Positive_True(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Set_custom_fields_False_Positive_True() called')
    
    id_value = container.get('id', None)

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    {"custom_fields": {
        "False Positive": "Yes"
    }}
    
    update_data = {"custom_fields": {"False Positive": "Yes", "Closure Type": "auto", "Assigned To" : "Playbook"}}
    success, message = phantom.update(container, update_data)

    ################################################################################
    ## Custom Code End
    ################################################################################
    Set_status_to_close(container=container)

    return

def Set_status_to_close(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Set_status_to_close() called')

    phantom.set_status(container=container, status="Closed")

    container = phantom.get_container(container.get('id', None))

    return

def Filter_for_selecting_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_for_selecting_severity() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.severity", "==", "critical"],
        ],
        name="Filter_for_selecting_severity:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        set_severity_10(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.severity", "==", "high"],
        ],
        name="Filter_for_selecting_severity:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        set_severity_11(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.severity", "==", "medium"],
        ],
        name="Filter_for_selecting_severity:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        set_severity_8(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    # collect filtered artifact ids for 'if' condition 4
    matched_artifacts_4, matched_results_4 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.severity", "==", "low"],
        ],
        name="Filter_for_selecting_severity:condition_4")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_4 or matched_results_4:
        set_severity_9(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_4, filtered_results=matched_results_4)

    # collect filtered artifact ids for 'if' condition 5
    matched_artifacts_5, matched_results_5 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.severity", "==", ""],
        ],
        name="Filter_for_selecting_severity:condition_5")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_5 or matched_results_5:
        join_Check_for_hostname_in_artifact(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_5, filtered_results=matched_results_5)

    return

def set_severity_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_8() called')

    phantom.set_severity(container=container, severity="Medium")

    container = phantom.get_container(container.get('id', None))
    join_Check_for_hostname_in_artifact(container=container)

    return

def set_severity_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_9() called')

    phantom.set_severity(container=container, severity="Low")

    container = phantom.get_container(container.get('id', None))
    join_Check_for_hostname_in_artifact(container=container)

    return

def set_severity_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_10() called')

    phantom.set_severity(container=container, severity="Critical")

    container = phantom.get_container(container.get('id', None))
    join_Check_for_hostname_in_artifact(container=container)

    return

def set_severity_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_11() called')

    phantom.set_severity(container=container, severity="High")

    container = phantom.get_container(container.get('id', None))
    join_Check_for_hostname_in_artifact(container=container)

    return

def add_note_12(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_12() called')

    note_title = "Set false positive"
    note_content = "Set false positive"
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    container = phantom.get_container(container.get('id', None))

    return

def cf_local_Set_last_automated_action_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_Set_last_automated_action_4() called')
    
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
    phantom.custom_function(custom_function='local/Set_last_automated_action', parameters=parameters, name='cf_local_Set_last_automated_action_4', callback=Set_custom_fields_False_Positive_True)

    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.deviceHostname", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        return

    # call connected blocks for 'else' condition 2
    format_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def format_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_3() called')
    
    template = """{0} earliest=-48h@h  latest=now `notable`"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_3", separator=", ")

    Get_related_event_to_IP(container=container)

    return

def Get_related_event_to_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Get_related_event_to_IP() called')

    # collect data for 'Get_related_event_to_IP' call
    formatted_data_1 = phantom.get_format_data(name='format_3')

    parameters = []
    
    # build parameters list for 'Get_related_event_to_IP' call
    parameters.append({
        'ph': "",
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'end_time': "",
        'parse_only': "",
        'start_time': "",
        'search_mode': "",
        'attach_result': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=custom_function_3, name="Get_related_event_to_IP")

    return

def custom_function_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('custom_function_3() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['Get_related_event_to_IP:action_result.summary.total_events'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    note_title = "Number of notables related to source IP"
    note_content = results_item_1_0
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

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