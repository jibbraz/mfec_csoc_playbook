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
| search name=\"{0}\"
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
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=Print_Query_Result_to_Notes, name="Run_query_get_similar_events_found_in_la")

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
            ["check_event_name:custom_function:Notable_contain_unknown", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        False_positive_not_checked(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Run_query_get_similar_events_found_in_la:action_result.summary.total_events", ">=", 2],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        Set_custom_fields_False_Positive_True(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 3
    False_Positive_checked_but_not_matched(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def join_If_similar_events_found_in_last_7_days_a(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_If_similar_events_found_in_last_7_days_a() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_If_similar_events_found_in_last_7_days_a_called'):
        return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['Run_query_get_similar_events_found_in_la']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_If_similar_events_found_in_last_7_days_a_called', value='If_similar_events_found_in_last_7_days_a')
        
        # call connected block "If_similar_events_found_in_last_7_days_a"
        If_similar_events_found_in_last_7_days_a(container=container, handle=handle)
    
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

    update_data = {"custom_fields": {"False Positive": "Yes", "Closure Type": "auto", "Assigned To": "Playbook"}}
    success, message = phantom.update(container, update_data)

    ################################################################################
    ## Custom Code End
    ################################################################################
    cf_local_Set_status_to_closed_1(container=container)

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
    phantom.custom_function(custom_function='local/ADD_T0_T1', parameters=parameters, name='cf_local_ADD_T0_T1_1', callback=Filter_for_selecting_severity)

    return

def False_Positive_checked_but_not_matched(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('False_Positive_checked_but_not_matched() called')

    note_title = "Notes from Triage playbook - Checked but not matched"
    note_content = "False Positive checked but not matched on this event"
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    phantom.set_status(container=container, status="Open")
    cf_local_Set_last_automated_action_1(container=container)

    return

"""
Filtering for selecting severity
"""
def Filter_for_selecting_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_for_selecting_severity() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
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
        action_results=results,
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
        action_results=results,
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
        action_results=results,
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
        action_results=results,
        conditions=[
            ["artifact:*.cef.severity", "==", ""],
        ],
        name="Filter_for_selecting_severity:condition_5")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_5 or matched_results_5:
        pass

    return

"""
Set severity to Medium
"""
def set_severity_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_8() called')

    phantom.set_severity(container=container, severity="Medium")
    join_Filter_out_search_name(container=container)

    return

"""
Set severity to Low
"""
def set_severity_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_9() called')

    phantom.set_severity(container=container, severity="Low")
    join_Filter_out_search_name(container=container)

    return

def set_severity_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_10() called')

    phantom.set_severity(container=container, severity="Critical")
    join_Filter_out_search_name(container=container)

    return

def set_severity_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_11() called')

    phantom.set_severity(container=container, severity="High")
    join_Filter_out_search_name(container=container)

    return

def Filter_out_search_name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_out_search_name() called')
    
    name_param = container.get('name', None)

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.search_name", "in", "custom_list:triage-search-name"],
            [name_param, "!=", ""],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        check_event_name(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        Format_data_to_run_query_get_similar_eve(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    Note_from_Triage_playbook_Not_checked(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def join_Filter_out_search_name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_Filter_out_search_name() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(custom_function_names=['cf_local_ADD_T0_T1_1']):
        
        # call connected block "Filter_out_search_name"
        Filter_out_search_name(container=container, handle=handle)
    
    return

def Note_from_Triage_playbook_Not_checked(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Note_from_Triage_playbook_Not_checked() called')

    note_title = "Notes from Triage playbook - Not checked due to search name not in custom list"
    note_content = "False Positive not checked on this event due to search name not in custom list"
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def Print_Query_Result_to_Notes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Print_Query_Result_to_Notes() called')
    
    template = """{0} case closed in last 7 days with False Positive by

%%
event id: {2}
analyst name: {1}

%%"""

    # parameter list for template variable replacement
    parameters = [
        "Run_query_get_similar_events_found_in_la:action_result.summary.total_events",
        "Run_query_get_similar_events_found_in_la:action_result.data.*.assigned_to",
        "Run_query_get_similar_events_found_in_la:action_result.data.*.id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Print_Query_Result_to_Notes", separator=", ")

    Note_from_Triage_playbook_Matched_even(container=container)

    return

"""
{case} case closed in last 7 days with False Positive by

%%
event id: {event id}
analyst name: {analyst name}

%%
"""
def Note_from_Triage_playbook_Matched_even(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Note_from_Triage_playbook_Matched_even() called')

    formatted_data_1 = phantom.get_format_data(name='Print_Query_Result_to_Notes')

    note_title = "Note from Triage playbook - Matched event id  closed as false positive"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    join_If_similar_events_found_in_last_7_days_a(container=container)

    return

def False_positive_not_checked(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('False_positive_not_checked() called')

    note_title = "Notes from Triage playbook - Not check"
    note_content = "Event title contains \"unknown\" or \"?\". False positive not check."
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    phantom.set_status(container=container, status="Open")
    cf_local_Set_last_automated_action_2(container=container)

    return

"""
check event name contains "[]" or "unknown" or "?". If yes, not check false positive.
"""
def check_event_name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_event_name() called')
    
    name_value = container.get('name', None)

    check_event_name__Notable_contain_unknown = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug(name_value.find("unknown"))
    phantom.debug(name_value.find("?"))
    if name_value.find("unknown") == -1 and name_value.find("?") == -1 and name_value.find("[]") == -1 and name_value.find("()") == -1:
        check_event_name__Notable_contain_unknown = False
    else:
        check_event_name__Notable_contain_unknown = True

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='check_event_name:Notable_contain_unknown', value=json.dumps(check_event_name__Notable_contain_unknown))
    join_If_similar_events_found_in_last_7_days_a(container=container)

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
            "Triaged",
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
    phantom.custom_function(custom_function='local/Set_last_automated_action', parameters=parameters, name='cf_local_Set_last_automated_action_1')

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
            "Triaged",
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
    phantom.custom_function(custom_function='local/Set_last_automated_action', parameters=parameters, name='cf_local_Set_last_automated_action_2')

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

def cf_local_Set_status_to_closed_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_Set_status_to_closed_1() called')
    
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

    # call custom function "local/Set_status_to_closed", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/Set_status_to_closed', parameters=parameters, name='cf_local_Set_status_to_closed_1', callback=cf_local_Set_last_automated_action_3)

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