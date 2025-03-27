"""
USE CASE: This playbook will perform triage tasks for label events, identify false positive and set timestamp for T0, T1.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'set_status_15' block
    set_status_15(container=container)

    return

"""
Format data to run query
get similar events found
in last 7 days and are
false positive
"""
@phantom.playbook_block()
def format_data_to_run_query_get_similar_eve(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_data_to_run_query_get_similar_eve() called')
    
    template = """index=phantom_container \"custom_fields.False Positive\"=Yes earliest=-7d@d latest=now 
| search \"{0}\"
| dedup id 
| dedup \"custom_fields.Assigned To\"
| rename \"custom_fields.Assigned To\" as assigned_to"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_data_to_run_query_get_similar_eve", separator=", ")

    run_query_get_similar_events_found_in_la(container=container)

    return

@phantom.playbook_block()
def join_format_data_to_run_query_get_similar_eve(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_format_data_to_run_query_get_similar_eve() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_format_data_to_run_query_get_similar_eve_called'):
        return

    # no callbacks to check, call connected block "format_data_to_run_query_get_similar_eve"
    phantom.save_run_data(key='join_format_data_to_run_query_get_similar_eve_called', value='format_data_to_run_query_get_similar_eve', auto=True)

    format_data_to_run_query_get_similar_eve(container=container, handle=handle)
    
    return

"""
Run query
get similar events found
in last 7 days and are
false positive
"""
@phantom.playbook_block()
def run_query_get_similar_events_found_in_la(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_query_get_similar_events_found_in_la() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_query_get_similar_events_found_in_la' call
    formatted_data_1 = phantom.get_format_data(name='format_data_to_run_query_get_similar_eve')

    parameters = []
    
    # build parameters list for 'run_query_get_similar_events_found_in_la' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=print_query_result_to_notes, name="run_query_get_similar_events_found_in_la")

    return

"""
If similar
events found
in last 7 days
and are false
positive
"""
@phantom.playbook_block()
def if_similar_events_found_in_last_7_days_a(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('if_similar_events_found_in_last_7_days_a() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["run_query_get_similar_events_found_in_la:action_result.summary.total_events", ">=", 2],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Set_custom_fields_False_Positive_True(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    false_positive_checked_but_not_matched(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Set custom fields
-False Positive = True
-Closure Type = auto
"""
@phantom.playbook_block()
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
    
    update_data = {"custom_fields": {"False Positive": "Yes", "Closure Type": "auto" , "Assigned To" : "Playbook" }}
    success, message = phantom.update(container, update_data)
    set_status_to_close(container=container)

    ################################################################################
    ## Custom Code End
    ################################################################################
    set_status_to_close(container=container)

    return

@phantom.playbook_block()
def set_status_to_close(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_to_close() called')

    phantom.set_status(container=container, status="Closed")

    note_title = "Notes from Triage playbook - Checked and matched"
    note_content = "False Positive checked and matched on this event"
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

"""
Adding Timestamp of T0, T1
"""
@phantom.playbook_block()
def cf_local_add_t0_t1_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_add_t0_t1_1() called')
    
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

    # call custom function "local/add_t0_t1", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/add_t0_t1', parameters=parameters, name='cf_local_add_t0_t1_1', callback=filter_for_selecting_severity)

    return

@phantom.playbook_block()
def false_positive_checked_but_not_matched(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('false_positive_checked_but_not_matched() called')

    note_title = "Notes from Triage playbook - Checked but not matched"
    note_content = "False Positive checked but not matched on this event"
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

"""
Filtering for selecting severity
"""
@phantom.playbook_block()
def filter_for_selecting_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_for_selecting_severity() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.severity", "==", "critical"],
        ],
        name="filter_for_selecting_severity:condition_1")

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
        name="filter_for_selecting_severity:condition_2")

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
        name="filter_for_selecting_severity:condition_3")

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
        name="filter_for_selecting_severity:condition_4")

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
        name="filter_for_selecting_severity:condition_5")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_5 or matched_results_5:
        pass

    return

"""
Set severity to Medium
"""
@phantom.playbook_block()
def set_severity_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_8() called')

    phantom.set_severity(container=container, severity="Medium")
    join_format_data_to_run_query_get_similar_eve(container=container)

    return

"""
Set severity to Low
"""
@phantom.playbook_block()
def set_severity_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_9() called')

    phantom.set_severity(container=container, severity="Low")
    join_format_data_to_run_query_get_similar_eve(container=container)

    return

@phantom.playbook_block()
def set_severity_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_10() called')

    phantom.set_severity(container=container, severity="Critical")
    join_format_data_to_run_query_get_similar_eve(container=container)

    return

@phantom.playbook_block()
def set_severity_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_11() called')

    phantom.set_severity(container=container, severity="High")
    join_format_data_to_run_query_get_similar_eve(container=container)

    return

@phantom.playbook_block()
def print_query_result_to_notes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('print_query_result_to_notes() called')
    
    template = """{0} case closed in last 7 days with False Positive by

%%
event id: {2}
analyst name: {1}

%%"""

    # parameter list for template variable replacement
    parameters = [
        "run_query_get_similar_events_found_in_la:action_result.summary.total_events",
        "run_query_get_similar_events_found_in_la:action_result.data.*.assigned_to",
        "run_query_get_similar_events_found_in_la:action_result.data.*.id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="print_query_result_to_notes", separator=", ")

    add_query_result_to_notes(container=container)

    return

@phantom.playbook_block()
def add_query_result_to_notes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_query_result_to_notes() called')

    formatted_data_1 = phantom.get_format_data(name='print_query_result_to_notes')

    note_title = "Adding  query result to event"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    if_similar_events_found_in_last_7_days_a(container=container)

    return

@phantom.playbook_block()
def set_status_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_15() called')

    phantom.set_status(container=container, status="Open")
    cf_local_add_t0_t1_1(container=container)

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