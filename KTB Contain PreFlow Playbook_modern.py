"""
USE CASE: This playbook is used to contain the threat
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

import ipaddress

# End - Global Code block
##############################

@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_out_devicehostname' block
    filter_out_devicehostname(container=container)

    return

"""
Filter out destinationHostName
"""
@phantom.playbook_block()
def filter_out_devicehostname(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_out_devicehostname() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.deviceHostname", "!=", ""],
            ["device_quarantined", "not in", "artifact:*.tags"],
            ["indicator_malicious", "in", "artifact:*.tags"],
        ],
        logical_operator='and',
        name="filter_out_devicehostname:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_endpoint_number_by_hostname_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def get_endpoint_number_by_hostname_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_endpoint_number_by_hostname_1() called')

    # collect data for 'get_endpoint_number_by_hostname_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.deviceHostname', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_endpoint_number_by_hostname_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hostName': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="get_endpoint_number_by_hostname", parameters=parameters, assets=['amp-cx'], callback=filter_6, name="get_endpoint_number_by_hostname_1")

    return

@phantom.playbook_block()
def filter_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_6() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_endpoint_number_by_hostname_1:action_result.summary.total_number_1", "==", 0],
        ],
        name="filter_6:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_7(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_endpoint_number_by_hostname_1:action_result.summary.total_number_1", "==", 1],
        ],
        name="filter_6:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        get_endpoint_isolation_status_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_endpoint_number_by_hostname_1:action_result.summary.total_number_1", ">", 1],
        ],
        name="filter_6:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        add_note_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    return

@phantom.playbook_block()
def add_note_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_4() called')

    results_data_1 = phantom.collect2(container=container, datapath=['get_endpoint_number_by_hostname_1:action_result.message'], action_results=results)

    results_item_1_0 = [item[0] for item in results_data_1]

    note_title = "Messges from query result "
    note_content = results_item_1_0
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

@phantom.playbook_block()
def filter_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_7() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["mcafee", "in", "artifact:*.cef.sourcetype"],
        ],
        name="filter_7:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_mac_address(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["kas", "in", "artifact:*.cef.sourcetype"],
        ],
        name="filter_7:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        add_note_9(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

"""
Get Mac_adddress
"""
@phantom.playbook_block()
def get_mac_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_mac_address() called')
    
    template = """index=ktb_mgmt_default sourcetype=mcafee* dest={0}
| dedup dest
| eval new1=substr(dest_mac,1,2) ,new2=substr(dest_mac,3,2) ,new3=substr(dest_mac,5,2) ,new4=substr(dest_mac,7,2), new5=substr(dest_mac,9,2) ,new6=substr(dest_mac,11,2)
| eval Calling_Station_ID=new1+\"-\"+new2+\"-\"+new3+\"-\"+new4+\"-\"+new5+\"-\"+new6
| table Calling_Station_ID"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.deviceHostname",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="get_mac_address", separator=", ")

    get_mac_by_splunk_earch(container=container)

    return

@phantom.playbook_block()
def get_mac_by_splunk_earch(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_mac_by_splunk_earch() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_mac_by_splunk_earch' call
    formatted_data_1 = phantom.get_format_data(name='get_mac_address')

    parameters = []
    
    # build parameters list for 'get_mac_by_splunk_earch' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=filter_8, name="get_mac_by_splunk_earch")

    return

@phantom.playbook_block()
def filter_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_8() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_mac_by_splunk_earch:action_result.summary.total_events", "==", 1],
        ],
        name="filter_8:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        custom_function_14(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_mac_by_splunk_earch:action_result.summary.total_events", "!=", 1],
        ],
        name="filter_8:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        add_note_10(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

@phantom.playbook_block()
def add_note_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_8() called')

    note_title = "Containment Failure Note"
    note_content = "Auto Containment is failure,  please proceed with manuall containment"
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

@phantom.playbook_block()
def join_add_note_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_add_note_8() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_add_note_8_called'):
        return

    # no callbacks to check, call connected block "add_note_8"
    phantom.save_run_data(key='join_add_note_8_called', value='add_note_8', auto=True)

    add_note_8(container=container, handle=handle)
    
    return

@phantom.playbook_block()
def add_note_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_9() called')

    note_title = "Kaspersky Containment note"
    note_content = "Kspersky client cotainment not available now."
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    join_add_note_8(container=container)

    return

@phantom.playbook_block()
def add_note_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_10() called')

    note_title = "Mcafee Containment notes"
    note_content = "Failure to Get MAC address of Mcafee client"
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    join_add_note_8(container=container)

    return

@phantom.playbook_block()
def add_tag_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_tag_11() called')

    phantom.add_tags(container=container, tags="amp_contain")

    return

@phantom.playbook_block()
def add_tag_12(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_tag_12() called')

    phantom.add_tags(container=container, tags="ise_contain")

    return

@phantom.playbook_block()
def custom_function_14(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('custom_function_14() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.id'])
    results_data_1 = phantom.collect2(container=container, datapath=['get_mac_by_splunk_earch:action_result.data.*.Calling_Station_ID'], action_results=results)
    container_item_0 = [item[0] for item in container_data]
    results_item_1_0 = [item[0] for item in results_data_1]

    custom_function_14__new_format = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    parameters = []

    cef_json = {"host_mac" : results_item_1_0[0]}
    newformat = results_item_1_0[0]

        # build parameters list for 'update_artifact_2' call
    parameters.append({
            'artifact_id': container_item_0[0],
            'name': "",
            'label': "",
            'severity': "",
            'cef_json': cef_json,
            'cef_types_json': "",
            'tags': "",
            'overwrite': "",
            'artifact_json': "",
        })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_host_mac")
    custom_function_14__new_format = newformat.replace("-",":")

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='custom_function_14:new_format', value=json.dumps(custom_function_14__new_format))
    cf_community_string_to_uppercase_1(container=container)

    return

@phantom.playbook_block()
def decision_19(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_19() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_endpoint_isolation_status_1:action_result.message", "==", "isolated"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        add_note_13(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_endpoint_isolation_status_1:action_result.message", "==", "not_isolated"],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        add_tag_11(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 3
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_endpoint_isolation_status_1:action_result.status", "==", "failed"],
        ])

    # call connected blocks if condition 3 matched
    if matched:
        add_note_15(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def add_note_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_13() called')

    note_title = "Device Quarantined "
    note_content = "The device has been  quarantined"
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

@phantom.playbook_block()
def check_if_macaddress_quarantined_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_if_macaddress_quarantined_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'check_if_macaddress_quarantined_1' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_community_string_to_uppercase_1:custom_function_result.data.uppercase_string'], action_results=results)

    parameters = []
    
    # build parameters list for 'check_if_macaddress_quarantined_1' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'macaddress': custom_function_results_item_1[0],
                'policyname': "TEST-Q",
            })

    phantom.act(action="check_if_macaddress_quarantined", parameters=parameters, assets=['new-ise-test'], callback=decision_20, name="check_if_macaddress_quarantined_1")

    return

@phantom.playbook_block()
def decision_20(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_20() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["check_if_macaddress_quarantined_1:action_result.message", "==", False],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        add_tag_12(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["check_if_macaddress_quarantined_1:action_result.message", "==", True],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        add_note_14(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def add_note_14(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_14() called')

    note_title = "Quarantined Noted"
    note_content = "The MAC address hs been quarantind before"
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

@phantom.playbook_block()
def cf_community_string_to_uppercase_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_string_to_uppercase_1() called')
    
    legacy_custom_function_result_0 = [
        [
            json.loads(phantom.get_run_data(key="custom_function_14:new_format")),
        ],
    ]

    parameters = []

    for item0 in legacy_custom_function_result_0:
        parameters.append({
            'input_string': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/string_to_uppercase", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/string_to_uppercase', parameters=parameters, name='cf_community_string_to_uppercase_1', callback=check_if_macaddress_quarantined_1)

    return

@phantom.playbook_block()
def get_endpoint_isolation_status_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_endpoint_isolation_status_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_endpoint_isolation_status_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.deviceHostname', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_endpoint_isolation_status_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hostName': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="get_endpoint_isolation_status", parameters=parameters, assets=['amp-cx'], callback=decision_19, name="get_endpoint_isolation_status_1")

    return

@phantom.playbook_block()
def add_note_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_15() called')

    results_data_1 = phantom.collect2(container=container, datapath=['get_endpoint_isolation_status_1:action_result.message'], action_results=results)

    results_item_1_0 = [item[0] for item in results_data_1]

    note_title = "Failed to Get Endpoint Isolation Status"
    note_content = results_item_1_0
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

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