"""
USE CASE: This playbook is used to contain the threat on External IP address in regular time set by Timer App
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

IP_CONTAIN_GLOBAL_RESULTS = []

# End - Global Code block
##############################

@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'clear_global_variable' block
    clear_global_variable(container=container)

    return

"""
Get the top IP address from the list
"""
@phantom.playbook_block()
def get_the_top_ip_address_from_the_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_the_top_ip_address_from_the_list() called')
    
    input_parameter_0 = ""

    get_the_top_ip_address_from_the_list__top_ip_address = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    import ipaddress
    success, message, iplist = phantom.get_list(list_name='PaloAlto - Dest IP to contain')
    for ip in iplist:
        try:
            ipaddress.ip_address(ip[0])
            phantom.debug(f"Top IP: {ip[0]}")
            get_the_top_ip_address_from_the_list__top_ip_address = ip[0]
            break
        except:
            continue

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='get_the_top_ip_address_from_the_list:top_ip_address', value=json.dumps(get_the_top_ip_address_from_the_list__top_ip_address))
    decision_1(container=container)

    return

@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_the_top_ip_address_from_the_list:custom_function:top_ip_address", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        block_ip_6(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    add_note_for_no_ip_address_to_contain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Add Note for No IP address to contain
"""
@phantom.playbook_block()
def add_note_for_no_ip_address_to_contain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_for_no_ip_address_to_contain() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_note_for_no_ip_address_to_contain' call

    parameters = []
    
    # build parameters list for 'add_note_for_no_ip_address_to_contain' call
    parameters.append({
        'title': "Destination Address: No IP address to contain",
        'content': "There is no IP address to contain from the custom list.",
        'phase_id': "",
        'container_id': "",
    })

    phantom.act(action="add note", parameters=parameters, assets=['phantom asset'], callback=set_severity_set_status_3, name="add_note_for_no_ip_address_to_contain")

    return

"""
Remove the top IP address from the list
"""
@phantom.playbook_block()
def remove_the_top_ip_address_from_the_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('remove_the_top_ip_address_from_the_list() called')
    
    get_the_top_ip_address_from_the_list__top_ip_address = json.loads(phantom.get_run_data(key='get_the_top_ip_address_from_the_list:top_ip_address'))

    remove_the_top_ip_address_from_the_list__ip_count = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    import ipaddress
    remove_the_top_ip_address_from_the_list__ip_count = 0
    
    phantom.debug(f"Popping out IP: {get_the_top_ip_address_from_the_list__top_ip_address}")
    phantom.delete_from_list(list_name="PaloAlto - Dest IP to contain", value=get_the_top_ip_address_from_the_list__top_ip_address, column=None, remove_all=False, remove_row=False)
    success, message, iplist = phantom.get_list(list_name='PaloAlto - Dest IP to contain')
    for ip in iplist:
        try:
            ipaddress.ip_address(ip[0])
            remove_the_top_ip_address_from_the_list__ip_count += 1
        except:
            continue

    phantom.debug(f"Current number of IP address remaining in the list: {remove_the_top_ip_address_from_the_list__ip_count}")

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='remove_the_top_ip_address_from_the_list:ip_count', value=json.dumps(remove_the_top_ip_address_from_the_list__ip_count))
    decision_7(container=container)

    return

@phantom.playbook_block()
def decision_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_7() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["remove_the_top_ip_address_from_the_list:custom_function:ip_count", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        join_decision_8(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    check_the_result(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

@phantom.playbook_block()
def decision_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_8() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            [1, "==", 1],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        get_the_top_ip_address_from_the_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def join_decision_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_decision_8() called')
    
    # if the joined function has already been called, do nothing
    #if phantom.get_run_data(key='join_decision_8_called'):
    #    return

    # no callbacks to check, call connected block "decision_8"
    phantom.save_run_data(key='join_decision_8_called', value='decision_8', auto=True)

    decision_8(container=container, handle=handle)
    
    return

"""
Check the result
"""
@phantom.playbook_block()
def check_the_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_the_result() called')
    
    collect_all_ip_address__all_IP_address_list = json.loads(phantom.get_run_data(key='collect_all_ip_address:all_IP_address_list'))

    check_the_result__results = None
    check_the_result__summary_result = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    global IP_CONTAIN_GLOBAL_RESULTS
    check_the_result__summary_result = "success"
    # Write your custom code here...
    for row in IP_CONTAIN_GLOBAL_RESULTS:
        if row['status'] != "success":
            check_the_result__summary_result = "failed"
    
    phantom.debug(IP_CONTAIN_GLOBAL_RESULTS)
    phantom.debug(check_the_result__summary_result)
    check_the_result__results = IP_CONTAIN_GLOBAL_RESULTS

    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ###############################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='check_the_result:results', value=json.dumps(check_the_result__results))
    phantom.save_run_data(key='check_the_result:summary_result', value=json.dumps(check_the_result__summary_result))
    add_note_for_the_result(container=container)

    return

"""
Add Note for the result
"""
@phantom.playbook_block()
def add_note_for_the_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_for_the_result() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    check_the_result__results = json.loads(phantom.get_run_data(key='check_the_result:results'))
    # collect data for 'add_note_for_the_result' call

    parameters = []
    
    # build parameters list for 'add_note_for_the_result' call
    content = f"| IP Address 	| Status  	|\n"
    content += f"|------------	|---------	|\n"
    for result in check_the_result__results:
        content += f"| {result['ip']}    	| {result['status']} 	|\n"
    content += "---\n"
    
    parameters.append({
        'title': "Destination Address: Result Summary",
        'content': content,
        'container_id': "",
        'phase_id': "",
    })

    phantom.act(action="add note", parameters=parameters, assets=['phantom asset'], callback=decision_9, name="add_note_for_the_result")

    return

@phantom.playbook_block()
def decision_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_9() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["check_the_result:custom_function:summary_result", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        set_severity_set_status_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    set_severity_set_status_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

@phantom.playbook_block()
def set_severity_set_status_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_set_status_1() called')

    phantom.set_severity(container=container, severity="Low")

    phantom.set_status(container=container, status="Closed")

    container = phantom.get_container(container.get('id', None))
    join_cf_local_set_custom_field_incident_type_1(container=container)

    return

@phantom.playbook_block()
def set_severity_set_status_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_set_status_2() called')

    phantom.set_severity(container=container, severity="Low")

    phantom.set_status(container=container, status="Open")

    container = phantom.get_container(container.get('id', None))
    join_cf_local_set_custom_field_incident_type_1(container=container)

    return

@phantom.playbook_block()
def set_severity_set_status_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_set_status_3() called')

    phantom.set_severity(container=container, severity="Low")

    phantom.set_status(container=container, status="Closed")

    container = phantom.get_container(container.get('id', None))
    join_cf_local_set_custom_field_incident_type_1(container=container)

    return

@phantom.playbook_block()
def cf_local_set_custom_field_incident_type_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_set_custom_field_incident_type_1() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "Operation",
        ],
    ]

    parameters = []

    container_property_0_0 = [item[0] for item in container_property_0]
    literal_values_0_0 = [item[0] for item in literal_values_0]

    parameters.append({
        'Container_id': container_property_0_0,
        'incident_type': literal_values_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/set_custom_field_incident_type", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_custom_field_incident_type', parameters=parameters, name='cf_local_set_custom_field_incident_type_1')

    return

@phantom.playbook_block()
def join_cf_local_set_custom_field_incident_type_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_cf_local_set_custom_field_incident_type_1() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_cf_local_set_custom_field_incident_type_1_called'):
        return

    # no callbacks to check, call connected block "cf_local_set_custom_field_incident_type_1"
    phantom.save_run_data(key='join_cf_local_set_custom_field_incident_type_1_called', value='cf_local_set_custom_field_incident_type_1', auto=True)

    cf_local_set_custom_field_incident_type_1(container=container, handle=handle)
    
    return

"""
Collect all IP address
"""
@phantom.playbook_block()
def collect_all_ip_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('collect_all_ip_address() called')
    
    input_parameter_0 = ""

    collect_all_ip_address__all_IP_address_list = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    collect_all_ip_address__all_IP_address_list = []
    import ipaddress
    success, message, iplist = phantom.get_list(list_name='PaloAlto - Dest IP to contain')
    for ip in iplist:
        try:
            ipaddress.ip_address(ip[0])
            collect_all_ip_address__all_IP_address_list.append(ip[0])
        except:
            continue

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='collect_all_ip_address:all_IP_address_list', value=json.dumps(collect_all_ip_address__all_IP_address_list))
    join_decision_8(container=container)

    return

"""
Save the result to global var
"""
@phantom.playbook_block()
def save_the_result_to_global_var(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('save_the_result_to_global_var() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['block_ip_6:action_result.parameter.ip', 'block_ip_6:action_result.status'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_1_1 = [item[1] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    global IP_CONTAIN_GLOBAL_RESULTS
    
    phantom.debug(IP_CONTAIN_GLOBAL_RESULTS)
    phantom.debug("------------------")
    phantom.debug(results_item_1_0)
    phantom.debug(results_item_1_1)
    phantom.debug("------------------")
    
    result_summary = "success"

    for result_per_asset in results_item_1_1:
        if result_per_asset != "success":
            result_summary = "failed"
                
    IP_CONTAIN_GLOBAL_RESULTS.append({'ip': results_item_1_0[0], 'status': result_summary})

    ################################################################################
    ## Custom Code End
    ################################################################################
    sleep(container=container)

    return

"""
sleep
"""
@phantom.playbook_block()
def sleep(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('sleep() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'sleep' call

    parameters = []
    
    # build parameters list for 'sleep' call
    parameters.append({
        'sleep_seconds': 120,
    })

    phantom.act(action="no op", parameters=parameters, assets=['phantom asset'], callback=remove_the_top_ip_address_from_the_list, name="sleep")

    return

"""
Clear Global Variable
"""
@phantom.playbook_block()
def clear_global_variable(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('clear_global_variable() called')
    
    input_parameter_0 = ""

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    global IP_CONTAIN_GLOBAL_RESULTS 
    IP_CONTAIN_GLOBAL_RESULTS = []

    ################################################################################
    ## Custom Code End
    ################################################################################
    collect_all_ip_address(container=container)

    return

"""
Palo Alto Block Dest IP
"""
@phantom.playbook_block()
def block_ip_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_ip_6() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    phantom.act(action="block ip", parameters=parameters, callback=save_the_result_to_global_var, name="block_ip_6")

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