"""
USE CASE: This playbook is used to contain the threat on External IP address in regular time set by Timer App
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

CONTAIN_FAILED = False

# End - Global Code block
##############################

@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'collect_all_ip_address' block
    collect_all_ip_address(container=container)

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
    success, message, iplist = phantom.get_list(list_name='Fortimanager - Src IP to contain')
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
        prepare_src_ip_artifact(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
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
        'title': "Source Address: No IP address to contain",
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
    phantom.delete_from_list(list_name="Fortimanager - Src IP to contain", value=get_the_top_ip_address_from_the_list__top_ip_address, column=None, remove_all=False, remove_row=False)
    success, message, iplist = phantom.get_list(list_name='Fortimanager - Src IP to contain')
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
    get_containment_status(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

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

@phantom.playbook_block()
def set_severity_set_status_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_set_status_1() called')

    phantom.set_severity(container=container, severity="Low")

    phantom.set_status(container=container, status="Closed")
    join_cf_local_set_custom_field_incident_type_1(container=container)

    return

@phantom.playbook_block()
def set_severity_set_status_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_set_status_3() called')

    phantom.set_severity(container=container, severity="Low")

    phantom.set_status(container=container, status="Closed")
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

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['sleep']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_cf_local_set_custom_field_incident_type_1_called', value='cf_local_set_custom_field_incident_type_1')
        
        # call connected block "cf_local_set_custom_field_incident_type_1"
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
    success, message, iplist = phantom.get_list(list_name='Fortimanager - Src IP to contain')
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
Fortimanager Block Src IP
"""
@phantom.playbook_block()
def fortimanager_block_src_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('fortimanager_block_src_ip() called')
    
    get_the_top_ip_address_from_the_list__top_ip_address = json.loads(phantom.get_run_data(key='get_the_top_ip_address_from_the_list:top_ip_address'))
    
    # call playbook "local/PLAYBOOK-CONTAIN-INDICATOR-CONSOLIDATED-FORTIMANAGER-SRCIP-01", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/PLAYBOOK-CONTAIN-INDICATOR-CONSOLIDATED-FORTIMANAGER-SRCIP-01", container=container, name=f"fortimanager_block_src_ip_{get_the_top_ip_address_from_the_list__top_ip_address}", callback=sleep)

    return

"""
Add src IP artifact
"""
@phantom.playbook_block()
def add_src_ip_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_src_ip_artifact() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    get_the_top_ip_address_from_the_list__top_ip_address = json.loads(phantom.get_run_data(key='get_the_top_ip_address_from_the_list:top_ip_address'))
    # collect data for 'add_src_ip_artifact' call
    formatted_data_1 = phantom.get_format_data(name='prepare_src_ip_artifact')

    parameters = []
    
    # build parameters list for 'add_src_ip_artifact' call
    parameters.append({
        'name': "User created artifact",
        'label': "event",
        'cef_name': "",
        'contains': "",
        'cef_value': "",
        'container_id': "",
        'cef_dictionary': formatted_data_1,
        'run_automation': False,
        'source_data_identifier': get_the_top_ip_address_from_the_list__top_ip_address,
    })

    phantom.act(action="add artifact", parameters=parameters, assets=['phantom asset'], callback=fortimanager_block_src_ip, name="add_src_ip_artifact")

    return

"""
Prepare src IP artifact
"""
@phantom.playbook_block()
def prepare_src_ip_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prepare_src_ip_artifact() called')
    
    template = """{{\"sourceAddress\": \"{0}\", \"sourceAddress_malicious\": \"True\"}}"""

    # parameter list for template variable replacement
    parameters = [
        "get_the_top_ip_address_from_the_list:custom_function:top_ip_address",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="prepare_src_ip_artifact", separator=", ")

    add_src_ip_artifact(container=container)

    return

"""
Delete the created artifact
"""
@phantom.playbook_block()
def delete_the_created_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('delete_the_created_artifact() called')
    
    input_parameter_0 = ""

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    artifacts = phantom.collect(container, 'artifacts:*', scope='all')
    # phantom.debug(artifacts)
    for artifact in artifacts:
        result = phantom.delete_artifact(artifact_id=artifact["id"])
        phantom.debug('phantom.delete_artifact results: {} '.format(result))

    ################################################################################
    ## Custom Code End
    ################################################################################
    remove_the_top_ip_address_from_the_list(container=container)

    return

@phantom.playbook_block()
def join_delete_the_created_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_delete_the_created_artifact() called')
    
    # if the joined function has already been called, do nothing
    #if phantom.get_run_data(key='join_delete_the_created_artifact_called'):
    #    return

    # no callbacks to check, call connected block "delete_the_created_artifact"
    #phantom.save_run_data(key='join_delete_the_created_artifact_called', value='delete_the_created_artifact', auto=True)

    delete_the_created_artifact(container=container, handle=handle)
    
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

    phantom.act(action="no op", parameters=parameters, assets=['phantom asset'], callback=decision_10, name="sleep")

    return

@phantom.playbook_block()
def decision_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_9() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_containment_status:custom_function:is_contain_failed", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        set_status_set_severity_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    set_severity_set_status_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

@phantom.playbook_block()
def set_status_set_severity_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_set_severity_4() called')

    phantom.set_status(container=container, status="Open")

    phantom.set_severity(container=container, severity="Low")
    join_cf_local_set_custom_field_incident_type_1(container=container)

    return

@phantom.playbook_block()
def decision_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_10() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.sourceAddress_ContainResult", "==", True],
        ],
        scope="all")

    # call connected blocks if condition 1 matched
    if matched:
        join_delete_the_created_artifact(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    flag_contain_failed(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Flag contain failed
"""
@phantom.playbook_block()
def flag_contain_failed(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('flag_contain_failed() called')
    
    input_parameter_0 = ""

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    global CONTAIN_FAILED
    CONTAIN_FAILED = True

    ################################################################################
    ## Custom Code End
    ################################################################################
    join_delete_the_created_artifact(container=container)

    return

"""
Get containment status
"""
@phantom.playbook_block()
def get_containment_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_containment_status() called')
    
    input_parameter_0 = ""

    get_containment_status__is_contain_failed = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    global CONTAIN_FAILED
    get_containment_status__is_contain_failed = CONTAIN_FAILED

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='get_containment_status:is_contain_failed', value=json.dumps(get_containment_status__is_contain_failed))
    decision_9(container=container)

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