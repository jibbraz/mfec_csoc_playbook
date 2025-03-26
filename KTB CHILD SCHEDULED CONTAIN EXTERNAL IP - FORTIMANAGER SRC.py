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

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Collect_all_IP_address' block
    Collect_all_IP_address(container=container)

    return

"""
Get the top IP address from the list
"""
def Get_the_top_IP_address_from_the_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Get_the_top_IP_address_from_the_list() called')
    
    input_parameter_0 = ""

    Get_the_top_IP_address_from_the_list__top_ip_address = None

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
            Get_the_top_IP_address_from_the_list__top_ip_address = ip[0]
            break
        except:
            continue

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Get_the_top_IP_address_from_the_list:top_ip_address', value=json.dumps(Get_the_top_IP_address_from_the_list__top_ip_address))
    decision_1(container=container)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Get_the_top_IP_address_from_the_list:custom_function:top_ip_address", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Prepare_src_IP_artifact(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    Add_Note_for_No_IP_address_to_contain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Add Note for No IP address to contain
"""
def Add_Note_for_No_IP_address_to_contain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_Note_for_No_IP_address_to_contain() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Add_Note_for_No_IP_address_to_contain' call

    parameters = []
    
    # build parameters list for 'Add_Note_for_No_IP_address_to_contain' call
    parameters.append({
        'title': "Source Address: No IP address to contain",
        'content': "There is no IP address to contain from the custom list.",
        'phase_id': "",
        'container_id': "",
    })

    phantom.act(action="add note", parameters=parameters, assets=['phantom asset'], callback=set_severity_set_status_3, name="Add_Note_for_No_IP_address_to_contain")

    return

"""
Remove the top IP address from the list
"""
def Remove_the_top_IP_address_from_the_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Remove_the_top_IP_address_from_the_list() called')
    
    Get_the_top_IP_address_from_the_list__top_ip_address = json.loads(phantom.get_run_data(key='Get_the_top_IP_address_from_the_list:top_ip_address'))

    Remove_the_top_IP_address_from_the_list__ip_count = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    import ipaddress
    Remove_the_top_IP_address_from_the_list__ip_count = 0
    
    phantom.debug(f"Popping out IP: {Get_the_top_IP_address_from_the_list__top_ip_address}")
    phantom.delete_from_list(list_name="Fortimanager - Src IP to contain", value=Get_the_top_IP_address_from_the_list__top_ip_address, column=None, remove_all=False, remove_row=False)
    success, message, iplist = phantom.get_list(list_name='Fortimanager - Src IP to contain')
    for ip in iplist:
        try:
            ipaddress.ip_address(ip[0])
            Remove_the_top_IP_address_from_the_list__ip_count += 1
        except:
            continue

    phantom.debug(f"Current number of IP address remaining in the list: {Remove_the_top_IP_address_from_the_list__ip_count}")

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Remove_the_top_IP_address_from_the_list:ip_count', value=json.dumps(Remove_the_top_IP_address_from_the_list__ip_count))
    decision_7(container=container)

    return

def decision_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_7() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Remove_the_top_IP_address_from_the_list:custom_function:ip_count", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        join_decision_8(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    Get_containment_status(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

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
        Get_the_top_IP_address_from_the_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def join_decision_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_decision_8() called')
    
    # if the joined function has already been called, do nothing
    #if phantom.get_run_data(key='join_decision_8_called'):
    #    return

    # no callbacks to check, call connected block "decision_8"
    phantom.save_run_data(key='join_decision_8_called', value='decision_8', auto=True)

    decision_8(container=container, handle=handle)
    
    return

def set_severity_set_status_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_set_status_1() called')

    phantom.set_severity(container=container, severity="Low")

    phantom.set_status(container=container, status="Closed")
    join_cf_local_set_custom_field_incident_type_1(container=container)

    return

def set_severity_set_status_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_set_status_3() called')

    phantom.set_severity(container=container, severity="Low")

    phantom.set_status(container=container, status="Closed")
    join_cf_local_set_custom_field_incident_type_1(container=container)

    return

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

def join_cf_local_set_custom_field_incident_type_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_cf_local_set_custom_field_incident_type_1() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_cf_local_set_custom_field_incident_type_1_called'):
        return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['Sleep']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_cf_local_set_custom_field_incident_type_1_called', value='cf_local_set_custom_field_incident_type_1')
        
        # call connected block "cf_local_set_custom_field_incident_type_1"
        cf_local_set_custom_field_incident_type_1(container=container, handle=handle)
    
    return

"""
Collect all IP address
"""
def Collect_all_IP_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Collect_all_IP_address() called')
    
    input_parameter_0 = ""

    Collect_all_IP_address__all_IP_address_list = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    Collect_all_IP_address__all_IP_address_list = []
    import ipaddress
    success, message, iplist = phantom.get_list(list_name='Fortimanager - Src IP to contain')
    for ip in iplist:
        try:
            ipaddress.ip_address(ip[0])
            Collect_all_IP_address__all_IP_address_list.append(ip[0])
        except:
            continue

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Collect_all_IP_address:all_IP_address_list', value=json.dumps(Collect_all_IP_address__all_IP_address_list))
    join_decision_8(container=container)

    return

"""
Fortimanager Block Src IP
"""
def Fortimanager_Block_Src_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Fortimanager_Block_Src_IP() called')
    
    Get_the_top_IP_address_from_the_list__top_ip_address = json.loads(phantom.get_run_data(key='Get_the_top_IP_address_from_the_list:top_ip_address'))
    
    # call playbook "local/PLAYBOOK-CONTAIN-INDICATOR-CONSOLIDATED-FORTIMANAGER-SRCIP-01", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/PLAYBOOK-CONTAIN-INDICATOR-CONSOLIDATED-FORTIMANAGER-SRCIP-01", container=container, name=f"Fortimanager_Block_Src_IP_{Get_the_top_IP_address_from_the_list__top_ip_address}", callback=Sleep)

    return

"""
Add src IP artifact
"""
def Add_src_IP_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_src_IP_artifact() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    Get_the_top_IP_address_from_the_list__top_ip_address = json.loads(phantom.get_run_data(key='Get_the_top_IP_address_from_the_list:top_ip_address'))
    # collect data for 'Add_src_IP_artifact' call
    formatted_data_1 = phantom.get_format_data(name='Prepare_src_IP_artifact')

    parameters = []
    
    # build parameters list for 'Add_src_IP_artifact' call
    parameters.append({
        'name': "User created artifact",
        'label': "event",
        'cef_name': "",
        'contains': "",
        'cef_value': "",
        'container_id': "",
        'cef_dictionary': formatted_data_1,
        'run_automation': False,
        'source_data_identifier': Get_the_top_IP_address_from_the_list__top_ip_address,
    })

    phantom.act(action="add artifact", parameters=parameters, assets=['phantom asset'], callback=Fortimanager_Block_Src_IP, name="Add_src_IP_artifact")

    return

"""
Prepare src IP artifact
"""
def Prepare_src_IP_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Prepare_src_IP_artifact() called')
    
    template = """{{\"sourceAddress\": \"{0}\", \"sourceAddress_malicious\": \"True\"}}"""

    # parameter list for template variable replacement
    parameters = [
        "Get_the_top_IP_address_from_the_list:custom_function:top_ip_address",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Prepare_src_IP_artifact", separator=", ")

    Add_src_IP_artifact(container=container)

    return

"""
Delete the created artifact
"""
def Delete_the_created_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Delete_the_created_artifact() called')
    
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
    Remove_the_top_IP_address_from_the_list(container=container)

    return

def join_Delete_the_created_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_Delete_the_created_artifact() called')
    
    # if the joined function has already been called, do nothing
    #if phantom.get_run_data(key='join_Delete_the_created_artifact_called'):
    #    return

    # no callbacks to check, call connected block "Delete_the_created_artifact"
    #phantom.save_run_data(key='join_Delete_the_created_artifact_called', value='Delete_the_created_artifact', auto=True)

    Delete_the_created_artifact(container=container, handle=handle)
    
    return

"""
Sleep
"""
def Sleep(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Sleep() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Sleep' call

    parameters = []
    
    # build parameters list for 'Sleep' call
    parameters.append({
        'sleep_seconds': 120,
    })

    phantom.act(action="no op", parameters=parameters, assets=['phantom asset'], callback=decision_10, name="Sleep")

    return

def decision_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_9() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Get_containment_status:custom_function:is_contain_failed", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        set_status_set_severity_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    set_severity_set_status_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def set_status_set_severity_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_set_severity_4() called')

    phantom.set_status(container=container, status="Open")

    phantom.set_severity(container=container, severity="Low")
    join_cf_local_set_custom_field_incident_type_1(container=container)

    return

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
        join_Delete_the_created_artifact(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    Flag_contain_failed(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Flag contain failed
"""
def Flag_contain_failed(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Flag_contain_failed() called')
    
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
    join_Delete_the_created_artifact(container=container)

    return

"""
Get containment status
"""
def Get_containment_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Get_containment_status() called')
    
    input_parameter_0 = ""

    Get_containment_status__is_contain_failed = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    global CONTAIN_FAILED
    Get_containment_status__is_contain_failed = CONTAIN_FAILED

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Get_containment_status:is_contain_failed', value=json.dumps(Get_containment_status__is_contain_failed))
    decision_9(container=container)

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