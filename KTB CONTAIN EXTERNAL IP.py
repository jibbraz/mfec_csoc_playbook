"""
USE CASE: This playbook is used to contain the threat on External IP address
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

import ipaddress

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Check_artifact_count' block
    Check_artifact_count(container=container)

    return

"""
Filter out sourceAddress
"""
def Filter_out_sourceAddress(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_out_sourceAddress() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "!=", ""],
            ["Address_blocked", "not in", "artifact:*.tags"],
            ["artifact:*.cef.sourceAddress_malicious", "==", True],
        ],
        logical_operator='and',
        name="Filter_out_sourceAddress:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        join_Check_if_Address_external(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Check if Address external
"""
def Check_if_Address_external(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_if_Address_external() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_sourceAddress:condition_1:artifact:*.cef.sourceAddress'])
    filtered_artifacts_data_2 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_destinationAddress:condition_1:artifact:*.cef.destinationAddress'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_2_0 = [item[0] for item in filtered_artifacts_data_2]

    Check_if_Address_external__AddressExternal = None
    Check_if_Address_external__AddressInternal = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    filtered_artifacts_item_0_0 = []
    phantom.debug(filtered_artifacts_item_1_0)
    phantom.debug(filtered_artifacts_item_2_0)
    if filtered_artifacts_item_1_0 != []:
        filtered_artifacts_item_0_0 = filtered_artifacts_item_1_0
    else:
        filtered_artifacts_item_0_0 = filtered_artifacts_item_2_0
    externaltemplist = []
    internaltemplist = []
    for ip in filtered_artifacts_item_0_0:
        private = ipaddress.ip_address(ip).is_private
        if private == True:
            phantom.debug("{} is private".format(ip))
            internaltemplist.append(ip)
        else:
            phantom.debug("{} is public".format(ip))
            externaltemplist.append(ip)
            
    Check_if_Address_external__AddressExternal = externaltemplist
    Check_if_Address_external__AddressInternal = internaltemplist
        
    ####
    ####
    ####
    ####
    ####
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Check_if_Address_external:AddressExternal', value=json.dumps(Check_if_Address_external__AddressExternal))
    phantom.save_run_data(key='Check_if_Address_external:AddressInternal', value=json.dumps(Check_if_Address_external__AddressInternal))
    Check_if_sourceAddressExternal(container=container)

    return

def join_Check_if_Address_external(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_Check_if_Address_external() called')

    # no callbacks to check, call connected block "Check_if_Address_external"
    phantom.save_run_data(key='join_Check_if_Address_external_called', value='Check_if_Address_external', auto=True)

    Check_if_Address_external(container=container, handle=handle)
    
    return

"""
Check if sourceAddressExternal
"""
def Check_if_sourceAddressExternal(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_if_sourceAddressExternal() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["Check_if_Address_external:custom_function:AddressExternal", "!=", []],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Get_total_amount_of_IP_address(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        conditions=[
            ["Check_if_Address_external:custom_function:AddressInternal", "!=", []],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        Add_note_for_no_external_IP(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Update artifact with blocked dest tag
"""
def Update_artifact_with_blocked_dest_tag(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Update_artifact_with_blocked_dest_tag() called')
    
    Check_if_Address_external__AddressExternal = json.loads(phantom.get_run_data(key='Check_if_Address_external:AddressExternal'))
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    artifactid = container_item_0[0]

    # url = phantom.build_phantom_rest_url('container' , id_value , 'artifacts')
    # url = url + '?_filter_cef__sourceAddress="' + Check_if_Address_external__AddressExternal[0] +'"'
    # phantom.debug(url)
    # response = phantom.requests.get(url, verify=False)
    # phantom.debug(response.json()['data'])
    # for key in response.json()['data']:
        # for item in key:
            # if item == 'id':
                # phantom.debug(key[item])
                # artifactid = key[item]
                # phantom.debug(artifactid)

    parameters = []
    parameters.append({
        'artifact_id': artifactid,
        'add_tags': "Address_blocked",
        'remove_tags': "",
    })

    phantom.act(action="update artifact tags", parameters=parameters, assets=['phantom asset'], name="update_artifact_tags")

    ################################################################################
    ## Custom Code End
    ################################################################################
    Format_block_dest_IP_success(container=container)

    return

"""
Format ext IP address to contain
"""
def Format_ext_IP_address_to_contain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_ext_IP_address_to_contain() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "Check_if_Address_external:custom_function:AddressExternal",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_ext_IP_address_to_contain", separator=", ")

    Firepower_Add_IP_to_custom_list(container=container)

    return

"""
Filter out destinationAddress
"""
def Filter_out_destinationAddress(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_out_destinationAddress() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "!=", ""],
            ["Address_blocked", "not in", "artifact:*.tags"],
            ["artifact:*.cef.destinationAddress_malicious", "==", True],
        ],
        logical_operator='and',
        name="Filter_out_destinationAddress:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        join_Check_if_Address_external(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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
            "Resolved -Scheduled-",
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

def join_cf_local_Set_last_automated_action_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_cf_local_Set_last_automated_action_1() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_cf_local_Set_last_automated_action_1_called'):
        return

    # no callbacks to check, call connected block "cf_local_Set_last_automated_action_1"
    phantom.save_run_data(key='join_cf_local_Set_last_automated_action_1_called', value='cf_local_Set_last_automated_action_1', auto=True)

    cf_local_Set_last_automated_action_1(container=container, handle=handle)
    
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
            "Containment Failed",
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

"""
Firepower Add IP to custom list
"""
def Firepower_Add_IP_to_custom_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Firepower_Add_IP_to_custom_list() called')
    
    Check_if_Address_external__AddressExternal = json.loads(phantom.get_run_data(key='Check_if_Address_external:AddressExternal'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    IP_LIST_NAME = "Firepower - IP to contain"
    
    for ip in Check_if_Address_external__AddressExternal:
        success, message, num_of_matching_row = phantom.check_list(list_name=IP_LIST_NAME, value=ip, case_sensitive=True, substring=False)
        #phantom.debug(num_of_matching_row)
        if num_of_matching_row == 0:
            phantom.add_list(list_name=IP_LIST_NAME, values=[ip])

    ################################################################################
    ## Custom Code End
    ################################################################################
    determine_src_or_dst_for_Fortinet(container=container)

    return

"""
Check artifact count
"""
def Check_artifact_count(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_artifact_count() called')
    
    artifact_count_param = container.get('artifact_count', None)

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            [artifact_count_param, "<=", 1],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Filter_out_sourceAddress(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        Filter_out_destinationAddress(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    Add_Note_for_more_than_1_artifact_found(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Add Note for more than 1 artifact found
"""
def Add_Note_for_more_than_1_artifact_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_Note_for_more_than_1_artifact_found() called')

    # collect data for 'Add_Note_for_more_than_1_artifact_found' call

    parameters = []
    
    # build parameters list for 'Add_Note_for_more_than_1_artifact_found' call
    parameters.append({
        'title': "ERROR: Detected more than 1 artifact",
        'content': "This playbook support the event that has only 1 artifact",
        'phase_id': "",
        'container_id': "",
    })

    phantom.act(action="add note", parameters=parameters, assets=['phantom asset'], callback=cf_local_Set_last_automated_action_2, name="Add_Note_for_more_than_1_artifact_found")

    return

"""
determine src or dst for Fortinet
"""
def determine_src_or_dst_for_Fortinet(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('determine_src_or_dst_for_Fortinet() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["filtered-data:Filter_out_sourceAddress:condition_1:artifact:*.cef.sourceAddress", "!=", []],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Palo_Alto_Add_Src_IP_to_custom_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        conditions=[
            ["filtered-data:Filter_out_destinationAddress:condition_1:artifact:*.cef.destinationAddress", "!=", []],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        Palo_Alto_Add_Dest_IP_to_custom_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Add note for no external IP
"""
def Add_note_for_no_external_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_for_no_external_IP() called')

    # collect data for 'Add_note_for_no_external_IP' call

    parameters = []
    
    # build parameters list for 'Add_note_for_no_external_IP' call
    parameters.append({
        'title': "External IP Not Found",
        'content': "There is no external IP address to contain",
        'phase_id': "",
        'container_id': "",
    })

    phantom.act(action="add note", parameters=parameters, assets=['phantom asset'], name="Add_note_for_no_external_IP")

    return

"""
Update artifact with blocked source tag
"""
def Update_artifact_with_blocked_source_tag(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Update_artifact_with_blocked_source_tag() called')
    
    Check_if_Address_external__AddressExternal = json.loads(phantom.get_run_data(key='Check_if_Address_external:AddressExternal'))
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    artifactid = container_item_0[0]

    parameters = []
    parameters.append({
        'artifact_id': artifactid,
        'add_tags': "Address_blocked",
        'remove_tags': "",
    })

    phantom.act(action="update artifact tags", parameters=parameters, assets=['phantom asset'], name="update_artifact_tags")

    ################################################################################
    ## Custom Code End
    ################################################################################
    Format_block_src_IP_success(container=container)

    return

"""
Format block src IP success
"""
def Format_block_src_IP_success(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_block_src_IP_success() called')
    
    template = """Source IP address: `{0}` has been added into the waiting list to be contained by Firepower,  Palo Alto, Fortigate and Fortimanager."""

    # parameter list for template variable replacement
    parameters = [
        "Check_if_Address_external:custom_function:AddressExternal",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_block_src_IP_success", separator=", ")

    Add_Note_for_block_src_IP_success(container=container)

    return

"""
Format block dest IP success
"""
def Format_block_dest_IP_success(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_block_dest_IP_success() called')
    
    template = """Destination IP address: `{0}` has been added into the waiting list to be contained by Firepower, Palo Alto, Fortigate and Fortimanager."""

    # parameter list for template variable replacement
    parameters = [
        "Format_ext_IP_address_to_contain:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_block_dest_IP_success", separator=", ")

    Add_Note_for_block_dst_IP_success(container=container)

    return

"""
Add Note for block src IP success
"""
def Add_Note_for_block_src_IP_success(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_Note_for_block_src_IP_success() called')

    # collect data for 'Add_Note_for_block_src_IP_success' call
    formatted_data_1 = phantom.get_format_data(name='Format_block_src_IP_success')

    parameters = []
    
    # build parameters list for 'Add_Note_for_block_src_IP_success' call
    parameters.append({
        'title': "Containment Result",
        'content': formatted_data_1,
        'phase_id': "",
        'container_id': "",
    })

    phantom.act(action="add note", parameters=parameters, assets=['phantom asset'], callback=join_cf_local_Set_last_automated_action_1, name="Add_Note_for_block_src_IP_success")

    return

"""
Add Note for block dst IP success
"""
def Add_Note_for_block_dst_IP_success(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_Note_for_block_dst_IP_success() called')

    # collect data for 'Add_Note_for_block_dst_IP_success' call
    formatted_data_1 = phantom.get_format_data(name='Format_block_dest_IP_success')

    parameters = []
    
    # build parameters list for 'Add_Note_for_block_dst_IP_success' call
    parameters.append({
        'title': "Containment Result",
        'content': formatted_data_1,
        'phase_id': "",
        'container_id': "",
    })

    phantom.act(action="add note", parameters=parameters, assets=['phantom asset'], callback=join_cf_local_Set_last_automated_action_1, name="Add_Note_for_block_dst_IP_success")

    return

"""
Palo Alto Add Src IP to custom list
"""
def Palo_Alto_Add_Src_IP_to_custom_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Palo_Alto_Add_Src_IP_to_custom_list() called')
    
    Check_if_Address_external__AddressExternal = json.loads(phantom.get_run_data(key='Check_if_Address_external:AddressExternal'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    IP_LIST_NAME = "PaloAlto - Src IP to contain"
    
    for ip in Check_if_Address_external__AddressExternal:
        success, message, num_of_matching_row = phantom.check_list(list_name=IP_LIST_NAME, value=ip, case_sensitive=True, substring=False)
        #phantom.debug(num_of_matching_row)
        if num_of_matching_row == 0:
            phantom.add_list(list_name=IP_LIST_NAME, values=[ip])
            
    ########
    ########
    ################################################################################
    ## Custom Code End
    ################################################################################
    Fortimanager_Add_Src_IP_to_custom_list(container=container)

    return

"""
Fortimanager Add Src IP to custom list
"""
def Fortimanager_Add_Src_IP_to_custom_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Fortimanager_Add_Src_IP_to_custom_list() called')
    
    Check_if_Address_external__AddressExternal = json.loads(phantom.get_run_data(key='Check_if_Address_external:AddressExternal'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    IP_LIST_NAME = "Fortimanager - Src IP to contain"
    
    for ip in Check_if_Address_external__AddressExternal:
        success, message, num_of_matching_row = phantom.check_list(list_name=IP_LIST_NAME, value=ip, case_sensitive=True, substring=False)
        #phantom.debug(num_of_matching_row)
        if num_of_matching_row == 0:
            phantom.add_list(list_name=IP_LIST_NAME, values=[ip])

    ################################################################################
    ## Custom Code End
    ################################################################################
    Update_artifact_with_blocked_source_tag(container=container)

    return

"""
Palo Alto Add Dest IP to custom list
"""
def Palo_Alto_Add_Dest_IP_to_custom_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Palo_Alto_Add_Dest_IP_to_custom_list() called')
    
    Check_if_Address_external__AddressExternal = json.loads(phantom.get_run_data(key='Check_if_Address_external:AddressExternal'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    IP_LIST_NAME = "PaloAlto - Dest IP to contain"
    
    for ip in Check_if_Address_external__AddressExternal:
        success, message, num_of_matching_row = phantom.check_list(list_name=IP_LIST_NAME, value=ip, case_sensitive=True, substring=False)
        #phantom.debug(num_of_matching_row)
        if num_of_matching_row == 0:
            phantom.add_list(list_name=IP_LIST_NAME, values=[ip])
            
    ########
    ########
    ################################################################################
    ## Custom Code End
    ################################################################################
    Fortimanager_Add_Dest_IP_to_custom_list(container=container)

    return

"""
Fortigate Add Dest IP to custom list
"""
def Fortigate_Add_Dest_IP_to_custom_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Fortigate_Add_Dest_IP_to_custom_list() called')
    
    Check_if_Address_external__AddressExternal = json.loads(phantom.get_run_data(key='Check_if_Address_external:AddressExternal'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    IP_LIST_NAME = "Fortigate - Dest IP to contain"
    
    for ip in Check_if_Address_external__AddressExternal:
        success, message, num_of_matching_row = phantom.check_list(list_name=IP_LIST_NAME, value=ip, case_sensitive=True, substring=False)
        #phantom.debug(num_of_matching_row)
        if num_of_matching_row == 0:
            phantom.add_list(list_name=IP_LIST_NAME, values=[ip])
            
    ########
    ########
    ################################################################################
    ## Custom Code End
    ################################################################################

    return

"""
Fortimanager Add Dest IP to custom list
"""
def Fortimanager_Add_Dest_IP_to_custom_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Fortimanager_Add_Dest_IP_to_custom_list() called')
    
    Check_if_Address_external__AddressExternal = json.loads(phantom.get_run_data(key='Check_if_Address_external:AddressExternal'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    IP_LIST_NAME = "Fortimanager - Dest IP to contain"
    
    for ip in Check_if_Address_external__AddressExternal:
        success, message, num_of_matching_row = phantom.check_list(list_name=IP_LIST_NAME, value=ip, case_sensitive=True, substring=False)
        #phantom.debug(num_of_matching_row)
        if num_of_matching_row == 0:
            phantom.add_list(list_name=IP_LIST_NAME, values=[ip])

    ################################################################################
    ## Custom Code End
    ################################################################################
    Update_artifact_with_blocked_dest_tag(container=container)

    return

"""
Fortigate Add Src IP to custom list
"""
def Fortigate_Add_Src_IP_to_custom_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Fortigate_Add_Src_IP_to_custom_list() called')
    
    Check_if_Address_external__AddressExternal = json.loads(phantom.get_run_data(key='Check_if_Address_external:AddressExternal'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    IP_LIST_NAME = "Fortigate - Src IP to contain"
    
    for ip in Check_if_Address_external__AddressExternal:
        success, message, num_of_matching_row = phantom.check_list(list_name=IP_LIST_NAME, value=ip, case_sensitive=True, substring=False)
        #phantom.debug(num_of_matching_row)
        if num_of_matching_row == 0:
            phantom.add_list(list_name=IP_LIST_NAME, values=[ip])

    ################################################################################
    ## Custom Code End
    ################################################################################

    return

"""
Get total amount of IP address

"""
def Get_total_amount_of_IP_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Get_total_amount_of_IP_address() called')
    
    Check_if_Address_external__AddressExternal = json.loads(phantom.get_run_data(key='Check_if_Address_external:AddressExternal'))

    Get_total_amount_of_IP_address__total_num_of_ip = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    import ipaddress
    ipaddress_list = set(Check_if_Address_external__AddressExternal)
    success, message, iplist = phantom.get_list(list_name='Firepower - IP to contain')
    for ip in iplist:
        try:
            ipaddress.ip_address(ip[0])
            phantom.debug(f"Current IP: {ip[0]}")
            ipaddress_list.add(ip[0])
        except:
            continue
    Get_total_amount_of_IP_address__total_num_of_ip = len(ipaddress_list)
    phantom.debug(f"Total IP in the list + to be added: {Get_total_amount_of_IP_address__total_num_of_ip}")

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Get_total_amount_of_IP_address:total_num_of_ip', value=json.dumps(Get_total_amount_of_IP_address__total_num_of_ip))
    decision_21(container=container)

    return

def decision_21(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_21() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["Get_total_amount_of_IP_address:custom_function:total_num_of_ip", "<=", 20],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Format_ext_IP_address_to_contain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    Format_IP_for_markdown(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Add note for IP amount excess error
"""
def Add_note_for_IP_amount_excess_error(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_for_IP_amount_excess_error() called')

    formatted_data_1 = phantom.get_format_data(name='Format_IP_for_markdown')

    note_title = "Failed to contain IP address due to amount exceeded"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    cf_local_Set_last_automated_action_3(container=container)

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
            "Containment Failed",
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

"""
Format IP for markdown
"""
def Format_IP_for_markdown(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_IP_for_markdown() called')
    
    template = """%%
- `{0}`
%%"""

    # parameter list for template variable replacement
    parameters = [
        "Check_if_Address_external:custom_function:AddressExternal",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_IP_for_markdown", separator=", ")

    Add_note_for_IP_amount_excess_error(container=container)

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