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

@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'check_artifact_count' block
    check_artifact_count(container=container)

    return

"""
Filter out sourceAddress
"""
@phantom.playbook_block()
def filter_out_sourceaddress(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_out_sourceaddress() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "!=", ""],
            ["Address_blocked", "not in", "artifact:*.tags"],
            ["artifact:*.cef.sourceAddress_malicious", "==", True],
        ],
        logical_operator='and',
        name="filter_out_sourceaddress:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        join_check_if_address_external(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Check if Address external
"""
@phantom.playbook_block()
def check_if_address_external(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_if_address_external() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_out_sourceaddress:condition_1:artifact:*.cef.sourceAddress'])
    filtered_artifacts_data_2 = phantom.collect2(container=container, datapath=['filtered-data:filter_out_destinationaddress:condition_1:artifact:*.cef.destinationAddress'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_2_0 = [item[0] for item in filtered_artifacts_data_2]

    check_if_address_external__AddressExternal = None
    check_if_address_external__AddressInternal = None

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
            
    check_if_address_external__AddressExternal = externaltemplist
    check_if_address_external__AddressInternal = internaltemplist
        
    ####
    ####
    ####
    ####
    ####
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='check_if_address_external:AddressExternal', value=json.dumps(check_if_address_external__AddressExternal))
    phantom.save_run_data(key='check_if_address_external:AddressInternal', value=json.dumps(check_if_address_external__AddressInternal))
    check_if_sourceaddressexternal(container=container)

    return

@phantom.playbook_block()
def join_check_if_address_external(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_check_if_address_external() called')

    # no callbacks to check, call connected block "check_if_address_external"
    phantom.save_run_data(key='join_check_if_address_external_called', value='check_if_address_external', auto=True)

    check_if_address_external(container=container, handle=handle)
    
    return

"""
Check if sourceAddressExternal
"""
@phantom.playbook_block()
def check_if_sourceaddressexternal(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_if_sourceaddressexternal() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["check_if_address_external:custom_function:AddressExternal", "!=", []],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        get_total_amount_of_ip_address(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        conditions=[
            ["check_if_address_external:custom_function:AddressInternal", "!=", []],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        add_note_for_no_external_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Update artifact with blocked dest tag
"""
@phantom.playbook_block()
def update_artifact_with_blocked_dest_tag(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_artifact_with_blocked_dest_tag() called')
    
    check_if_address_external__AddressExternal = json.loads(phantom.get_run_data(key='check_if_address_external:AddressExternal'))
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    artifactid = container_item_0[0]

    # url = phantom.build_phantom_rest_url('container' , id_value , 'artifacts')
    # url = url + '?_filter_cef__sourceAddress="' + check_if_address_external__AddressExternal[0] +'"'
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
    format_block_dest_ip_success(container=container)

    return

"""
Format ext IP address to contain
"""
@phantom.playbook_block()
def format_ext_ip_address_to_contain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ext_ip_address_to_contain() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "check_if_address_external:custom_function:AddressExternal",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ext_ip_address_to_contain", separator=", ")

    firepower_add_ip_to_custom_list(container=container)

    return

"""
Filter out destinationAddress
"""
@phantom.playbook_block()
def filter_out_destinationaddress(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_out_destinationaddress() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "!=", ""],
            ["Address_blocked", "not in", "artifact:*.tags"],
            ["artifact:*.cef.destinationAddress_malicious", "==", True],
        ],
        logical_operator='and',
        name="filter_out_destinationaddress:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        join_check_if_address_external(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def cf_local_set_last_automated_action_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_set_last_automated_action_1() called')
    
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

    # call custom function "local/set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_last_automated_action', parameters=parameters, name='cf_local_set_last_automated_action_1')

    return

@phantom.playbook_block()
def join_cf_local_set_last_automated_action_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_cf_local_set_last_automated_action_1() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_cf_local_set_last_automated_action_1_called'):
        return

    # no callbacks to check, call connected block "cf_local_set_last_automated_action_1"
    phantom.save_run_data(key='join_cf_local_set_last_automated_action_1_called', value='cf_local_set_last_automated_action_1', auto=True)

    cf_local_set_last_automated_action_1(container=container, handle=handle)
    
    return

@phantom.playbook_block()
def cf_local_set_last_automated_action_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_set_last_automated_action_2() called')
    
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

    # call custom function "local/set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_last_automated_action', parameters=parameters, name='cf_local_set_last_automated_action_2')

    return

"""
Firepower Add IP to custom list
"""
@phantom.playbook_block()
def firepower_add_ip_to_custom_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('firepower_add_ip_to_custom_list() called')
    
    check_if_address_external__AddressExternal = json.loads(phantom.get_run_data(key='check_if_address_external:AddressExternal'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    IP_LIST_NAME = "Firepower - IP to contain"
    
    for ip in check_if_address_external__AddressExternal:
        success, message, num_of_matching_row = phantom.check_list(list_name=IP_LIST_NAME, value=ip, case_sensitive=True, substring=False)
        #phantom.debug(num_of_matching_row)
        if num_of_matching_row == 0:
            phantom.add_list(list_name=IP_LIST_NAME, values=[ip])

    ################################################################################
    ## Custom Code End
    ################################################################################
    determine_src_or_dst_for_fortinet(container=container)

    return

"""
Check artifact count
"""
@phantom.playbook_block()
def check_artifact_count(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_artifact_count() called')
    
    artifact_count_param = container.get('artifact_count', None)

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            [artifact_count_param, "<=", 1],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        filter_out_sourceaddress(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        filter_out_destinationaddress(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    add_note_for_more_than_1_artifact_found(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Add Note for more than 1 artifact found
"""
@phantom.playbook_block()
def add_note_for_more_than_1_artifact_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_for_more_than_1_artifact_found() called')

    # collect data for 'add_note_for_more_than_1_artifact_found' call

    parameters = []
    
    # build parameters list for 'add_note_for_more_than_1_artifact_found' call
    parameters.append({
        'title': "ERROR: Detected more than 1 artifact",
        'content': "This playbook support the event that has only 1 artifact",
        'phase_id': "",
        'container_id': "",
    })

    phantom.act(action="add note", parameters=parameters, assets=['phantom asset'], callback=cf_local_set_last_automated_action_2, name="add_note_for_more_than_1_artifact_found")

    return

"""
determine src or dst for Fortinet
"""
@phantom.playbook_block()
def determine_src_or_dst_for_fortinet(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('determine_src_or_dst_for_fortinet() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["filtered-data:filter_out_sourceaddress:condition_1:artifact:*.cef.sourceAddress", "!=", []],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        palo_alto_add_src_ip_to_custom_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        conditions=[
            ["filtered-data:filter_out_destinationaddress:condition_1:artifact:*.cef.destinationAddress", "!=", []],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        palo_alto_add_dest_ip_to_custom_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Add note for no external IP
"""
@phantom.playbook_block()
def add_note_for_no_external_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_for_no_external_ip() called')

    # collect data for 'add_note_for_no_external_ip' call

    parameters = []
    
    # build parameters list for 'add_note_for_no_external_ip' call
    parameters.append({
        'title': "External IP Not Found",
        'content': "There is no external IP address to contain",
        'phase_id': "",
        'container_id': "",
    })

    phantom.act(action="add note", parameters=parameters, assets=['phantom asset'], name="add_note_for_no_external_ip")

    return

"""
Update artifact with blocked source tag
"""
@phantom.playbook_block()
def update_artifact_with_blocked_source_tag(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_artifact_with_blocked_source_tag() called')
    
    check_if_address_external__AddressExternal = json.loads(phantom.get_run_data(key='check_if_address_external:AddressExternal'))
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
    format_block_src_ip_success(container=container)

    return

"""
Format block src IP success
"""
@phantom.playbook_block()
def format_block_src_ip_success(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_block_src_ip_success() called')
    
    template = """Source IP address: `{0}` has been added into the waiting list to be contained by Firepower,  Palo Alto, Fortigate and Fortimanager."""

    # parameter list for template variable replacement
    parameters = [
        "check_if_address_external:custom_function:AddressExternal",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_block_src_ip_success", separator=", ")

    add_note_for_block_src_ip_success(container=container)

    return

"""
Format block dest IP success
"""
@phantom.playbook_block()
def format_block_dest_ip_success(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_block_dest_ip_success() called')
    
    template = """Destination IP address: `{0}` has been added into the waiting list to be contained by Firepower, Palo Alto, Fortigate and Fortimanager."""

    # parameter list for template variable replacement
    parameters = [
        "format_ext_ip_address_to_contain:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_block_dest_ip_success", separator=", ")

    add_note_for_block_dst_ip_success(container=container)

    return

"""
Add Note for block src IP success
"""
@phantom.playbook_block()
def add_note_for_block_src_ip_success(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_for_block_src_ip_success() called')

    # collect data for 'add_note_for_block_src_ip_success' call
    formatted_data_1 = phantom.get_format_data(name='format_block_src_ip_success')

    parameters = []
    
    # build parameters list for 'add_note_for_block_src_ip_success' call
    parameters.append({
        'title': "Containment Result",
        'content': formatted_data_1,
        'phase_id': "",
        'container_id': "",
    })

    phantom.act(action="add note", parameters=parameters, assets=['phantom asset'], callback=join_cf_local_set_last_automated_action_1, name="add_note_for_block_src_ip_success")

    return

"""
Add Note for block dst IP success
"""
@phantom.playbook_block()
def add_note_for_block_dst_ip_success(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_for_block_dst_ip_success() called')

    # collect data for 'add_note_for_block_dst_ip_success' call
    formatted_data_1 = phantom.get_format_data(name='format_block_dest_ip_success')

    parameters = []
    
    # build parameters list for 'add_note_for_block_dst_ip_success' call
    parameters.append({
        'title': "Containment Result",
        'content': formatted_data_1,
        'phase_id': "",
        'container_id': "",
    })

    phantom.act(action="add note", parameters=parameters, assets=['phantom asset'], callback=join_cf_local_set_last_automated_action_1, name="add_note_for_block_dst_ip_success")

    return

"""
Palo Alto Add Src IP to custom list
"""
@phantom.playbook_block()
def palo_alto_add_src_ip_to_custom_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('palo_alto_add_src_ip_to_custom_list() called')
    
    check_if_address_external__AddressExternal = json.loads(phantom.get_run_data(key='check_if_address_external:AddressExternal'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    IP_LIST_NAME = "PaloAlto - Src IP to contain"
    
    for ip in check_if_address_external__AddressExternal:
        success, message, num_of_matching_row = phantom.check_list(list_name=IP_LIST_NAME, value=ip, case_sensitive=True, substring=False)
        #phantom.debug(num_of_matching_row)
        if num_of_matching_row == 0:
            phantom.add_list(list_name=IP_LIST_NAME, values=[ip])
            
    ########
    ########
    ################################################################################
    ## Custom Code End
    ################################################################################
    fortimanager_add_src_ip_to_custom_list(container=container)

    return

"""
Fortimanager Add Src IP to custom list
"""
@phantom.playbook_block()
def fortimanager_add_src_ip_to_custom_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('fortimanager_add_src_ip_to_custom_list() called')
    
    check_if_address_external__AddressExternal = json.loads(phantom.get_run_data(key='check_if_address_external:AddressExternal'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    IP_LIST_NAME = "Fortimanager - Src IP to contain"
    
    for ip in check_if_address_external__AddressExternal:
        success, message, num_of_matching_row = phantom.check_list(list_name=IP_LIST_NAME, value=ip, case_sensitive=True, substring=False)
        #phantom.debug(num_of_matching_row)
        if num_of_matching_row == 0:
            phantom.add_list(list_name=IP_LIST_NAME, values=[ip])

    ################################################################################
    ## Custom Code End
    ################################################################################
    update_artifact_with_blocked_source_tag(container=container)

    return

"""
Palo Alto Add Dest IP to custom list
"""
@phantom.playbook_block()
def palo_alto_add_dest_ip_to_custom_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('palo_alto_add_dest_ip_to_custom_list() called')
    
    check_if_address_external__AddressExternal = json.loads(phantom.get_run_data(key='check_if_address_external:AddressExternal'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    IP_LIST_NAME = "PaloAlto - Dest IP to contain"
    
    for ip in check_if_address_external__AddressExternal:
        success, message, num_of_matching_row = phantom.check_list(list_name=IP_LIST_NAME, value=ip, case_sensitive=True, substring=False)
        #phantom.debug(num_of_matching_row)
        if num_of_matching_row == 0:
            phantom.add_list(list_name=IP_LIST_NAME, values=[ip])
            
    ########
    ########
    ################################################################################
    ## Custom Code End
    ################################################################################
    fortimanager_add_dest_ip_to_custom_list(container=container)

    return

"""
Fortigate Add Dest IP to custom list
"""
@phantom.playbook_block()
def fortigate_add_dest_ip_to_custom_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('fortigate_add_dest_ip_to_custom_list() called')
    
    check_if_address_external__AddressExternal = json.loads(phantom.get_run_data(key='check_if_address_external:AddressExternal'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    IP_LIST_NAME = "Fortigate - Dest IP to contain"
    
    for ip in check_if_address_external__AddressExternal:
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
@phantom.playbook_block()
def fortimanager_add_dest_ip_to_custom_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('fortimanager_add_dest_ip_to_custom_list() called')
    
    check_if_address_external__AddressExternal = json.loads(phantom.get_run_data(key='check_if_address_external:AddressExternal'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    IP_LIST_NAME = "Fortimanager - Dest IP to contain"
    
    for ip in check_if_address_external__AddressExternal:
        success, message, num_of_matching_row = phantom.check_list(list_name=IP_LIST_NAME, value=ip, case_sensitive=True, substring=False)
        #phantom.debug(num_of_matching_row)
        if num_of_matching_row == 0:
            phantom.add_list(list_name=IP_LIST_NAME, values=[ip])

    ################################################################################
    ## Custom Code End
    ################################################################################
    update_artifact_with_blocked_dest_tag(container=container)

    return

"""
Fortigate Add Src IP to custom list
"""
@phantom.playbook_block()
def fortigate_add_src_ip_to_custom_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('fortigate_add_src_ip_to_custom_list() called')
    
    check_if_address_external__AddressExternal = json.loads(phantom.get_run_data(key='check_if_address_external:AddressExternal'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    IP_LIST_NAME = "Fortigate - Src IP to contain"
    
    for ip in check_if_address_external__AddressExternal:
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
@phantom.playbook_block()
def get_total_amount_of_ip_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_total_amount_of_ip_address() called')
    
    check_if_address_external__AddressExternal = json.loads(phantom.get_run_data(key='check_if_address_external:AddressExternal'))

    get_total_amount_of_ip_address__total_num_of_ip = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    import ipaddress
    ipaddress_list = set(check_if_address_external__AddressExternal)
    success, message, iplist = phantom.get_list(list_name='Firepower - IP to contain')
    for ip in iplist:
        try:
            ipaddress.ip_address(ip[0])
            phantom.debug(f"Current IP: {ip[0]}")
            ipaddress_list.add(ip[0])
        except:
            continue
    get_total_amount_of_ip_address__total_num_of_ip = len(ipaddress_list)
    phantom.debug(f"Total IP in the list + to be added: {get_total_amount_of_ip_address__total_num_of_ip}")

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='get_total_amount_of_ip_address:total_num_of_ip', value=json.dumps(get_total_amount_of_ip_address__total_num_of_ip))
    decision_21(container=container)

    return

@phantom.playbook_block()
def decision_21(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_21() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["get_total_amount_of_ip_address:custom_function:total_num_of_ip", "<=", 20],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        format_ext_ip_address_to_contain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    format_ip_for_markdown(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Add note for IP amount excess error
"""
@phantom.playbook_block()
def add_note_for_ip_amount_excess_error(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_for_ip_amount_excess_error() called')

    formatted_data_1 = phantom.get_format_data(name='format_ip_for_markdown')

    note_title = "Failed to contain IP address due to amount exceeded"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    cf_local_set_last_automated_action_3(container=container)

    return

@phantom.playbook_block()
def cf_local_set_last_automated_action_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_set_last_automated_action_3() called')
    
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

    # call custom function "local/set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_last_automated_action', parameters=parameters, name='cf_local_set_last_automated_action_3')

    return

"""
Format IP for markdown
"""
@phantom.playbook_block()
def format_ip_for_markdown(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ip_for_markdown() called')
    
    template = """%%
- `{0}`
%%"""

    # parameter list for template variable replacement
    parameters = [
        "check_if_address_external:custom_function:AddressExternal",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ip_for_markdown", separator=", ")

    add_note_for_ip_amount_excess_error(container=container)

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