"""
USE CASE: This playbook will perform enrichment tasks on the indicators
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
    
    # call 'cf_local_Set_last_automated_action_1' block
    cf_local_Set_last_automated_action_1(container=container)

    return

"""
Filter out sourceAddress
"""
def Filter_out_sourceAddress(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_out_sourceAddress() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.sourceAddress", "!=", ""],
        ],
        name="Filter_out_sourceAddress:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Check_if_sourceAddress_external(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Check if sourceAddress external
"""
def Check_if_sourceAddress_external(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_if_sourceAddress_external() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_sourceAddress:condition_1:artifact:*.cef.sourceAddress'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    Check_if_sourceAddress_external__sourceAddressExternal = None
    Check_if_sourceAddress_external__sourceAddressInternal = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    extemplist = []
    intemplist = []
    for ip in filtered_artifacts_item_1_0:
        try:
            private = ipaddress.ip_address(ip).is_private
            if private == True:
                phantom.debug("{} is private".format(ip))
                intemplist.append(ip)
            else:
                phantom.debug("{} is public".format(ip))
                extemplist.append(ip)
        except ValueError:
            phantom.debug(f">>>>>> address '{ip}' is invalid, skipping...")
            
    Check_if_sourceAddress_external__sourceAddressExternal = extemplist
    Check_if_sourceAddress_external__sourceAddressInternal = intemplist

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Check_if_sourceAddress_external:sourceAddressExternal', value=json.dumps(Check_if_sourceAddress_external__sourceAddressExternal))
    phantom.save_run_data(key='Check_if_sourceAddress_external:sourceAddressInternal', value=json.dumps(Check_if_sourceAddress_external__sourceAddressInternal))
    Check_if_sourceAddress_is_private(container=container)

    return

"""
IP Reputation src IP VT
"""
def IP_Reputation_src_IP_VT(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('IP_Reputation_src_IP_VT() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'IP_Reputation_src_IP_VT' call
    formatted_data_1 = phantom.get_format_data(name='Format_src_IP')

    parameters = []
    
    # build parameters list for 'IP_Reputation_src_IP_VT' call
    parameters.append({
        'ip': formatted_data_1,
    })

    phantom.act(action="ip reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=IP_Reputation_src_IP_TS, name="IP_Reputation_src_IP_VT")

    return

"""
IP Reputation src IP TS
"""
def IP_Reputation_src_IP_TS(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('IP_Reputation_src_IP_TS() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'IP_Reputation_src_IP_TS' call
    formatted_data_1 = phantom.get_format_data(name='Format_src_IP')

    parameters = []
    
    # build parameters list for 'IP_Reputation_src_IP_TS' call
    parameters.append({
        'ip': formatted_data_1,
        'limit': 1000,
    })

    phantom.act(action="ip reputation", parameters=parameters, assets=['threatstream hybrid vm','threatstream cloud'], callback=join_Link_back_src_IP_to_artifact_record, name="IP_Reputation_src_IP_TS", parent_action=action)

    return

"""
WhoIS src IP TS
"""
def WhoIS_src_IP_TS(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('WhoIS_src_IP_TS() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'WhoIS_src_IP_TS' call
    formatted_data_1 = phantom.get_format_data(name='Format_src_IP')

    parameters = []
    
    # build parameters list for 'WhoIS_src_IP_TS' call
    parameters.append({
        'ip': formatted_data_1,
    })

    phantom.act(action="whois ip", parameters=parameters, assets=['threatstream cloud'], callback=join_Link_back_src_IP_to_artifact_record, name="WhoIS_src_IP_TS")

    return

"""
Add note src IP
"""
def Add_note_src_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_src_IP() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['IP_Reputation_src_IP_VT:action_result.summary.malicious'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['IP_Reputation_src_IP_TS:action_result.data.*.threat_type'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['WhoIS_src_IP_TS:action_result.summary'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Link_back_src_IP_to_artifact_record:condition_1:artifact:*.id', 'filtered-data:Link_back_src_IP_to_artifact_record:condition_1:artifact:*.cef.sourceAddress'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]
    results_item_3_0 = [item[0] for item in results_data_3]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    ts_reputation_threat_type = []
    for t in results_item_2_0:
        if t not in ts_reputation_threat_type and t != None:
            ts_reputation_threat_type.append(t)
    
    content = f"Source IP address: {filtered_artifacts_item_1_1[0]}\n\n"
    content += f"**VirusTotal IP Reputation**\n" 
    content += f"- Malicious count: {results_item_1_0[0]}\n\n"
    content += f"- Summary: {'MALICIOUS' if results_item_1_0[0] > 2 else 'NON-MALICIOUS'}\n\n"
    
    content += f"**ThreatStream IP Repuation**\n"
    content += f"- Threat type: {', '.join(ts_reputation_threat_type) if ts_reputation_threat_type != [] else '-'}\n\n"
    content += f"- Summary: {'MALICIOUS' if len(ts_reputation_threat_type) > 0 else 'NON-MALICIOUS'}\n\n"
    
    content += f"**WhoIS IP**\n"
    content += f"- Summary: {results_item_3_0[0] if results_item_3_0[0] != {} else '-'}"
    #phantom.debug(filtered_artifacts_item_1_1[0])
    #phantom.debug(str(results_item_1_0[0]))
    #phantom.debug(str(results_item_2_0[0]))
    #phantom.debug(str(results_item_3_0[0]))
    
    note_title = "sourceAddress Investigation"
    note_content = content
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    ################################################################################
    ## Custom Code End
    ################################################################################
    Update_src_IP_artifact(container=container)

    return

"""
Update src IP artifact
"""
def Update_src_IP_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Update_src_IP_artifact() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['IP_Reputation_src_IP_VT:action_result.summary.malicious'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['IP_Reputation_src_IP_TS:action_result.data.*.threat_type'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['WhoIS_src_IP_TS:action_result.summary'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Link_back_src_IP_to_artifact_record:condition_1:artifact:*.id', 'filtered-data:Link_back_src_IP_to_artifact_record:condition_1:artifact:*.cef.sourceAddress'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]
    results_item_3_0 = [item[0] for item in results_data_3]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    ts_ip_reputation_threat_type = []
    for t in results_item_2_0:
        if t not in ts_ip_reputation_threat_type and t != None:
            ts_ip_reputation_threat_type.append(t)
            
    if ts_ip_reputation_threat_type != [] or results_item_1_0[0] > 2:
        parameters = []   
            
        cef_json = {"sourceAddress_malicious" : "True"}
         
        parameters.append({
            'artifact_id': filtered_artifacts_item_1_0[0],
            'name': "",
            'label': "",
            'severity': "",
            'cef_json': cef_json,
            'cef_types_json': "",
            'tags': "",
            'overwrite': "",
            'artifact_json': "",
        })
        phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_sourceAddress")

        parameters = []
        parameters.append({
            'artifact_id': filtered_artifacts_item_1_0[0],
            'add_tags': "indicator_malicious",
            'remove_tags': "",
        })
        phantom.act(action="update artifact tags", parameters=parameters, assets=['phantom asset'], name="update_artifact_tags")

    ################################################################################
    ## Custom Code End
    ################################################################################
    join_filter_21(container=container)

    return

"""
Link back src IP to artifact record
"""
def Link_back_src_IP_to_artifact_record(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Link_back_src_IP_to_artifact_record() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.sourceAddress", "in", "Check_if_sourceAddress_external:custom_function:sourceAddressExternal"],
        ],
        name="Link_back_src_IP_to_artifact_record:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Add_note_src_IP(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def join_Link_back_src_IP_to_artifact_record(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_Link_back_src_IP_to_artifact_record() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['WhoIS_src_IP_TS', 'IP_Reputation_src_IP_TS']):
        
        # call connected block "Link_back_src_IP_to_artifact_record"
        Link_back_src_IP_to_artifact_record(container=container, handle=handle)
    
    return

"""
Filter out destinationAddress
"""
def Filter_out_destinationAddress(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_out_destinationAddress() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationAddress", "!=", ""],
        ],
        name="Filter_out_destinationAddress:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Check_if_destinationAddress_external(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Check if destinationAddress external
"""
def Check_if_destinationAddress_external(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_if_destinationAddress_external() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_destinationAddress:condition_1:artifact:*.cef.destinationAddress'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    Check_if_destinationAddress_external__destinationAddressExternal = None
    Check_if_destinationAddress_external__destinationAddressInternal = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    extemplist = []
    intemplist = []
    for ip in filtered_artifacts_item_1_0:
        try:
            private = ipaddress.ip_address(ip).is_private
            if private == True:
                phantom.debug("{} is private".format(ip))
                intemplist.append(ip)
            else:
                phantom.debug("{} is public".format(ip))
                extemplist.append(ip)
        except ValueError:
            phantom.debug(f"address '{ip}' is invalid, skipping...")
            
    Check_if_destinationAddress_external__destinationAddressExternal = extemplist
    Check_if_destinationAddress_external__destinationAddressInternal = intemplist
    ###################################################################
    ###################################################################
    ###################################################################
    ###################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Check_if_destinationAddress_external:destinationAddressExternal', value=json.dumps(Check_if_destinationAddress_external__destinationAddressExternal))
    phantom.save_run_data(key='Check_if_destinationAddress_external:destinationAddressInternal', value=json.dumps(Check_if_destinationAddress_external__destinationAddressInternal))
    Check_if_destinationAddress_is_private(container=container)

    return

"""
Check if sourceAddress is private
"""
def Check_if_sourceAddress_is_private(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_if_sourceAddress_is_private() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_if_sourceAddress_external:custom_function:sourceAddressExternal", "!=", []],
        ],
        name="Check_if_sourceAddress_is_private:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_src_IP(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_if_sourceAddress_external:custom_function:sourceAddressInternal", "!=", []],
        ],
        name="Check_if_sourceAddress_is_private:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        Link_internal_src_to_artifact_record(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

"""
Check if destinationAddress is private
"""
def Check_if_destinationAddress_is_private(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_if_destinationAddress_is_private() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_if_destinationAddress_external:custom_function:destinationAddressExternal", "!=", []],
        ],
        name="Check_if_destinationAddress_is_private:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_dst_IP(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_if_destinationAddress_external:custom_function:destinationAddressInternal", "!=", []],
        ],
        name="Check_if_destinationAddress_is_private:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        Link_internal_dst_to_artifact_record(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

"""
IP Reputation dst IP VT
"""
def IP_Reputation_dst_IP_VT(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('IP_Reputation_dst_IP_VT() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'IP_Reputation_dst_IP_VT' call
    formatted_data_1 = phantom.get_format_data(name='Format_dst_IP')

    parameters = []
    
    # build parameters list for 'IP_Reputation_dst_IP_VT' call
    parameters.append({
        'ip': formatted_data_1,
    })

    phantom.act(action="ip reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=IP_Reputation_dst_IP_TS, name="IP_Reputation_dst_IP_VT")

    return

"""
Format src IP
"""
def Format_src_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_src_IP() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "Check_if_sourceAddress_external:custom_function:sourceAddressExternal",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_src_IP", separator=", ")

    IP_Reputation_src_IP_VT(container=container)
    WhoIS_src_IP_TS(container=container)

    return

"""
Format dst IP
"""
def Format_dst_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_dst_IP() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "Check_if_destinationAddress_external:custom_function:destinationAddressExternal",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_dst_IP", separator=", ")

    IP_Reputation_dst_IP_VT(container=container)
    WhoIS_dst_IP_TS(container=container)

    return

"""
IP Reputation src IP TS
"""
def IP_Reputation_dst_IP_TS(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('IP_Reputation_dst_IP_TS() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'IP_Reputation_dst_IP_TS' call
    formatted_data_1 = phantom.get_format_data(name='Format_dst_IP')

    parameters = []
    
    # build parameters list for 'IP_Reputation_dst_IP_TS' call
    parameters.append({
        'ip': formatted_data_1,
        'limit': 1000,
    })

    phantom.act(action="ip reputation", parameters=parameters, assets=['threatstream cloud','threatstream hybrid vm'], callback=join_Link_back_dst_IP_to_artifact_record, name="IP_Reputation_dst_IP_TS", parent_action=action)

    return

"""
WhoIS dst IP TS
"""
def WhoIS_dst_IP_TS(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('WhoIS_dst_IP_TS() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'WhoIS_dst_IP_TS' call
    formatted_data_1 = phantom.get_format_data(name='Format_dst_IP')

    parameters = []
    
    # build parameters list for 'WhoIS_dst_IP_TS' call
    parameters.append({
        'ip': formatted_data_1,
    })

    phantom.act(action="whois ip", parameters=parameters, assets=['threatstream cloud'], callback=join_Link_back_dst_IP_to_artifact_record, name="WhoIS_dst_IP_TS")

    return

"""
Link back dst IP to artifact record
"""
def Link_back_dst_IP_to_artifact_record(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Link_back_dst_IP_to_artifact_record() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationAddress", "in", "Check_if_destinationAddress_external:custom_function:destinationAddressExternal"],
        ],
        name="Link_back_dst_IP_to_artifact_record:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Add_note_dst_IP(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def join_Link_back_dst_IP_to_artifact_record(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_Link_back_dst_IP_to_artifact_record() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['WhoIS_dst_IP_TS', 'IP_Reputation_dst_IP_TS']):
        
        # call connected block "Link_back_dst_IP_to_artifact_record"
        Link_back_dst_IP_to_artifact_record(container=container, handle=handle)
    
    return

"""
Add note dst IP
"""
def Add_note_dst_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_dst_IP() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['IP_Reputation_dst_IP_VT:action_result.summary.malicious'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['IP_Reputation_dst_IP_TS:action_result.data.*.threat_type'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['WhoIS_dst_IP_TS:action_result.summary'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Link_back_dst_IP_to_artifact_record:condition_1:artifact:*.id', 'filtered-data:Link_back_dst_IP_to_artifact_record:condition_1:artifact:*.cef.destinationAddress'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]
    results_item_3_0 = [item[0] for item in results_data_3]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    ts_reputation_threat_type = []
    for t in results_item_2_0:
        if t not in ts_reputation_threat_type and t != None:
            ts_reputation_threat_type.append(t)
    
    content = f"Destination IP address: {filtered_artifacts_item_1_1[0]}\n\n"
    content += f"**VirusTotal IP Reputation**\n" 
    content += f"- Malicious count: {results_item_1_0[0]}\n\n"
    content += f"- Summary: {'MALICIOUS' if results_item_1_0[0] > 2 else 'NON-MALICIOUS'}\n\n"
    
    content += f"**ThreatStream IP Repuation**\n"
    content += f"- Threat type: {', '.join(ts_reputation_threat_type) if ts_reputation_threat_type != [] else '-'}\n\n"
    content += f"- Summary: {'MALICIOUS' if len(ts_reputation_threat_type) > 0 else 'NON-MALICIOUS'}\n\n"
    
    content += f"**WhoIS IP**\n"
    content += f"- Summary: {results_item_3_0[0] if results_item_3_0[0] != {} else '-'}"
    
    note_title = "destinationAddress Investigation"
    note_content = content
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################
    Update_dst_IP_artifact(container=container)

    return

"""
Update dst IP artifact
"""
def Update_dst_IP_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Update_dst_IP_artifact() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['IP_Reputation_dst_IP_VT:action_result.summary.malicious'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['IP_Reputation_dst_IP_TS:action_result.data.*.threat_type'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['WhoIS_dst_IP_TS:action_result.summary'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Link_back_dst_IP_to_artifact_record:condition_1:artifact:*.id', 'filtered-data:Link_back_dst_IP_to_artifact_record:condition_1:artifact:*.cef.destinationAddress'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]
    results_item_3_0 = [item[0] for item in results_data_3]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    ts_ip_reputation_threat_type = []
    for t in results_item_2_0:
        if t not in ts_ip_reputation_threat_type and t != None:
            ts_ip_reputation_threat_type.append(t)
    #phantom.debug('VT=' )
    #phantom.debug(results_item_1_0)
    #phantom.debug('TS=')
    #phantom.debug(results_item_2_0)
    
    if ts_ip_reputation_threat_type != [] or results_item_1_0[0] > 2:
        parameters = []

        cef_json = {"destinationAddress_malicious" : "True"}

        # build parameters list for 'update_artifact_2' call
        parameters.append({
            'artifact_id': filtered_artifacts_item_1_0[0],
            'name': "",
            'label': "",
            'severity': "",
            'cef_json': cef_json,
            'cef_types_json': "",
            'tags': "",
            'overwrite': "",
            'artifact_json': "",
        })

        phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_destinationAddress")

        parameters = []
        parameters.append({
            'artifact_id': filtered_artifacts_item_1_0[0],
            'add_tags': "indicator_malicious",
            'remove_tags': "",
        })

        phantom.act(action="update artifact tags", parameters=parameters, assets=['phantom asset'], name="update_artifact_tags")
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################
    join_filter_21(container=container)

    return

"""
Filter out requestURL
"""
def Filter_out_requestURL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_out_requestURL() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""],
        ],
        name="Filter_out_requestURL:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Check_if_requestURL_external(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Check if requestURL external
"""
def Check_if_requestURL_external(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_if_requestURL_external() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_requestURL:condition_1:artifact:*.cef.requestURL'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    Check_if_requestURL_external__requestURLExternal = None
    Check_if_requestURL_external__requestURLInternal = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    # ktbdomainlist = ["ktb.co.th" , "ktbcs.co.th"]
    success, message, ktburllist = phantom.get_list(list_name='ktburllist')
    
    urllist = filtered_artifacts_item_1_0
    externaltemplist = []
    internaltemplist = []
    for item in urllist:
        if not any(item in sublist for sublist in ktburllist):
            phantom.debug("{} is public".format(item))
            externaltemplist.append(item)
        else:
            phantom.debug("{} is private".format(item))
            internaltemplist.append(item)
            
    Check_if_requestURL_external__requestURLExternal = externaltemplist
    Check_if_requestURL_external__requestURLInternal = internaltemplist
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Check_if_requestURL_external:requestURLExternal', value=json.dumps(Check_if_requestURL_external__requestURLExternal))
    phantom.save_run_data(key='Check_if_requestURL_external:requestURLInternal', value=json.dumps(Check_if_requestURL_external__requestURLInternal))
    Check_if_requestURL_is_private(container=container)

    return

"""
Check if requestURL is private
"""
def Check_if_requestURL_is_private(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_if_requestURL_is_private() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_if_requestURL_external:custom_function:requestURLExternal", "!=", []],
        ],
        name="Check_if_requestURL_is_private:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_URL(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_if_requestURL_external:custom_function:requestURLInternal", "!=", []],
        ],
        name="Check_if_requestURL_is_private:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        Link_URL_to_artifact_record(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

"""
Format URL
"""
def Format_URL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_URL() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "Check_if_requestURL_external:custom_function:requestURLExternal",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_URL", separator=", ")

    URL_Reputation_VT(container=container)

    return

"""
URL Reputation VT
"""
def URL_Reputation_VT(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('URL_Reputation_VT() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'URL_Reputation_VT' call
    formatted_data_1 = phantom.get_format_data(name='Format_URL')

    parameters = []
    
    # build parameters list for 'URL_Reputation_VT' call
    parameters.append({
        'url': formatted_data_1,
    })

    phantom.act(action="url reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=URL_Reputation_TS, name="URL_Reputation_VT")

    return

"""
Link URL to artifact record
"""
def Link_URL_to_artifact_record(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Link_URL_to_artifact_record() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.requestURL", "in", "Check_if_requestURL_external:custom_function:requestURLInternal"],
        ],
        name="Link_URL_to_artifact_record:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Update_internal_requestURL_artifact(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Update internal requestURL artifact
"""
def Update_internal_requestURL_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Update_internal_requestURL_artifact() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Update_internal_requestURL_artifact' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Link_URL_to_artifact_record:condition_1:artifact:*.id', 'filtered-data:Link_URL_to_artifact_record:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'Update_internal_requestURL_artifact' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'name': "",
                'tags': "",
                'label': "",
                'cef_json': "{\"is_internalURL\": \"True\"}",
                'severity': "",
                'overwrite': "",
                'artifact_id': filtered_artifacts_item_1[0],
                'artifact_json': "",
                'cef_types_json': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="Update_internal_requestURL_artifact")

    return

"""
URL Reputation TS
"""
def URL_Reputation_TS(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('URL_Reputation_TS() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'URL_Reputation_TS' call
    results_data_1 = phantom.collect2(container=container, datapath=['URL_Reputation_VT:action_result.parameter.url', 'URL_Reputation_VT:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'URL_Reputation_TS' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'url': results_item_1[0],
                'limit': 1000,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="url reputation", parameters=parameters, assets=['threatstream cloud','threatstream hybrid vm'], callback=Link_back_requestURL_to_artifact_record, name="URL_Reputation_TS", parent_action=action)

    return

"""
Link back requestURL to artifact record
"""
def Link_back_requestURL_to_artifact_record(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Link_back_requestURL_to_artifact_record() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.requestURL", "in", "Check_if_requestURL_external:custom_function:requestURLExternal"],
        ],
        name="Link_back_requestURL_to_artifact_record:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Add_note_requestURL(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Add note requestURL
"""
def Add_note_requestURL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_requestURL() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['URL_Reputation_VT:action_result.summary.malicious'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['URL_Reputation_TS:action_result.data.*.threat_type'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Link_back_requestURL_to_artifact_record:condition_1:artifact:*.id', 'filtered-data:Link_back_requestURL_to_artifact_record:condition_1:artifact:*.cef.requestURL'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ts_reputation_threat_type = []
    for t in results_item_2_0:
        if t not in ts_reputation_threat_type and t != None:
            ts_reputation_threat_type.append(t)
    
    content = f"URL: `{filtered_artifacts_item_1_1[0]}`\n\n"
    content += f"**VirusTotal URL Reputation**\n" 
    content += f"- Malicious count: {results_item_1_0[0]}\n\n"
    content += f"- Summary: {'N/A' if results_item_1_0[0] == None else 'MALICIOUS' if results_item_1_0[0] > 2 else 'NON-MALICIOUS'}\n\n"
    
    content += f"**ThreatStream URL Repuation**\n"
    content += f"- Threat type: {', '.join(ts_reputation_threat_type) if ts_reputation_threat_type != [] else '-'}\n\n"
    content += f"- Summary: {'MALICIOUS' if len(ts_reputation_threat_type) > 0 else 'NON-MALICIOUS'}\n\n"
    
    note_title = "URL Investigation"
    note_content = content
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################
    Update_external_requestURL_artifact(container=container)

    return

"""
Update external requestURL artifact
"""
def Update_external_requestURL_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Update_external_requestURL_artifact() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['URL_Reputation_VT:action_result.summary.malicious'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['URL_Reputation_TS:action_result.data.*.threat_type'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Link_back_requestURL_to_artifact_record:condition_1:artifact:*.id', 'filtered-data:Link_back_requestURL_to_artifact_record:condition_1:artifact:*.cef.requestURL'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    ts_ip_reputation_threat_type = []
    for t in results_item_2_0:
        if t not in ts_ip_reputation_threat_type and t != None:
            ts_ip_reputation_threat_type.append(t)
            
    if ts_ip_reputation_threat_type != [] or (results_item_1_0[0] != None and results_item_1_0[0] > 2):
    
        parameters = []

        cef_json = {"requestURL_malicious" : "True"}

        # build parameters list for 'update_artifact_2' call
        parameters.append({
            'artifact_id': filtered_artifacts_item_1_0[0],
            'name': "",
            'label': "",
            'severity': "",
            'cef_json': cef_json,
            'cef_types_json': "",
            'tags': "",
            'overwrite': "",
            'artifact_json': "",
        })

        phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_requestURL")

        parameters = []
        parameters.append({
            'artifact_id': filtered_artifacts_item_1_0[0],
            'add_tags': "indicator_malicious",
            'remove_tags': "",
        })

        phantom.act(action="update artifact tags", parameters=parameters, assets=['phantom asset'], name="update_artifact_tags")
    
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################
    join_filter_21(container=container)

    return

"""
Filter out fileHash
"""
def Filter_out_fileHash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_out_fileHash() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.fileHash", "!=", ""],
        ],
        name="Filter_out_fileHash:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        File_reputation_VT(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
File reputation VT
"""
def File_reputation_VT(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('File_reputation_VT() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'File_reputation_VT' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_fileHash:condition_1:artifact:*.cef.fileHash', 'filtered-data:Filter_out_fileHash:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'File_reputation_VT' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'hash': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="file reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=File_reputation_TS, name="File_reputation_VT")

    return

"""
File reputation TS
"""
def File_reputation_TS(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('File_reputation_TS() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'File_reputation_TS' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['File_reputation_VT:artifact:*.cef.fileHash', 'File_reputation_VT:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'File_reputation_TS' call
    for inputs_item_1 in inputs_data_1:
        if inputs_item_1[0]:
            parameters.append({
                'hash': inputs_item_1[0],
                'limit': 1000,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': inputs_item_1[1]},
            })

    phantom.act(action="file reputation", parameters=parameters, assets=['threatstream cloud'], callback=Add_note_fileHash, name="File_reputation_TS", parent_action=action)

    return

"""
Add note fileHash
"""
def Add_note_fileHash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_fileHash() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['File_reputation_VT:action_result.summary.malicious'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['File_reputation_TS:action_result.data.*.threat_type'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_fileHash:condition_1:artifact:*.id', 'filtered-data:Filter_out_fileHash:condition_1:artifact:*.cef.fileHash'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    #content = "fileHash: " +  filtered_artifacts_item_1_1[0] +"\n" + "\n" + "VirusTotal File Reputation" +"\n" + "Summary Malicious: " + str(results_item_1_0[0]) +"\n" + "\n" + "ThreatStream File Repuation" +"\n" + "Summary: " + str(results_item_2_0[0])
    
    ts_reputation_threat_type = []
    for t in results_item_2_0:
        if t not in ts_reputation_threat_type and t != None:
            ts_reputation_threat_type.append(t)
    
    content = f"fileHash: {filtered_artifacts_item_1_1[0]}\n\n"
    content += f"**VirusTotal File Reputation**\n" 
    content += f"- Malicious count: {results_item_1_0[0]}\n\n"
    content += f"- Summary: {'MALICIOUS' if results_item_1_0[0] > 2 else 'NON-MALICIOUS'}\n\n"
    
    content += f"**ThreatStream File Repuation**\n"
    content += f"- Threat type: {', '.join(ts_reputation_threat_type) if ts_reputation_threat_type != [] else '-'}\n\n"
    content += f"- Summary: {'MALICIOUS' if len(ts_reputation_threat_type) > 0 else 'NON-MALICIOUS'}\n\n"

    note_title = "fileHash Investigation"
    note_content = content
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    ################################################################################
    ## Custom Code End
    ################################################################################
    Update_fileHash(container=container)

    return

"""
Update fileHash
"""
def Update_fileHash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Update_fileHash() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['File_reputation_VT:action_result.summary.malicious'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['File_reputation_TS:action_result.data.*.threat_type'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_fileHash:condition_1:artifact:*.id', 'filtered-data:Filter_out_fileHash:condition_1:artifact:*.cef.fileHash'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    ts_reputation_threat_type = []
    for t in results_item_2_0:
        if t not in ts_reputation_threat_type and t != None:
            ts_reputation_threat_type.append(t)
    
    if ts_reputation_threat_type != [] or results_item_1_0[0] > 2:
    
        parameters = []

        cef_json = {"fileHash_malicious" : "True"}

        # build parameters list for 'update_artifact_2' call
        parameters.append({
            'artifact_id': filtered_artifacts_item_1_0[0],
            'name': "",
            'label': "",
            'severity': "",
            'cef_json': cef_json,
            'cef_types_json': "",
            'tags': "",
            'overwrite': "",
            'artifact_json': "",
        })

        phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_fileHash")

        parameters = []
        parameters.append({
            'artifact_id': filtered_artifacts_item_1_0[0],
            'add_tags': "indicator_malicious",
            'remove_tags': "",
        })

        phantom.act(action="update artifact tags", parameters=parameters, assets=['phantom asset'], name="update_artifact_tags")

    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################
    join_filter_21(container=container)

    return

"""
Filter out destinationDnsDomain
"""
def Filter_out_destinationDnsDomain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_out_destinationDnsDomain() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationDnsDomain", "!=", ""],
        ],
        name="Filter_out_destinationDnsDomain:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Check_if_destinationDnsDomain_external(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Check if destinationDnsDomain external
"""
def Check_if_destinationDnsDomain_external(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_if_destinationDnsDomain_external() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_destinationDnsDomain:condition_1:artifact:*.cef.destinationDnsDomain'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    Check_if_destinationDnsDomain_external__destinationDnsDomainExternal = None
    Check_if_destinationDnsDomain_external__destinationDnsDomainInternal = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    success, message, ktbdomainlist = phantom.get_list(list_name='ktbdomainlist')
    
    domainlist = filtered_artifacts_item_1_0
    externaltemplist = []
    internaltemplist = []
    phantom.debug(ktbdomainlist)
    for item in domainlist:
        if not any(item in sublist for sublist in ktbdomainlist):
            phantom.debug("{} is public".format(item))
            externaltemplist.append(item)
        else:
            phantom.debug("{} is private".format(item))
            internaltemplist.append(item)
            
    Check_if_destinationDnsDomain_external__destinationDnsDomainExternal = externaltemplist
    Check_if_destinationDnsDomain_external__destinationDnsDomainInternal = internaltemplist
    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Check_if_destinationDnsDomain_external:destinationDnsDomainExternal', value=json.dumps(Check_if_destinationDnsDomain_external__destinationDnsDomainExternal))
    phantom.save_run_data(key='Check_if_destinationDnsDomain_external:destinationDnsDomainInternal', value=json.dumps(Check_if_destinationDnsDomain_external__destinationDnsDomainInternal))
    Check_if_destinationDnsDomain_is_private(container=container)

    return

"""
Check if destinationDnsDomain is private
"""
def Check_if_destinationDnsDomain_is_private(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_if_destinationDnsDomain_is_private() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_if_destinationDnsDomain_external:custom_function:destinationDnsDomainExternal", "!=", []],
        ],
        name="Check_if_destinationDnsDomain_is_private:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_domain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_if_destinationDnsDomain_external:custom_function:destinationDnsDomainInternal", "!=", []],
        ],
        name="Check_if_destinationDnsDomain_is_private:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        Link_domain_to_artifact_record(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

"""
Format domain
"""
def Format_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_domain() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "Check_if_destinationDnsDomain_external:custom_function:destinationDnsDomainExternal",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_domain", separator=", ")

    Domain_Reputation_VT(container=container)

    return

"""
Domain Reputation VT
"""
def Domain_Reputation_VT(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Domain_Reputation_VT() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Domain_Reputation_VT' call
    formatted_data_1 = phantom.get_format_data(name='Format_domain')

    parameters = []
    
    # build parameters list for 'Domain_Reputation_VT' call
    parameters.append({
        'domain': formatted_data_1,
    })

    phantom.act(action="domain reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=Domain_Reputation_TS, name="Domain_Reputation_VT")

    return

"""
Domain Reputation TS
"""
def Domain_Reputation_TS(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Domain_Reputation_TS() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Domain_Reputation_TS' call
    results_data_1 = phantom.collect2(container=container, datapath=['Domain_Reputation_VT:action_result.parameter.domain', 'Domain_Reputation_VT:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'Domain_Reputation_TS' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'limit': 1000,
                'domain': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="domain reputation", parameters=parameters, assets=['threatstream cloud','threatstream hybrid vm'], callback=Domain_Reputation_UBL, name="Domain_Reputation_TS", parent_action=action)

    return

"""
Link back destinationDnsDoman to artifact record
"""
def Link_back_destinationDnsDoman_to_artifac(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Link_back_destinationDnsDoman_to_artifac() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationDnsDomain", "in", "Check_if_destinationDnsDomain_external:custom_function:destinationDnsDomainExternal"],
        ],
        name="Link_back_destinationDnsDoman_to_artifac:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Add_note_destinationDnsDomain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Add note destinationDnsDomain
"""
def Add_note_destinationDnsDomain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_destinationDnsDomain() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['Domain_Reputation_VT:action_result.summary.malicious'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['Domain_Reputation_TS:action_result.data.*.threat_type'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['Domain_Reputation_UBL:action_result.summary.domain_status'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Link_back_destinationDnsDoman_to_artifac:condition_1:artifact:*.id', 'filtered-data:Link_back_destinationDnsDoman_to_artifac:condition_1:artifact:*.cef.destinationDnsDomain'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]
    results_item_3_0 = [item[0] for item in results_data_3]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    #content = "Domain: " +  filtered_artifacts_item_1_1[0] +"\n" + "\n" + "VirusTotal Domain Reputation" +"\n" + "Summary Malicious: " + str(results_item_1_0[0]) +"\n" + "\n" + "ThreatStream Domain Repuation" +"\n" + "Summary: " + str(results_item_2_0[0]) +"\n" + "\n" + "Umbrella Domain Reputation" +"\n" + "Domain status: " + str(results_item_3_0[0]) 

    ts_reputation_threat_type = []
    for t in results_item_2_0:
        if t not in ts_reputation_threat_type and t != None:
            ts_reputation_threat_type.append(t)
            
    content = f"Domain: {filtered_artifacts_item_1_1[0]}\n\n"
    content += f"**VirusTotal Domain Reputation**\n" 
    content += f"- Malicious count: {results_item_1_0[0]}\n\n"
    content += f"- Summary: {'N/A' if results_item_1_0[0] == None else 'MALICIOUS' if results_item_1_0[0] > 2 else 'NON-MALICIOUS'}\n\n"
    
    content += f"**ThreatStream Domain Repuation**\n"
    content += f"- Threat type: {', '.join(ts_reputation_threat_type) if ts_reputation_threat_type != [] else '-'}\n\n"
    content += f"- Summary: {'MALICIOUS' if len(ts_reputation_threat_type) > 0 else 'NON-MALICIOUS'}\n\n"
    
    content += f"**Umbrella Domain Reputation**\n"
    content += f"- Summary: {results_item_3_0[0] if results_item_3_0[0] else '-'}"
    
    note_title = "Domain Investigation"
    note_content = content
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################
    Update_external_destinationDnsDomain_art(container=container)

    return

"""
Update external destinationDnsDomain artifact
"""
def Update_external_destinationDnsDomain_art(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Update_external_destinationDnsDomain_art() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['Domain_Reputation_VT:action_result.summary.malicious'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['Domain_Reputation_TS:action_result.data.*.threat_type'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['Domain_Reputation_UBL:action_result.summary.domain_status'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Link_back_destinationDnsDoman_to_artifac:condition_1:artifact:*.id', 'filtered-data:Link_back_destinationDnsDoman_to_artifac:condition_1:artifact:*.cef.destinationDnsDomain'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]
    results_item_3_0 = [item[0] for item in results_data_3]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    phantom.debug(results_item_2_0)
    ts_ip_reputation_threat_type = []
    for t in results_item_2_0:
        if t not in ts_ip_reputation_threat_type and t != None:
            ts_ip_reputation_threat_type.append(t)
    
    phantom.debug(ts_ip_reputation_threat_type)
    
    if ts_ip_reputation_threat_type != [] or (results_item_1_0[0] != None and results_item_1_0[0] > 2) or results_item_3_0[0] == "MALICIOUS":
        parameters = []

        cef_json = {"destinationDnsDomain_malicious" : "True"}

        # build parameters list for 'update_artifact_2' call
        parameters.append({
            'artifact_id': filtered_artifacts_item_1_0[0],
            'name': "",
            'label': "",
            'severity': "",
            'cef_json': cef_json,
            'cef_types_json': "",
            'tags': "",
            'overwrite': "",
            'artifact_json': "",
        })

        phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_destinationDnsDomain")

        parameters = []
        parameters.append({
            'artifact_id': filtered_artifacts_item_1_0[0],
            'add_tags': "indicator_malicious",
            'remove_tags': "",
        })

        phantom.act(action="update artifact tags", parameters=parameters, assets=['phantom asset'], name="update_artifact_tags")
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################
    join_filter_21(container=container)

    return

"""
Link domain to artifact record
"""
def Link_domain_to_artifact_record(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Link_domain_to_artifact_record() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationDnsDomain", "in", "Check_if_destinationDnsDomain_external:custom_function:destinationDnsDomainInternal"],
        ],
        name="Link_domain_to_artifact_record:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Update_internal_destinationDnsDomain_art(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Update internal destinationDnsDomain artifact
"""
def Update_internal_destinationDnsDomain_art(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Update_internal_destinationDnsDomain_art() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Update_internal_destinationDnsDomain_art' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Link_domain_to_artifact_record:condition_1:artifact:*.id', 'filtered-data:Link_domain_to_artifact_record:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'Update_internal_destinationDnsDomain_art' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'name': "",
                'tags': "",
                'label': "",
                'cef_json': "{\"is_internalDomain\": \"True\"}",
                'severity': "",
                'overwrite': "",
                'artifact_id': filtered_artifacts_item_1[0],
                'artifact_json': "",
                'cef_types_json': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="Update_internal_destinationDnsDomain_art")

    return

def filter_21(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_21() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            [1, "==", 1],
        ],
        name="filter_21:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pass

    return

def join_filter_21(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_filter_21() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['WhoIS_dst_IP_TS', 'IP_Reputation_dst_IP_TS', 'WhoIS_src_IP_TS', 'IP_Reputation_src_IP_TS', 'Domain_Reputation_UBL', 'URL_Reputation_TS', 'File_reputation_TS', 'IP_Reputation_Host_TS', 'WhoIS_Host_IP_TS', 'FQDN_Reputation_UBL', 'Email_reputation_TS']):
        
        # call connected block "filter_21"
        filter_21(container=container, handle=handle)
    
    return

def filter_22(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_22() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationHostName", "!=", ""],
        ],
        name="filter_22:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_data_for_kaspersky_query_on_hostn(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        Format_data_for_amp_query_on_hostname(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        Format_data_for_mcafee_query_on_hostname(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Format data for kaspersky query on hostname
"""
def Format_data_for_kaspersky_query_on_hostn(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_data_for_kaspersky_query_on_hostn() called')
    
    template = """earliest = -7d@d index=ktb_mgmt_default sourcetype =\"kaspersky:klprci\"| search identNetBios= {0}
| sort 0 - _time
| eval time = _time
|convert timeformat=\"%d-%m-%Y %H:%M:%S\" ctime(time) AS time
| table time,identNetBios,src
| dedup identNetBios,src"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_22:condition_1:artifact:*.cef.destinationHostName",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_data_for_kaspersky_query_on_hostn", separator=", ")

    Run_kaspersky_query_on_hostname(container=container)

    return

"""
Run kaspersky query on hostname
"""
def Run_kaspersky_query_on_hostname(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Run_kaspersky_query_on_hostname() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Run_kaspersky_query_on_hostname' call
    formatted_data_1 = phantom.get_format_data(name='Format_data_for_kaspersky_query_on_hostn')

    parameters = []
    
    # build parameters list for 'Run_kaspersky_query_on_hostname' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=join_Extract_address_of_hostname, name="Run_kaspersky_query_on_hostname")

    return

"""
Extract address of hostname
"""
def Extract_address_of_hostname(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Extract_address_of_hostname() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['Run_kaspersky_query_on_hostname:action_result.data.*.time', 'Run_kaspersky_query_on_hostname:action_result.data.*.src'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['Run_amp_query_on_hostname:action_result.data.*.time', 'Run_amp_query_on_hostname:action_result.data.*.ip'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['Run_mcafee_query_on_hostname:action_result.data.*.time', 'Run_mcafee_query_on_hostname:action_result.data.*.dest_ip'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_1_1 = [item[1] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]
    results_item_2_1 = [item[1] for item in results_data_2]
    results_item_3_0 = [item[0] for item in results_data_3]
    results_item_3_1 = [item[1] for item in results_data_3]

    Extract_address_of_hostname__ListAddressExternal = None
    Extract_address_of_hostname__ListAddressInternal = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    import ipaddress
    from datetime import datetime
    
    private_ip_address_list = []
    public_ip_address_list = []
    
    latest_time = None
    latest_ip = None

    kaspersky_time = datetime.strptime(results_item_1_0[0], "%d-%m-%Y %H:%M:%S") if results_item_1_0[0] else None
    kaspersky_ip = results_item_1_1[0] if results_item_1_1[0] else None
    amp_time = datetime.strptime(results_item_2_0[0], "%d-%m-%Y %H:%M:%S") if results_item_2_0[0] else None
    amp_ip = results_item_2_1[0] if results_item_2_1[0] else None
    mcafee_time = datetime.strptime(results_item_3_0[0], "%d-%m-%Y %H:%M:%S") if results_item_3_0[0] else None
    mcafee_ip = results_item_3_1[0] if results_item_3_1[0] else None
        
    # Get latest IP
    if kaspersky_time != None and (latest_time == None or kaspersky_time > latest_time):
        latest_time = kaspersky_time
        latest_ip = kaspersky_ip
    if amp_time != None and (latest_time == None or amp_time > latest_time):
        latest_time = amp_time
        latest_ip = amp_ip
    if mcafee_time != None and (latest_time == None or mcafee_time > latest_time):
        latest_time = mcafee_time
        latest_ip = mcafee_ip
        
    phantom.debug(f"latest_time: {latest_time}")
    phantom.debug(f"latest_ip: {latest_ip}")
    
    if latest_ip:
        try:
            ip = latest_ip
            if ipaddress.ip_address(ip).is_private:
                if ip not in private_ip_address_list:
                    private_ip_address_list.append(ip)
            else:
                if ip not in public_ip_address_list:
                    public_ip_address_list.append(ip)
        except ValueError:
            pass
    
    Extract_address_of_hostname__ListAddressExternal = public_ip_address_list
    Extract_address_of_hostname__ListAddressInternal = private_ip_address_list
    phantom.debug(f"private_ip_address_list: {private_ip_address_list}")
    phantom.debug(f"public_ip_address_list: {public_ip_address_list}")

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Extract_address_of_hostname:ListAddressExternal', value=json.dumps(Extract_address_of_hostname__ListAddressExternal))
    phantom.save_run_data(key='Extract_address_of_hostname:ListAddressInternal', value=json.dumps(Extract_address_of_hostname__ListAddressInternal))
    filter_23(container=container)

    return

def join_Extract_address_of_hostname(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_Extract_address_of_hostname() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['Run_kaspersky_query_on_hostname', 'Run_amp_query_on_hostname', 'Run_mcafee_query_on_hostname']):
        
        # call connected block "Extract_address_of_hostname"
        Extract_address_of_hostname(container=container, handle=handle)
    
    return

def filter_23(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_23() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Extract_address_of_hostname:custom_function:ListAddressExternal", "!=", []],
        ],
        name="filter_23:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        IP_Reputation_Host_VT(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        WhoIS_Host_IP_TS(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Extract_address_of_hostname:custom_function:ListAddressInternal", "!=", []],
        ],
        name="filter_23:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        Add_note_details_on_internal_hostname(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

"""
IP Reputation Host VT
"""
def IP_Reputation_Host_VT(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('IP_Reputation_Host_VT() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    Extract_address_of_hostname__ListAddressExternal = json.loads(phantom.get_run_data(key='Extract_address_of_hostname:ListAddressExternal'))
    # collect data for 'IP_Reputation_Host_VT' call
    last_index = len(Extract_address_of_hostname__ListAddressExternal) - 1
    for i, ip in enumerate(Extract_address_of_hostname__ListAddressExternal):
        parameters = []
        # build parameters list for 'IP_Reputation_Host_VT' call
        parameters.append({
            'ip': ip,
        })
        if i < last_index:
            phantom.act(action="ip reputation", parameters=parameters, assets=['virustotal v3 asset'], name=f"IP_Reputation_Host_VT_{i}")
        else:
            phantom.act(action="ip reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=IP_Reputation_Host_TS, name=f"IP_Reputation_Host_VT_{i}")

    return

"""
IP Reputation Host TS
"""
def IP_Reputation_Host_TS(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('IP_Reputation_Host_TS() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    Extract_address_of_hostname__ListAddressExternal = json.loads(phantom.get_run_data(key='Extract_address_of_hostname:ListAddressExternal'))
    # collect data for 'IP_Reputation_Host_TS' call

    for i, ip in enumerate(Extract_address_of_hostname__ListAddressExternal):
        parameters = []
        # build parameters list for 'IP_Reputation_Host_TS' call
        parameters.append({
            'ip': ip,
            'limit': 1000,
        })
        phantom.act(action="ip reputation", parameters=parameters, assets=['threatstream cloud','threatstream hybrid vm'], callback=join_filter_24, name=f"IP_Reputation_Host_TS_{i}", parent_action=action)

    return

"""
WhoIS Host IP TS
"""
def WhoIS_Host_IP_TS(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('WhoIS_Host_IP_TS() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    Extract_address_of_hostname__ListAddressExternal = json.loads(phantom.get_run_data(key='Extract_address_of_hostname:ListAddressExternal'))
    # collect data for 'WhoIS_Host_IP_TS' call
    
    for i, ip in enumerate(Extract_address_of_hostname__ListAddressExternal):
        parameters = []
        # build parameters list for 'WhoIS_Host_IP_TS' call
        parameters.append({
           'ip': ip,
        })

        phantom.act(action="whois ip", parameters=parameters, assets=['threatstream cloud','threatstream hybrid vm'], callback=join_filter_24, name=f"WhoIS_Host_IP_TS_{i}")

    return

def filter_24(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_24() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationHostName", "!=", ""],
        ],
        name="filter_24:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Add_note_hostname(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def join_filter_24(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_filter_24() called')
    Extract_address_of_hostname__ListAddressExternal = json.loads(phantom.get_run_data(key='Extract_address_of_hostname:ListAddressExternal'))
    number_of_address = len(Extract_address_of_hostname__ListAddressExternal)
    phantom.debug(f'Number of ExtIP: {number_of_address}')
    phantom.debug(Extract_address_of_hostname__ListAddressExternal)
    custom_action_list = [f"IP_Reputation_Host_TS_{i}" for i in range(number_of_address)] + [f"WhoIS_Host_IP_TS_{i}" for i in range(number_of_address)]
    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    #if phantom.completed(action_names=['IP_Reputation_Host_TS', 'WhoIS_Host_IP_TS']):
    if phantom.completed(action_names=custom_action_list): 
        
        # call connected block "filter_24"
        filter_24(container=container, handle=handle)
    
    return

"""
Add note hostname
"""
def Add_note_hostname(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_hostname() called')
    
    Extract_address_of_hostname__ListAddressExternal = json.loads(phantom.get_run_data(key='Extract_address_of_hostname:ListAddressExternal'))
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_22:condition_1:artifact:*.id', 'filtered-data:filter_22:condition_1:artifact:*.cef.destinationHostName'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    # phantom.debug("ADD NOTE HOSTNAME: Collecting result>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
    content = f"### Hostname: {filtered_artifacts_item_1_1[0]}\n\n"
    for i, ip in enumerate(Extract_address_of_hostname__ListAddressExternal): 
        results_data_1 = phantom.collect2(container=container, datapath=[f'IP_Reputation_Host_VT_{i}:action_result.summary.malicious'], action_results=results)
        results_data_2 = phantom.collect2(container=container, datapath=[f'IP_Reputation_Host_TS_{i}:action_result.data.*.threat_type'], action_results=results)
        results_data_3 = phantom.collect2(container=container, datapath=[f'WhoIS_Host_IP_TS_{i}:action_result.summary'], action_results=results)
        results_item_1_0 = [item[0] for item in results_data_1]
        results_item_2_0 = [item[0] for item in results_data_2]
        results_item_3_0 = [item[0] for item in results_data_3]
        ts_reputation_threat_type = []
        for t in results_item_2_0:
            if t not in ts_reputation_threat_type and t != None:
                ts_reputation_threat_type.append(t)
                
        content += f"**IP address: {ip}**\n\n"
        content += f"VirusTotal IP Reputation\n" 
        content += f"- Malicious count: {results_item_1_0[0]}\n\n"
        content += f"- Summary: {'MALICIOUS' if results_item_1_0[0] > 2 else 'NON-MALICIOUS'}\n\n"
        
        content += f"ThreatStream IP Repuation\n"
        content += f"- Threat type: {', '.join(ts_reputation_threat_type) if ts_reputation_threat_type != [] else '-'}\n\n"
        content += f"- Summary: {'MALICIOUS' if len(ts_reputation_threat_type) > 0 else 'NON-MALICIOUS'}\n\n"
        
        content += f"WhoIS IP\n"
        content += f"- Summary: {results_item_3_0[0] if results_item_3_0[0] != {} else '-'}\n\n"
        content += "---\n\n"
    
    #content = "Destination IP address: " +  filtered_artifacts_item_1_1[0] +"\n" + "\n" + "VirusTotal IP Reputation" +"\n" + "Summary Detected URLs: " + str(results_item_1_0[0]) +"\n" + "\n" + "ThreatStream IP Repuation" +"\n" + "Summary: " + str(results_item_2_0[0]) + "\n" + "\n" + "WhoIS IP" +"\n" + "Summary: " + str(results_item_3_0[0])
    
    note_title = "Hostname Investigation"
    note_content = content
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    ################################################################################
    ## Custom Code End
    ################################################################################
    Update_hostname_artifact(container=container)

    return

"""
Update hostname artifact
"""
def Update_hostname_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Update_hostname_artifact() called')
    
    Extract_address_of_hostname__ListAddressExternal = json.loads(phantom.get_run_data(key='Extract_address_of_hostname:ListAddressExternal'))
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_22:condition_1:artifact:*.id', 'filtered-data:filter_22:condition_1:artifact:*.cef.destinationHostName'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    phantom.debug("UPDATE HOSTNAME ARTIFACT: Collecting result>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
    is_malicious = False
    #phantom.debug(Extract_address_of_hostname__ListAddressExternal)
    for i, ip in enumerate(Extract_address_of_hostname__ListAddressExternal): 
        results_data_1 = phantom.collect2(container=container, datapath=[f'IP_Reputation_Host_VT_{i}:action_result.summary.malicious'], action_results=results)
        results_data_2 = phantom.collect2(container=container, datapath=[f'IP_Reputation_Host_TS_{i}:action_result.data.*.threat_type'], action_results=results)
        results_data_3 = phantom.collect2(container=container, datapath=[f'WhoIS_Host_IP_TS_{i}:action_result.summary'], action_results=results)
        results_item_1_0 = [item[0] for item in results_data_1]
        results_item_2_0 = [item[0] for item in results_data_2]
        results_item_3_0 = [item[0] for item in results_data_3]

        ts_ip_reputation_threat_type = []
        for t in results_item_2_0:
            if t not in ts_ip_reputation_threat_type and t != None:
                ts_ip_reputation_threat_type.append(t)

        if ts_ip_reputation_threat_type != [] or results_item_1_0[0] > 2:
            is_malicious = True
            break
    
    phantom.debug(f"is_malicious: {is_malicious}")
    if is_malicious:
        parameters = []
        cef_json = {"destinationHostName_malicious" : "True"}

        # build parameters list for 'update_artifact_2' call
        parameters.append({
            'artifact_id': filtered_artifacts_item_1_0[0],
            'name': "",
            'label': "",
            'severity': "",
            'cef_json': cef_json,
            'cef_types_json': "",
            'tags': "",
            'overwrite': "",
            'artifact_json': "",
        })

        phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_hostname")

        parameters = []
        parameters.append({
            'artifact_id': filtered_artifacts_item_1_0[0],
            'add_tags': "indicator_malicious",
            'remove_tags': "",
        })

        phantom.act(action="update artifact tags", parameters=parameters, assets=['phantom asset'], name="update_artifact_tags")
            
    ########
    ########
    ########
    ########
    ########
    ########
    ########
    ########
    ########
    ################################################################################
    ## Custom Code End
    ################################################################################
    join_filter_21(container=container)

    return

"""
Add note details on internal hostname
"""
def Add_note_details_on_internal_hostname(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_details_on_internal_hostname() called')
    
    Extract_address_of_hostname__ListAddressInternal = json.loads(phantom.get_run_data(key='Extract_address_of_hostname:ListAddressInternal'))
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_22:condition_1:artifact:*.cef.destinationHostName'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    if  Extract_address_of_hostname__ListAddressInternal != []:
        content = f"Hostname: {filtered_artifacts_item_1_0[0]}\n\n" 
        content += "Internal IP address found: \n\n" 
        for ip in Extract_address_of_hostname__ListAddressInternal:
            content += f"- {ip}\n"

        note_title = "Hostname Internal Address Investigation"
        note_content = content
        note_format = "markdown"
        phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return

"""
Domain Reputation UBL
"""
def Domain_Reputation_UBL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Domain_Reputation_UBL() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Domain_Reputation_UBL' call
    formatted_data_1 = phantom.get_format_data(name='Format_domain')

    parameters = []
    
    # build parameters list for 'Domain_Reputation_UBL' call
    parameters.append({
        'domain': formatted_data_1,
    })

    phantom.act(action="domain reputation", parameters=parameters, assets=['ktb-umbrella-asset'], callback=Link_back_destinationDnsDoman_to_artifac, name="Domain_Reputation_UBL", parent_action=action)

    return

"""
Filter out destinationDnsFQDN
"""
def Filter_out_destinationDnsFQDN(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_out_destinationDnsFQDN() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationDnsFQDN", "!=", ""],
        ],
        name="Filter_out_destinationDnsFQDN:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Check_if_destinationDnsFQDN_external(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Check_if_destinationDnsFQDN_external(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_if_destinationDnsFQDN_external() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_destinationDnsFQDN:condition_1:artifact:*.cef.destinationDnsFQDN'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    Check_if_destinationDnsFQDN_external__destinationDnsFQDNExternal = None
    Check_if_destinationDnsFQDN_external__destinationDnsFQDNInternal = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    success, message, ktbdomainlist = phantom.get_list(list_name='ktbfqdnlist')

    domainlist = filtered_artifacts_item_1_0
    externaltemplist = []
    internaltemplist = []
    phantom.debug(ktbdomainlist)
    for item in domainlist:
        if not any(item in sublist for sublist in ktbdomainlist):
            phantom.debug("{} is public".format(item))
            externaltemplist.append(item)
        else:
            phantom.debug("{} is private".format(item))
            internaltemplist.append(item)
            
    Check_if_destinationDnsFQDN_external__destinationDnsFQDNExternal = externaltemplist
    Check_if_destinationDnsFQDN_external__destinationDnsFQDNInternal = internaltemplist

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Check_if_destinationDnsFQDN_external:destinationDnsFQDNExternal', value=json.dumps(Check_if_destinationDnsFQDN_external__destinationDnsFQDNExternal))
    phantom.save_run_data(key='Check_if_destinationDnsFQDN_external:destinationDnsFQDNInternal', value=json.dumps(Check_if_destinationDnsFQDN_external__destinationDnsFQDNInternal))
    filter_26(container=container)

    return

def filter_26(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_26() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_if_destinationDnsFQDN_external:custom_function:destinationDnsFQDNExternal", "!=", []],
        ],
        name="filter_26:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_FQDN(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_if_destinationDnsFQDN_external:custom_function:destinationDnsFQDNInternal", "!=", []],
        ],
        name="filter_26:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        Link_FQDN_to_artifact_record(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

"""
Format FQDN
"""
def Format_FQDN(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_FQDN() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "Check_if_destinationDnsFQDN_external:custom_function:destinationDnsFQDNExternal",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_FQDN", separator=", ")

    FQDN_Reputation_VT(container=container)

    return

"""
FQDN Reputation VT
"""
def FQDN_Reputation_VT(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('FQDN_Reputation_VT() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'FQDN_Reputation_VT' call
    formatted_data_1 = phantom.get_format_data(name='Format_FQDN')

    parameters = []
    
    # build parameters list for 'FQDN_Reputation_VT' call
    parameters.append({
        'domain': formatted_data_1,
    })

    phantom.act(action="domain reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=FQDN_Reputation_TS, name="FQDN_Reputation_VT")

    return

"""
FQDN Reputation TS
"""
def FQDN_Reputation_TS(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('FQDN_Reputation_TS() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'FQDN_Reputation_TS' call
    formatted_data_1 = phantom.get_format_data(name='Format_FQDN')

    parameters = []
    
    # build parameters list for 'FQDN_Reputation_TS' call
    parameters.append({
        'limit': 1000,
        'domain': formatted_data_1,
    })

    phantom.act(action="domain reputation", parameters=parameters, assets=['threatstream cloud','threatstream hybrid vm'], callback=FQDN_Reputation_UBL, name="FQDN_Reputation_TS", parent_action=action)

    return

"""
FQDN Reputation UBL
"""
def FQDN_Reputation_UBL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('FQDN_Reputation_UBL() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'FQDN_Reputation_UBL' call
    formatted_data_1 = phantom.get_format_data(name='Format_FQDN')

    parameters = []
    
    # build parameters list for 'FQDN_Reputation_UBL' call
    parameters.append({
        'domain': formatted_data_1,
    })

    phantom.act(action="domain reputation", parameters=parameters, assets=['ktb-umbrella-asset'], callback=Link_back_destinationDnsFQDN_to_artifact, name="FQDN_Reputation_UBL", parent_action=action)

    return

"""
Link back destinationDnsFQDN to artifact
"""
def Link_back_destinationDnsFQDN_to_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Link_back_destinationDnsFQDN_to_artifact() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationDnsFQDN", "in", "Check_if_destinationDnsFQDN_external:custom_function:destinationDnsFQDNExternal"],
        ],
        name="Link_back_destinationDnsFQDN_to_artifact:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Add_note_destinationDnsFQDN(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Add note destinationDnsFQDN
"""
def Add_note_destinationDnsFQDN(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_destinationDnsFQDN() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['FQDN_Reputation_VT:action_result.summary.malicious'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['FQDN_Reputation_TS:action_result.data.*.threat_type'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['FQDN_Reputation_UBL:action_result.summary.domain_status'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Link_back_destinationDnsFQDN_to_artifact:condition_1:artifact:*.id', 'filtered-data:Link_back_destinationDnsFQDN_to_artifact:condition_1:artifact:*.cef.destinationDnsFQDN'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]
    results_item_3_0 = [item[0] for item in results_data_3]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # content = "FQDN: " +  filtered_artifacts_item_1_1[0] +"\n" + "\n" + "VirusTotal FQDN Reputation" +"\n" + "Summary Malicious: " + str(results_item_1_0[0]) +"\n" + "\n" + "ThreatStream FQDN Repuation" +"\n" + "Summary: " + str(results_item_2_0[0]) +"\n" + "\n" + "Umbrella FQDN Reputation" +"\n" + "FQDN status: " + str(results_item_3_0[0]) 
    
    ts_reputation_threat_type = []
    for t in results_item_2_0:
        if t not in ts_reputation_threat_type and t != None:
            ts_reputation_threat_type.append(t)
            
    content = f"FQDN: {filtered_artifacts_item_1_1[0]}\n\n"
    content += f"**VirusTotal FQDN Reputation**\n" 
    content += f"- Malicious count: {results_item_1_0[0]}\n\n"
    content += f"- Summary: {'N/A' if results_item_1_0[0] == None else 'MALICIOUS' if results_item_1_0[0] > 2 else 'NON-MALICIOUS'}\n\n"
    
    content += f"**ThreatStream FQDN Repuation**\n"
    content += f"- Threat type: {', '.join(ts_reputation_threat_type) if ts_reputation_threat_type != [] else '-'}\n\n"
    content += f"- Summary: {'MALICIOUS' if len(ts_reputation_threat_type) > 0 else 'NON-MALICIOUS'}\n\n"
    
    content += f"**Umbrella FQDN Reputation**\n"
    content += f"- Summary: {results_item_3_0[0] if results_item_3_0[0] else '-'}"
    
    note_title = "FQDN Investigation"
    note_content = content
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    ################################################################################
    ## Custom Code End
    ################################################################################
    Update_external_destinationDnsFQDN_artif(container=container)

    return

"""
Update external destinationDnsFQDN artif
"""
def Update_external_destinationDnsFQDN_artif(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Update_external_destinationDnsFQDN_artif() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['FQDN_Reputation_VT:action_result.summary.malicious'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['FQDN_Reputation_TS:action_result.data.*.threat_type'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['FQDN_Reputation_UBL:action_result.summary.domain_status'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Link_back_destinationDnsFQDN_to_artifact:condition_1:artifact:*.id', 'filtered-data:Link_back_destinationDnsFQDN_to_artifact:condition_1:artifact:*.cef.destinationDnsFQDN'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]
    results_item_3_0 = [item[0] for item in results_data_3]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    phantom.debug(results_item_3_0[0])
    ts_ip_reputation_threat_type = []
    for t in results_item_2_0:
        if t not in ts_ip_reputation_threat_type and t != None:
            ts_ip_reputation_threat_type.append(t)
    
    if ts_ip_reputation_threat_type != [] or (results_item_1_0[0] != None and results_item_1_0[0] > 2) or results_item_3_0[0] == "MALICIOUS":
        parameters = []

        cef_json = {"destinationDnsFQDN_malicious" : "True"}

        # build parameters list for 'update_artifact_2' call
        parameters.append({
            'artifact_id': filtered_artifacts_item_1_0[0],
            'name': "",
            'label': "",
            'severity': "",
            'cef_json': cef_json,
            'cef_types_json': "",
            'tags': "",
            'overwrite': "",
            'artifact_json': "",
        })

        phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_destinationDnsFQDN")

        parameters = []
        parameters.append({
            'artifact_id': filtered_artifacts_item_1_0[0],
            'add_tags': "indicator_malicious",
            'remove_tags': "",
        })

        phantom.act(action="update artifact tags", parameters=parameters, assets=['phantom asset'], name="update_artifact_tags")

    ################################################################################
    ## Custom Code End
    ################################################################################
    join_filter_21(container=container)

    return

"""
Link FQDN to artifact record
"""
def Link_FQDN_to_artifact_record(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Link_FQDN_to_artifact_record() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationDnsFQDN", "in", "Check_if_destinationDnsFQDN_external:custom_function:destinationDnsFQDNInternal"],
        ],
        name="Link_FQDN_to_artifact_record:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Update_internal_destinationDnsFQDN_artif(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Update internal destinationDnsFQDN artifact
"""
def Update_internal_destinationDnsFQDN_artif(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Update_internal_destinationDnsFQDN_artif() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Update_internal_destinationDnsFQDN_artif' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Link_FQDN_to_artifact_record:condition_1:artifact:*.id', 'filtered-data:Link_FQDN_to_artifact_record:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'Update_internal_destinationDnsFQDN_artif' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'name': "",
                'tags': "",
                'label': "",
                'cef_json': "{\"is_internalFQDN\": \"True\"}",
                'severity': "",
                'overwrite': "",
                'artifact_id': filtered_artifacts_item_1[0],
                'artifact_json': "",
                'cef_types_json': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="Update_internal_destinationDnsFQDN_artif")

    return

"""
Filter out user_email
"""
def Filter_out_user_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_out_user_email() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.user_email", "!=", ""],
        ],
        name="Filter_out_user_email:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Email_reputation_TS(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Email_reputation_TS(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Email_reputation_TS() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Email_reputation_TS' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_user_email:condition_1:artifact:*.cef.user_email', 'filtered-data:Filter_out_user_email:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'Email_reputation_TS' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'email': filtered_artifacts_item_1[0],
                'limit': 1000,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="email reputation", parameters=parameters, assets=['threatstream cloud','threatstream hybrid vm'], callback=Add_note_user_email, name="Email_reputation_TS")

    return

"""
Add note user_email
"""
def Add_note_user_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_user_email() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['Email_reputation_TS:action_result.data.*.threat_type'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_user_email:condition_1:artifact:*.id', 'filtered-data:Filter_out_user_email:condition_1:artifact:*.cef.user_email'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    #content = "User Email: " +  str(filtered_artifacts_item_1_1[0]) +"\n" + "\n" + "ThreatStream E-mail Repuation" +"\n" + "Summary: " + str(results_item_1_0[0])
    
    content = f"User Email: {filtered_artifacts_item_1_1[0]}\n\n"
    
    content += f"**ThreatStream E-mail Repuation**\n"
    content += f"- Threat type: {results_item_1_0[0] if results_item_1_0[0] != None else '-'}\n"
    content += f"- Summary: {'MALICIOUS' if results_item_1_0[0] != None else 'NON-MALICIOUS'}\n\n"
    
    note_title = "User Email Investigation"
    note_content = content
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    ################################################################################
    ## Custom Code End
    ################################################################################
    Update_user_email(container=container)

    return

"""
Update user_email
"""
def Update_user_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Update_user_email() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['Email_reputation_TS:action_result.data.*.threat_type'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_user_email:condition_1:artifact:*.id', 'filtered-data:Filter_out_user_email:condition_1:artifact:*.cef.user_email'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################
    phantom.debug("email-threat-type:" + str(results_item_1_0[0]))
    if results_item_1_0[0] != None:
    
        parameters = []

        cef_json = {"user_email_malicious" : "True"}

        # build parameters list for 'update_artifact_2' call
        parameters.append({
            'artifact_id': filtered_artifacts_item_1_0[0],
            'name': "",
            'label': "",
            'severity': "",
            'cef_json': cef_json,
            'cef_types_json': "",
            'tags': "",
            'overwrite': "",
            'artifact_json': "",
        })

        phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_user_email")

        parameters = []
        parameters.append({
            'artifact_id': filtered_artifacts_item_1_0[0],
            'add_tags': "indicator_malicious",
            'remove_tags': "",
        })

        phantom.act(action="update artifact tags", parameters=parameters, assets=['phantom asset'], name="update_artifact_tags")

    ################################################################################
    ## Custom Code End
    ################################################################################
    join_filter_21(container=container)

    return

"""
Update internal sourceAddress artifact
"""
def Update_internal_sourceAddress_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Update_internal_sourceAddress_artifact() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Update_internal_sourceAddress_artifact' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Link_internal_src_to_artifact_record:condition_1:artifact:*.id', 'filtered-data:Link_internal_src_to_artifact_record:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'Update_internal_sourceAddress_artifact' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'name': "",
                'tags': "",
                'label': "",
                'cef_json': "{\"is_internalSourceAddress\": \"True\"}",
                'severity': "",
                'overwrite': "",
                'artifact_id': filtered_artifacts_item_1[0],
                'artifact_json': "",
                'cef_types_json': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="Update_internal_sourceAddress_artifact")

    return

"""
Update internal destinationAddress artifact
"""
def Update_internal_destinationAddress_artif(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Update_internal_destinationAddress_artif() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Update_internal_destinationAddress_artif' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Link_internal_dst_to_artifact_record:condition_1:artifact:*.id', 'filtered-data:Link_internal_dst_to_artifact_record:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'Update_internal_destinationAddress_artif' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'name': "",
                'tags': "",
                'label': "",
                'cef_json': "{\"is_internalDestinationAddress\": \"True\"}",
                'severity': "",
                'overwrite': "",
                'artifact_id': filtered_artifacts_item_1[0],
                'artifact_json': "",
                'cef_types_json': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="Update_internal_destinationAddress_artif")

    return

"""
Link internal src to artifact record
"""
def Link_internal_src_to_artifact_record(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Link_internal_src_to_artifact_record() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.sourceAddress", "in", "Check_if_sourceAddress_external:custom_function:sourceAddressInternal"],
        ],
        name="Link_internal_src_to_artifact_record:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Update_internal_sourceAddress_artifact(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Link internal dst to artifact record
"""
def Link_internal_dst_to_artifact_record(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Link_internal_dst_to_artifact_record() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationAddress", "in", "Check_if_destinationAddress_external:custom_function:destinationAddressInternal"],
        ],
        name="Link_internal_dst_to_artifact_record:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Update_internal_destinationAddress_artif(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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
            "Enriched",
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
    phantom.custom_function(custom_function='local/Set_last_automated_action', parameters=parameters, name='cf_local_Set_last_automated_action_1', callback=cf_local_Set_last_automated_action_1_callback)

    return

def cf_local_Set_last_automated_action_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('cf_local_Set_last_automated_action_1_callback() called')
    
    Filter_out_sourceAddress(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    Filter_out_destinationAddress(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    filter_22(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    Filter_out_requestURL(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    Filter_out_destinationDnsDomain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    Filter_out_destinationDnsFQDN(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    Filter_out_fileHash(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    Filter_out_user_email(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Format data for amp query on hostname
"""
def Format_data_for_amp_query_on_hostname(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_data_for_amp_query_on_hostname() called')
    
    template = """earliest = -7d@d index=ktb_csoc_default sourcetype= \"cisco:amp:event\"
| sort 0 - _time
| eval time = _time
|convert timeformat=\"%d-%m-%Y %H:%M:%S\" ctime(time) AS time
| spath \"event.computer.hostname\" | search \"event.computer.hostname\"=\"{0}*\"
| table time,event.computer.hostname ,event.computer.network_addresses{{}}.ip ,event.computer.network_addresses{{}}.mac ,event.computer.connector_guid
| dedup event.computer.connector_guid
| rename event.computer.network_addresses{{}}.ip as ip"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_22:condition_1:artifact:*.cef.destinationHostName",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_data_for_amp_query_on_hostname", separator=", ")

    Run_amp_query_on_hostname(container=container)

    return

"""
Format data for mcafee query on hostname
"""
def Format_data_for_mcafee_query_on_hostname(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_data_for_mcafee_query_on_hostname() called')
    
    template = """earliest = -7d@d index=ktb_mgmt_default sourcetype=\"mcafee:epo\" dest_dns={0}
| sort 0 - _time
| eval time = _time
|convert timeformat=\"%d-%m-%Y %H:%M:%S\" ctime(time) AS time
| table time,dest_dns ,dest_ip,dest_mac,os,sp
| dedup dest_dns ,dest_ip"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_22:condition_1:artifact:*.cef.destinationHostName",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_data_for_mcafee_query_on_hostname", separator=", ")

    Run_mcafee_query_on_hostname(container=container)

    return

"""
Run amp query on hostname
"""
def Run_amp_query_on_hostname(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Run_amp_query_on_hostname() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Run_amp_query_on_hostname' call
    formatted_data_1 = phantom.get_format_data(name='Format_data_for_amp_query_on_hostname')

    parameters = []
    
    # build parameters list for 'Run_amp_query_on_hostname' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=join_Extract_address_of_hostname, name="Run_amp_query_on_hostname")

    return

"""
Run mcafee query on hostname
"""
def Run_mcafee_query_on_hostname(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Run_mcafee_query_on_hostname() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Run_mcafee_query_on_hostname' call
    formatted_data_1 = phantom.get_format_data(name='Format_data_for_mcafee_query_on_hostname')

    parameters = []
    
    # build parameters list for 'Run_mcafee_query_on_hostname' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=join_Extract_address_of_hostname, name="Run_mcafee_query_on_hostname")

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