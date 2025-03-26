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
    
    # call 'Filter_out_sourceAddress' block
    Filter_out_sourceAddress(container=container)

    # call 'Filter_out_destinationAddress' block
    Filter_out_destinationAddress(container=container)

    # call 'Filter_out_requestURL' block
    Filter_out_requestURL(container=container)

    # call 'Filter_out_fileHash' block
    Filter_out_fileHash(container=container)

    # call 'Filter_out_username' block
    Filter_out_username(container=container)

    # call 'Filter_out_destinationHostName' block
    Filter_out_destinationHostName(container=container)

    # call 'Filter_out_destinationDnsDomain' block
    Filter_out_destinationDnsDomain(container=container)

    # call 'filter_19' block
    filter_19(container=container)

    # call 'Filter_out_Hostname' block
    Filter_out_Hostname(container=container)

    return

"""
Filter out notable event_id 
"""
def Filter_out_notable_event_id(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_out_notable_event_id() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.event_id", "!=", ""],
        ],
        name="Filter_out_notable_event_id:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_data_to_run_query_to_get_event_de(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Format data to run query to get event details
"""
def Format_data_to_run_query_to_get_event_de(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_data_to_run_query_to_get_event_de() called')
    
    template = """earliest=-48h@h  latest=now `notable` | search event_id={0}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Filter_out_notable_event_id:condition_1:artifact:*.cef.event_id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_data_to_run_query_to_get_event_de", separator=", ")

    Run_query_to_get_event_details(container=container)

    return

"""
Run query to get event details
"""
def Run_query_to_get_event_details(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Run_query_to_get_event_details() called')

    # collect data for 'Run_query_to_get_event_details' call
    formatted_data_1 = phantom.get_format_data(name='Format_data_to_run_query_to_get_event_de')

    parameters = []
    
    # build parameters list for 'Run_query_to_get_event_details' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=Format_data_to_add_event_details_as_note, name="Run_query_to_get_event_details")

    return

"""
Format data to add event detail as note
"""
def Format_data_to_add_event_details_as_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_data_to_add_event_details_as_note() called')
    
    template = """event_id={0}  earliest=-48h@h  latest=now `notable`"""

    # parameter list for template variable replacement
    parameters = [
        "Run_query_to_get_event_details:action_result.summary.total_events",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_data_to_add_event_details_as_note", separator=", ")

    Add_event_details_as_note(container=container)

    return

"""
Add event details as note
"""
def Add_event_details_as_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_event_details_as_note() called')

    formatted_data_1 = phantom.get_format_data(name='Format_data_to_add_event_details_as_note')

    note_title = "Add event details as note"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

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
        except:
            continue
            
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
Format data to query on internal src IP
"""
def Format_data_to_query_on_internal_src_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_data_to_query_on_internal_src_IP() called')
    
    template = """summariesonly=t count from datamodel=Network_Traffic.All_Traffic where All_Traffic.src={0} earliest=-4h@h latest=now by sourcetype"""

    # parameter list for template variable replacement
    parameters = [
        "Check_if_sourceAddress_external:custom_function:sourceAddressInternal",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_data_to_query_on_internal_src_IP", separator=", ")

    Run_query_on_internal_src_IP(container=container)

    return

"""
Run query on internal src IP
"""
def Run_query_on_internal_src_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Run_query_on_internal_src_IP() called')

    # collect data for 'Run_query_on_internal_src_IP' call
    formatted_data_1 = phantom.get_format_data(name='Format_data_to_query_on_internal_src_IP')

    parameters = []
    
    # build parameters list for 'Run_query_on_internal_src_IP' call
    parameters.append({
        'query': formatted_data_1,
        'command': "tstats",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=Add_note_details_on_internal_src_IP, name="Run_query_on_internal_src_IP")

    return

"""
Add note details on internal src IP
"""
def Add_note_details_on_internal_src_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_details_on_internal_src_IP() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['Run_query_on_internal_src_IP:action_result.summary.total_events'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    if  results_item_1_0[0] is not None:
        content = "Splunk Enteprise Search: " + str(results_item_1_0[0])

        note_title = "Internal sourceAddress Investigation"
        note_content = content
        note_format = "markdown"
        phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return

"""
IP Reputation src IP VT
"""
def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_reputation_1() called')

    # collect data for 'ip_reputation_1' call
    formatted_data_1 = phantom.get_format_data(name='Format_src_IP')

    parameters = []
    
    # build parameters list for 'ip_reputation_1' call
    parameters.append({
        'ip': formatted_data_1,
    })

    phantom.act(action="ip reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=IP_Reputation_src_IP_TS, name="ip_reputation_1")

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

    phantom.act(action="ip reputation", parameters=parameters, assets=['threatstream hybrid vm'], callback=WhoIS_src_IP_TS, name="IP_Reputation_src_IP_TS", parent_action=action)

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

    phantom.act(action="whois ip", parameters=parameters, assets=['threatstream cloud'], callback=Format_data_to_query_src_IP, name="WhoIS_src_IP_TS", parent_action=action)

    return

"""
Format data to query src IP
"""
def Format_data_to_query_src_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_data_to_query_src_IP() called')
    
    template = """summariesonly=t count from datamodel=Network_Traffic.All_Traffic where All_Traffic.src={0} earliest=-1h@h latest=now | rename All_Traffic.* AS *"""

    # parameter list for template variable replacement
    parameters = [
        "Format_src_IP:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_data_to_query_src_IP", separator=", ")

    Run_query_src_IP(container=container)

    return

"""
Run query src IP
"""
def Run_query_src_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Run_query_src_IP() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Run_query_src_IP' call
    formatted_data_1 = phantom.get_format_data(name='Format_data_to_query_src_IP')

    parameters = []
    
    # build parameters list for 'Run_query_src_IP' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=Link_back_src_IP_to_artifact_record, name="Run_query_src_IP")

    return

"""
Add note src IP
"""
def Add_note_src_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_src_IP() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['ip_reputation_1:action_result.summary.detected_urls'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['IP_Reputation_src_IP_TS:action_result.data.*.threat_type'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['WhoIS_src_IP_TS:action_result.summary'], action_results=results)
    results_data_4 = phantom.collect2(container=container, datapath=['Run_query_src_IP:action_result.summary.total_events'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Link_back_src_IP_to_artifact_record:condition_1:artifact:*.id', 'filtered-data:Link_back_src_IP_to_artifact_record:condition_1:artifact:*.cef.sourceAddress'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]
    results_item_3_0 = [item[0] for item in results_data_3]
    results_item_4_0 = [item[0] for item in results_data_4]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    content = "Source IP address: " +  filtered_artifacts_item_1_1[0] +"\n" + "\n" + "VirusTotal IP Reputation" +"\n" + "Summary Detected URLs: " + str(results_item_1_0[0]) +"\n" + "\n" + "ThreatStream IP Repuation" +"\n" + "Summary: " + str(results_item_2_0[0]) + "\n" + "\n" + "WhoIS IP" +"\n" + "Summary: " + str(results_item_3_0[0]) + "\n" + "\n" + "Splunk Enterprise Search" +"\n" + "Total Events: " + str(results_item_4_0[0])
    
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
    
    results_data_1 = phantom.collect2(container=container, datapath=['ip_reputation_1:action_result.summary.malicious'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['IP_Reputation_src_IP_TS:action_result.data.*.threat_type'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['WhoIS_src_IP_TS:action_result.summary'], action_results=results)
    results_data_4 = phantom.collect2(container=container, datapath=['Run_query_src_IP:action_result.summary.total_events'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Link_back_src_IP_to_artifact_record:condition_1:artifact:*.id', 'filtered-data:Link_back_src_IP_to_artifact_record:condition_1:artifact:*.cef.sourceAddress'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]
    results_item_3_0 = [item[0] for item in results_data_3]
    results_item_4_0 = [item[0] for item in results_data_4]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    if results_item_2_0[0] != {} or results_item_1_0[0] > 2:
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
        except:
            continue
            
    Check_if_destinationAddress_external__destinationAddressExternal = extemplist
    Check_if_destinationAddress_external__destinationAddressInternal = intemplist
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
        conditions=[
            ["Check_if_sourceAddress_external:custom_function:sourceAddressInternal", "!=", []],
        ],
        name="Check_if_sourceAddress_is_private:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        Format_data_to_query_on_internal_src_IP(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

"""
Check if destinationAddress is private
"""
def Check_if_destinationAddress_is_private(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_if_destinationAddress_is_private() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
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
        conditions=[
            ["Check_if_destinationAddress_external:custom_function:destinationAddressInternal", "!=", []],
        ],
        name="Check_if_destinationAddress_is_private:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        Format_data_to_query_on_internal_dst_IP(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

"""
IP Reputation dst IP VT
"""
def ip_reputation_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_reputation_3() called')

    # collect data for 'ip_reputation_3' call
    formatted_data_1 = phantom.get_format_data(name='Format_dst_IP')

    parameters = []
    
    # build parameters list for 'ip_reputation_3' call
    parameters.append({
        'ip': formatted_data_1,
    })

    phantom.act(action="ip reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=IP_Reputation_dst_IP_TS, name="ip_reputation_3")

    return

"""
Format data to query on internal dst IP
"""
def Format_data_to_query_on_internal_dst_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_data_to_query_on_internal_dst_IP() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "Check_if_destinationAddress_external:custom_function:destinationAddressInternal",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_data_to_query_on_internal_dst_IP", separator=", ")

    Run_query_on_internal_dst_IP(container=container)

    return

"""
Run query on internal dst IP
"""
def Run_query_on_internal_dst_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Run_query_on_internal_dst_IP() called')

    # collect data for 'Run_query_on_internal_dst_IP' call
    formatted_data_1 = phantom.get_format_data(name='Format_data_to_query_on_internal_dst_IP')

    parameters = []
    
    # build parameters list for 'Run_query_on_internal_dst_IP' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=Add_note_details_on_internal_dst_IP, name="Run_query_on_internal_dst_IP")

    return

"""
Add note details on internal dst IP
"""
def Add_note_details_on_internal_dst_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_details_on_internal_dst_IP() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['Run_query_on_internal_dst_IP:action_result.summary.total_events'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    if  results_item_1_0[0] is not None:

        content = "Splunk Enteprise Search: " + str(results_item_1_0[0])

        note_title = "Internal destinationAddress Investigation"
        note_content = content
        note_format = "markdown"
        phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

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

    ip_reputation_1(container=container)

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

    ip_reputation_3(container=container)

    return

"""
IP Reputation src IP TS
"""
def IP_Reputation_dst_IP_TS(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('IP_Reputation_dst_IP_TS() called')
    phantom.debug(results)   
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'IP_Reputation_dst_IP_TS' call
    formatted_data_1 = phantom.get_format_data(name='Format_dst_IP')

    parameters = []
    
    # build parameters list for 'IP_Reputation_dst_IP_TS' call
    parameters.append({
        'ip': formatted_data_1,
        'limit': 1000,
    })

    phantom.act(action="ip reputation", parameters=parameters, assets=['threatstream cloud'], callback=WhoIS_dst_IP_TS, name="IP_Reputation_dst_IP_TS", parent_action=action)

    return

"""
WhoIS dst IP TS
"""
def WhoIS_dst_IP_TS(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('WhoIS_dst_IP_TS() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'WhoIS_dst_IP_TS' call
    results_data_1 = phantom.collect2(container=container, datapath=['ip_reputation_3:action_result.parameter.ip', 'ip_reputation_3:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'WhoIS_dst_IP_TS' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="whois ip", parameters=parameters, assets=['threatstream cloud'], callback=Format_data_to_query_dst_IP, name="WhoIS_dst_IP_TS", parent_action=action)

    return

"""
Format data to query dst IP
"""
def Format_data_to_query_dst_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_data_to_query_dst_IP() called')
    
    template = """{0} earliest=-48h@h  latest=now `notable`"""

    # parameter list for template variable replacement
    parameters = [
        "ip_reputation_3:action_result.parameter.ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_data_to_query_dst_IP", separator=", ")

    Run_query_dst_IP(container=container)

    return

"""
Run query dst IP
"""
def Run_query_dst_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Run_query_dst_IP() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Run_query_dst_IP' call
    formatted_data_1 = phantom.get_format_data(name='Format_data_to_query_dst_IP')

    parameters = []
    
    # build parameters list for 'Run_query_dst_IP' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=Link_back_dst_IP_to_artifact_record, name="Run_query_dst_IP")

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

"""
Add note dst IP
"""
def Add_note_dst_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_dst_IP() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['ip_reputation_3:action_result.summary.detected_urls'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['IP_Reputation_dst_IP_TS:action_result.summary'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['WhoIS_dst_IP_TS:action_result.summary'], action_results=results)
    results_data_4 = phantom.collect2(container=container, datapath=['Run_query_dst_IP:action_result.summary.total_events'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Link_back_dst_IP_to_artifact_record:condition_1:artifact:*.id', 'filtered-data:Link_back_dst_IP_to_artifact_record:condition_1:artifact:*.cef.destinationAddress'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]
    results_item_3_0 = [item[0] for item in results_data_3]
    results_item_4_0 = [item[0] for item in results_data_4]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    content = "Destination IP address: " +  filtered_artifacts_item_1_1[0] +"\n" + "\n" + "VirusTotal IP Reputation" +"\n" + "Summary Detected URLs: " + str(results_item_1_0[0]) +"\n" + "\n" + "ThreatStream IP Repuation" +"\n" + "Summary: " + str(results_item_2_0[0]) + "\n" + "\n" + "WhoIS IP" +"\n" + "Summary: " + str(results_item_3_0[0]) + "\n" + "\n" + "Splunk Enterprise Search" +"\n" + "Total Events: " + str(results_item_4_0[0])
    
    note_title = "destinationAddress Investigation"
    note_content = content
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
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
    
    results_data_1 = phantom.collect2(container=container, datapath=['ip_reputation_3:action_result.summary.malicious'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['IP_Reputation_dst_IP_TS:action_result.summary'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['WhoIS_dst_IP_TS:action_result.summary'], action_results=results)
    results_data_4 = phantom.collect2(container=container, datapath=['Run_query_dst_IP:action_result.summary.total_events'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Link_back_dst_IP_to_artifact_record:condition_1:artifact:*.id', 'filtered-data:Link_back_dst_IP_to_artifact_record:condition_1:artifact:*.cef.destinationAddress'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]
    results_item_3_0 = [item[0] for item in results_data_3]
    results_item_4_0 = [item[0] for item in results_data_4]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug('VT=' )
    phantom.debug(results_item_1_0)
    phantom.debug('TS=')
    phantom.debug(results_item_2_0)
    
    if results_item_2_0[0] != {} or results_item_1_0[0] >= 2:
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

    url_reputation_1(container=container)

    return

"""
URL Reputation VT
"""
def url_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_reputation_1() called')

    # collect data for 'url_reputation_1' call
    formatted_data_1 = phantom.get_format_data(name='Format_URL')

    parameters = []
    
    # build parameters list for 'url_reputation_1' call
    parameters.append({
        'url': formatted_data_1,
    })

    phantom.act(action="url reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=URL_Reputation_TS, name="url_reputation_1")

    return

"""
Link URL to artifact record
"""
def Link_URL_to_artifact_record(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Link_URL_to_artifact_record() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
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
    results_data_1 = phantom.collect2(container=container, datapath=['url_reputation_1:action_result.parameter.url', 'url_reputation_1:action_result.parameter.context.artifact_id'], action_results=results)

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

    phantom.act(action="url reputation", parameters=parameters, assets=['threatstream cloud'], callback=Format_data_to_query_requestURL, name="URL_Reputation_TS", parent_action=action)

    return

"""
Format data to query requestURL
"""
def Format_data_to_query_requestURL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_data_to_query_requestURL() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "url_reputation_1:action_result.parameter.url",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_data_to_query_requestURL", separator=", ")

    Run_query_requestURL(container=container)

    return

"""
Run query requestURL
"""
def Run_query_requestURL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Run_query_requestURL() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Run_query_requestURL' call
    formatted_data_1 = phantom.get_format_data(name='Format_data_to_query_requestURL')

    parameters = []
    
    # build parameters list for 'Run_query_requestURL' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=Link_back_requestURL_to_artifact_record, name="Run_query_requestURL")

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
    
    results_data_1 = phantom.collect2(container=container, datapath=['url_reputation_1:action_result.summary.positives'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['URL_Reputation_TS:action_result.summary'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['Run_query_requestURL:action_result.summary.total_events'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Link_back_requestURL_to_artifact_record:condition_1:artifact:*.id', 'filtered-data:Link_back_requestURL_to_artifact_record:condition_1:artifact:*.cef.requestURL'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]
    results_item_3_0 = [item[0] for item in results_data_3]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    content = "URL: " +  filtered_artifacts_item_1_1[0] +"\n" + "\n" + "VirusTotal URL Reputation" +"\n" + "Summary Positives: " + str(results_item_1_0[0]) +"\n" + "\n" + "ThreatStream URL Repuation" +"\n" + "Summary: " + str(results_item_2_0[0]) +"\n" + "\n" + "Splunk Enterprise Search" +"\n" + "Total Events: " + str(results_item_3_0[0])

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
    ## Custom Code End
    ################################################################################
    Update_external_requestURL_artifact(container=container)

    return

"""
Update external requestURL artifact
"""
def Update_external_requestURL_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Update_external_requestURL_artifact() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['url_reputation_1:action_result.summary.malicious'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['URL_Reputation_TS:action_result.summary'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['Run_query_requestURL:action_result.summary.total_events'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Link_back_requestURL_to_artifact_record:condition_1:artifact:*.id', 'filtered-data:Link_back_requestURL_to_artifact_record:condition_1:artifact:*.cef.requestURL'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]
    results_item_3_0 = [item[0] for item in results_data_3]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    if results_item_2_0[0] != {} or results_item_1_0[0] > 2:
    
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
        conditions=[
            ["artifact:*.cef.fileHash", "!=", ""],
        ],
        name="Filter_out_fileHash:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        file_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
File reputation VT
"""
def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('file_reputation_1() called')

    # collect data for 'file_reputation_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_fileHash:condition_1:artifact:*.cef.fileHash', 'filtered-data:Filter_out_fileHash:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'hash': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="file reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=File_reputation_TS, name="file_reputation_1")

    return

"""
File reputation TS
"""
def File_reputation_TS(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('File_reputation_TS() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'File_reputation_TS' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['file_reputation_1:artifact:*.cef.fileHash', 'file_reputation_1:artifact:*.id'], action_results=results)

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

    phantom.act(action="file reputation", parameters=parameters, assets=['threatstream cloud'], callback=decision_2, name="File_reputation_TS", parent_action=action)

    return

"""
Format data to query fileHash
"""
def Format_data_to_query_fileHash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_data_to_query_fileHash() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "file_reputation_1:action_result.parameter.hash",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_data_to_query_fileHash", separator=", ")

    Run_query_fileHash(container=container)

    return

"""
Run query fileHash
"""
def Run_query_fileHash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Run_query_fileHash() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Run_query_fileHash' call
    formatted_data_1 = phantom.get_format_data(name='Format_data_to_query_fileHash')

    parameters = []
    
    # build parameters list for 'Run_query_fileHash' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=Add_note_fileHash, name="Run_query_fileHash")

    return

"""
Add note fileHash
"""
def Add_note_fileHash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_fileHash() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['file_reputation_1:action_result.summary.malicious'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['File_reputation_TS:action_result.summary'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['Run_query_fileHash:action_result.summary.total_events'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_fileHash:condition_1:artifact:*.id', 'filtered-data:Filter_out_fileHash:condition_1:artifact:*.cef.fileHash'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]
    results_item_3_0 = [item[0] for item in results_data_3]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    content = "fileHash: " +  filtered_artifacts_item_1_1[0] +"\n" + "\n" + "VirusTotal File Reputation" +"\n" + "Summar Malicious: " + str(results_item_1_0[0]) +"\n" + "\n" + "ThreatStream File Repuation" +"\n" + "Summary: " + str(results_item_2_0[0]) +"\n" + "\n" + "Splunk Enterprise Search" +"\n" + "Total Events: " + str(results_item_3_0[0])
    
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
    
    results_data_1 = phantom.collect2(container=container, datapath=['file_reputation_1:action_result.summary.malicious'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['File_reputation_TS:action_result.summary'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['Run_query_fileHash:action_result.summary.total_events'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_fileHash:condition_1:artifact:*.id', 'filtered-data:Filter_out_fileHash:condition_1:artifact:*.cef.fileHash'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]
    results_item_3_0 = [item[0] for item in results_data_3]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    if results_item_2_0[0] != {} or results_item_1_0[0] >= 1:
    
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
Filter out username
"""
def Filter_out_username(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_out_username() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.username", "!=", ""],
        ],
        name="Filter_out_username:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Get_user_attribute(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Get user attribute
"""
def Get_user_attribute(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Get_user_attribute() called')

    # collect data for 'Get_user_attribute' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_username:condition_1:artifact:*.cef.username', 'filtered-data:Filter_out_username:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'Get_user_attribute' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'attributes': "sAMAccountName",
                'principals': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="get attributes", parameters=parameters, assets=['csoc ad ldap asset containment'], callback=join_Add_note_username, name="Get_user_attribute")

    return

"""
Create Artifact
User Email Address
"""
def Create_Artifact_User_Email_Address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Create_Artifact_User_Email_Address() called')
    
    id_value = container.get('id', None)
    results_data_1 = phantom.collect2(container=container, datapath=['Get_user_attribute:action_result.message'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    url = phantom.build_phantom_rest_url('container', id_value, 'artifacts') 
    url = url  + '?_filter_cef__toEmail__isnull=False'
    phantom.debug(url)
    response = phantom.requests.get(
        url,
     verify=False
    )
    phantom.debug(response.json())
    r = response.json()
    for i in r:
        if i == 'count':
            if r[i] > 0:
                phantom.debug("toEmail exist")
            elif r[i] == 0:
                phantom.debug("toEmail do not exist")    
                parameters = []
                phantom.debug(results_item_1_0)

                # build parameters list for 'add_artifact_1' call
                parameters.append({
                    'name': "Email Artifact",
                    'container_id': "",
                    'label': "event",
                    'source_data_identifier': "None",
                    'cef_name': "toEmail",
                    'cef_value': "someEmail",
                    'cef_dictionary': "",
                    'contains': "",
                    'run_automation': False,
                })

                phantom.act(action="add artifact", parameters=parameters, assets=['phantom asset'], name="add_artifact_emailAddress")

    ################################################################################
    ## Custom Code End
    ################################################################################
    join_Add_note_username(container=container)

    return

"""
Add note username
"""
def Add_note_username(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_username() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['Get_user_attribute:action_result.message'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_username:condition_1:artifact:*.id', 'filtered-data:Filter_out_username:condition_1:artifact:*.cef.username'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    content = "Username: "  + filtered_artifacts_item_1_1[0] + "\n" + "Results: " + results_item_1_0[0]
    
    note_title = "Get User Attribute"
    note_content = content
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return

def join_Add_note_username(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_Add_note_username() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['Get_user_attribute']):
        
        # call connected block "Add_note_username"
        Add_note_username(container=container, handle=handle)
    
    return

"""
Filter out destinationHostName
"""
def Filter_out_destinationHostName(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_out_destinationHostName() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationHostName", "!=", ""],
        ],
        name="Filter_out_destinationHostName:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Get_system_attribute(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Get system attribute
"""
def Get_system_attribute(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Get_system_attribute() called')

    # collect data for 'Get_system_attribute' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_destinationHostName:condition_1:artifact:*.cef.destinationHostName', 'filtered-data:Filter_out_destinationHostName:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'Get_system_attribute' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'attributes': "sAMAccountName ; distinguishedName ; userprincipalname",
                'principals': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="get attributes", parameters=parameters, assets=['csoc ad ldap asset containment'], callback=Add_note_system, name="Get_system_attribute")

    return

"""
Add note system
"""
def Add_note_system(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_system() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['Get_system_attribute:action_result.message'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_destinationHostName:condition_1:artifact:*.id', 'filtered-data:Filter_out_destinationHostName:condition_1:artifact:*.cef.destinationHostName'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    content = "Hostname: "  + filtered_artifacts_item_1_1[0] + "\n" + "Results: " + results_item_1_0[0]
    
    note_title = "Get System Attribute"
    note_content = content
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return

"""
Filter out destinationDnsDomain
"""
def Filter_out_destinationDnsDomain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_out_destinationDnsDomain() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
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

    phantom.act(action="domain reputation", parameters=parameters, assets=['threatstream cloud'], callback=Format_data_to_query_destinationDnsDomai, name="Domain_Reputation_TS", parent_action=action)

    return

"""
Format data to query destinationDnsDomai
"""
def Format_data_to_query_destinationDnsDomai(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_data_to_query_destinationDnsDomai() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "Domain_Reputation_VT:action_result.parameter.domain",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_data_to_query_destinationDnsDomai", separator=", ")

    Run_query_destinationDnsDomain(container=container)

    return

"""
Run query destinationDnsDomain
"""
def Run_query_destinationDnsDomain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Run_query_destinationDnsDomain() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Run_query_destinationDnsDomain' call
    formatted_data_1 = phantom.get_format_data(name='Format_data_to_query_destinationDnsDomai')

    parameters = []
    
    # build parameters list for 'Run_query_destinationDnsDomain' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=Link_back_destinationDnsDoman_to_artifac, name="Run_query_destinationDnsDomain")

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
    
    results_data_1 = phantom.collect2(container=container, datapath=['Domain_Reputation_VT:action_result.summary.detected_urls'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['Domain_Reputation_TS:action_result.summary'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['Run_query_destinationDnsDomain:action_result.summary.total_events'], action_results=results)
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
    content = "Domain: " +  filtered_artifacts_item_1_1[0] +"\n" + "\n" + "VirusTotal Domain Reputation" +"\n" + "Summary Detected URLs: " + str(results_item_1_0[0]) +"\n" + "\n" + "ThreatStream Domain Repuation" +"\n" + "Summary: " + str(results_item_2_0[0]) +"\n" + "\n" + "Splunk Enterprise Search" +"\n" + "Total Events: " + str(results_item_3_0[0])
    
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
    results_data_2 = phantom.collect2(container=container, datapath=['Domain_Reputation_TS:action_result.summary'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['Run_query_destinationDnsDomain:action_result.summary.total_events'], action_results=results)
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
    if results_item_2_0[0] != {} or results_item_1_0[0] > 2:
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

def filter_19(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_19() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceUserName", "!=", ""],
        ],
        name="filter_19:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        retrieve_username(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def retrieve_username(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('retrieve_username() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceUserName', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]

    retrieve_username__PrincipleName = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    retrieve_username__PrincipleName = container_item_0[0].split("@")[0]

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='retrieve_username:PrincipleName', value=json.dumps(retrieve_username__PrincipleName))
    Get_user_attribute_CSOC(container=container)
    Get_user_attribute_KTB(container=container)
    Get_user_attribute_KTBCS(container=container)

    return

def Get_user_attribute_CSOC(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Get_user_attribute_CSOC() called')

    retrieve_username__PrincipleName = json.loads(phantom.get_run_data(key='retrieve_username:PrincipleName'))
    # collect data for 'Get_user_attribute_CSOC' call

    parameters = []
    
    # build parameters list for 'Get_user_attribute_CSOC' call
    parameters.append({
        'attributes': "sAMAccountName ; distinguishedName ; userprincipalname",
        'principals': retrieve_username__PrincipleName,
    })

    phantom.act(action="get attributes", parameters=parameters, assets=['csoc ad ldap asset containment'], callback=join_Query_result, name="Get_user_attribute_CSOC")

    return

def Get_user_attribute_KTB(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Get_user_attribute_KTB() called')

    retrieve_username__PrincipleName = json.loads(phantom.get_run_data(key='retrieve_username:PrincipleName'))
    # collect data for 'Get_user_attribute_KTB' call

    parameters = []
    
    # build parameters list for 'Get_user_attribute_KTB' call
    parameters.append({
        'attributes': "sAMAccountName ; distinguishedName ; userprincipalname",
        'principals': retrieve_username__PrincipleName,
    })

    phantom.act(action="get attributes", parameters=parameters, assets=['ktb domain ad'], callback=join_Query_result, name="Get_user_attribute_KTB")

    return

def Get_user_attribute_KTBCS(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Get_user_attribute_KTBCS() called')

    retrieve_username__PrincipleName = json.loads(phantom.get_run_data(key='retrieve_username:PrincipleName'))
    # collect data for 'Get_user_attribute_KTBCS' call

    parameters = []
    
    # build parameters list for 'Get_user_attribute_KTBCS' call
    parameters.append({
        'attributes': "sAMAccountName ; distinguishedName ; userprincipalname",
        'principals': retrieve_username__PrincipleName,
    })

    phantom.act(action="get attributes", parameters=parameters, assets=['ktbcs domain ad'], callback=join_Query_result, name="Get_user_attribute_KTBCS")

    return

def Query_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Query_result() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Get_user_attribute_CSOC:action_result.summary.total_objects", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Print_query_result(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Get_user_attribute_KTB:action_result.summary.total_objects", ">", 0],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        Print_query_result(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 3
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Get_user_attribute_KTBCS:action_result.summary.total_objects", ">", 0],
        ])

    # call connected blocks if condition 3 matched
    if matched:
        Print_query_result(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def join_Query_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_Query_result() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['Get_user_attribute_CSOC', 'Get_user_attribute_KTB', 'Get_user_attribute_KTBCS']):
        
        # call connected block "Query_result"
        Query_result(container=container, handle=handle)
    
    return

def Print_query_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Print_query_result() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['Get_user_attribute_CSOC:action_result.summary.total_objects'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['Get_user_attribute_KTB:action_result.summary.total_objects'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['Get_user_attribute_KTBCS:action_result.summary.total_objects'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]
    results_item_3_0 = [item[0] for item in results_data_3]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug(results_item_1_0)
    phantom.debug(results_item_2_0)
    phantom.debug(results_item_3_0)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return

def Filter_out_Hostname(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_out_Hostname() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.deviceHostname", "!=", ""],
            ["artifact:*.cef.sourceAddress", "==", ""],
        ],
        logical_operator='and',
        name="Filter_out_Hostname:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        query_dns(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def query_dns(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('query_dns() called')

    # collect data for 'query_dns' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_Hostname:condition_1:artifact:*.cef.deviceHostname', 'filtered-data:Filter_out_Hostname:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'query_dns' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'type': "",
                'domain': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="lookup domain", parameters=parameters, assets=['csoc-dns'], name="query_dns")

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
    if phantom.completed(action_names=['Run_query_dst_IP', 'Run_query_src_IP', 'Run_query_destinationDnsDomain', 'Run_query_requestURL', 'Run_query_fileHash']):
        
        # call connected block "filter_21"
        filter_21(container=container, handle=handle)
    
    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.status", "!=", "failed"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Format_data_to_query_fileHash(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2

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