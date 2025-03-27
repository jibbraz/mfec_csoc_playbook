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

@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_out_sourceaddress' block
    filter_out_sourceaddress(container=container)

    # call 'filter_out_destinationaddress' block
    filter_out_destinationaddress(container=container)

    # call 'filter_out_requesturl' block
    filter_out_requesturl(container=container)

    # call 'filter_out_filehash' block
    filter_out_filehash(container=container)

    # call 'filter_out_username' block
    filter_out_username(container=container)

    # call 'filter_out_destinationhostname' block
    filter_out_destinationhostname(container=container)

    # call 'filter_out_destinationdnsdomain' block
    filter_out_destinationdnsdomain(container=container)

    # call 'filter_19' block
    filter_19(container=container)

    # call 'filter_out_hostname' block
    filter_out_hostname(container=container)

    return

"""
Filter out notable event_id 
"""
@phantom.playbook_block()
def filter_out_notable_event_id(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_out_notable_event_id() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.event_id", "!=", ""],
        ],
        name="filter_out_notable_event_id:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_data_to_run_query_to_get_event_de(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Format data to run query to get event details
"""
@phantom.playbook_block()
def format_data_to_run_query_to_get_event_de(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_data_to_run_query_to_get_event_de() called')
    
    template = """earliest=-48h@h  latest=now `notable` | search event_id={0}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_out_notable_event_id:condition_1:artifact:*.cef.event_id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_data_to_run_query_to_get_event_de", separator=", ")

    run_query_to_get_event_details(container=container)

    return

"""
Run query to get event details
"""
@phantom.playbook_block()
def run_query_to_get_event_details(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_query_to_get_event_details() called')

    # collect data for 'run_query_to_get_event_details' call
    formatted_data_1 = phantom.get_format_data(name='format_data_to_run_query_to_get_event_de')

    parameters = []
    
    # build parameters list for 'run_query_to_get_event_details' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=format_data_to_add_event_details_as_note, name="run_query_to_get_event_details")

    return

"""
Format data to add event detail as note
"""
@phantom.playbook_block()
def format_data_to_add_event_details_as_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_data_to_add_event_details_as_note() called')
    
    template = """event_id={0}  earliest=-48h@h  latest=now `notable`"""

    # parameter list for template variable replacement
    parameters = [
        "run_query_to_get_event_details:action_result.summary.total_events",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_data_to_add_event_details_as_note", separator=", ")

    add_event_details_as_note(container=container)

    return

"""
Add event details as note
"""
@phantom.playbook_block()
def add_event_details_as_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_event_details_as_note() called')

    formatted_data_1 = phantom.get_format_data(name='format_data_to_add_event_details_as_note')

    note_title = "Add event details as note"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

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
        ],
        name="filter_out_sourceaddress:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        check_if_sourceaddress_external(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Check if sourceAddress external
"""
@phantom.playbook_block()
def check_if_sourceaddress_external(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_if_sourceaddress_external() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_out_sourceaddress:condition_1:artifact:*.cef.sourceAddress'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    check_if_sourceaddress_external__sourceAddressExternal = None
    check_if_sourceaddress_external__sourceAddressInternal = None

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
            
    check_if_sourceaddress_external__sourceAddressExternal = extemplist
    check_if_sourceaddress_external__sourceAddressInternal = intemplist

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='check_if_sourceaddress_external:sourceAddressExternal', value=json.dumps(check_if_sourceaddress_external__sourceAddressExternal))
    phantom.save_run_data(key='check_if_sourceaddress_external:sourceAddressInternal', value=json.dumps(check_if_sourceaddress_external__sourceAddressInternal))
    check_if_sourceaddress_is_private(container=container)

    return

"""
Format data to query on internal src IP
"""
@phantom.playbook_block()
def format_data_to_query_on_internal_src_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_data_to_query_on_internal_src_ip() called')
    
    template = """summariesonly=t count from datamodel=Network_Traffic.All_Traffic where All_Traffic.src={0} earliest=-4h@h latest=now by sourcetype"""

    # parameter list for template variable replacement
    parameters = [
        "check_if_sourceaddress_external:custom_function:sourceAddressInternal",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_data_to_query_on_internal_src_ip", separator=", ")

    run_query_on_internal_src_ip(container=container)

    return

"""
Run query on internal src IP
"""
@phantom.playbook_block()
def run_query_on_internal_src_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_query_on_internal_src_ip() called')

    # collect data for 'run_query_on_internal_src_ip' call
    formatted_data_1 = phantom.get_format_data(name='format_data_to_query_on_internal_src_ip')

    parameters = []
    
    # build parameters list for 'run_query_on_internal_src_ip' call
    parameters.append({
        'query': formatted_data_1,
        'command': "tstats",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=add_note_details_on_internal_src_ip, name="run_query_on_internal_src_ip")

    return

"""
Add note details on internal src IP
"""
@phantom.playbook_block()
def add_note_details_on_internal_src_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_details_on_internal_src_ip() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['run_query_on_internal_src_ip:action_result.summary.total_events'], action_results=results)
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
@phantom.playbook_block()
def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_reputation_1() called')

    # collect data for 'ip_reputation_1' call
    formatted_data_1 = phantom.get_format_data(name='format_src_ip')

    parameters = []
    
    # build parameters list for 'ip_reputation_1' call
    parameters.append({
        'ip': formatted_data_1,
    })

    phantom.act(action="ip reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=ip_reputation_src_ip_ts, name="ip_reputation_1")

    return

"""
IP Reputation src IP TS
"""
@phantom.playbook_block()
def ip_reputation_src_ip_ts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_reputation_src_ip_ts() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ip_reputation_src_ip_ts' call
    formatted_data_1 = phantom.get_format_data(name='format_src_ip')

    parameters = []
    
    # build parameters list for 'ip_reputation_src_ip_ts' call
    parameters.append({
        'ip': formatted_data_1,
        'limit': 1000,
    })

    phantom.act(action="ip reputation", parameters=parameters, assets=['threatstream hybrid vm'], callback=whois_src_ip_ts, name="ip_reputation_src_ip_ts", parent_action=action)

    return

"""
WhoIS src IP TS
"""
@phantom.playbook_block()
def whois_src_ip_ts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('whois_src_ip_ts() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'whois_src_ip_ts' call
    formatted_data_1 = phantom.get_format_data(name='format_src_ip')

    parameters = []
    
    # build parameters list for 'whois_src_ip_ts' call
    parameters.append({
        'ip': formatted_data_1,
    })

    phantom.act(action="whois ip", parameters=parameters, assets=['threatstream cloud'], callback=format_data_to_query_src_ip, name="whois_src_ip_ts", parent_action=action)

    return

"""
Format data to query src IP
"""
@phantom.playbook_block()
def format_data_to_query_src_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_data_to_query_src_ip() called')
    
    template = """summariesonly=t count from datamodel=Network_Traffic.All_Traffic where All_Traffic.src={0} earliest=-1h@h latest=now | rename All_Traffic.* AS *"""

    # parameter list for template variable replacement
    parameters = [
        "format_src_ip:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_data_to_query_src_ip", separator=", ")

    run_query_src_ip(container=container)

    return

"""
Run query src IP
"""
@phantom.playbook_block()
def run_query_src_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_query_src_ip() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_query_src_ip' call
    formatted_data_1 = phantom.get_format_data(name='format_data_to_query_src_ip')

    parameters = []
    
    # build parameters list for 'run_query_src_ip' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=link_back_src_ip_to_artifact_record, name="run_query_src_ip")

    return

"""
Add note src IP
"""
@phantom.playbook_block()
def add_note_src_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_src_ip() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['ip_reputation_1:action_result.summary.detected_urls'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['ip_reputation_src_ip_ts:action_result.data.*.threat_type'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['whois_src_ip_ts:action_result.summary'], action_results=results)
    results_data_4 = phantom.collect2(container=container, datapath=['run_query_src_ip:action_result.summary.total_events'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:link_back_src_ip_to_artifact_record:condition_1:artifact:*.id', 'filtered-data:link_back_src_ip_to_artifact_record:condition_1:artifact:*.cef.sourceAddress'])
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
    update_src_ip_artifact(container=container)

    return

"""
Update src IP artifact
"""
@phantom.playbook_block()
def update_src_ip_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_src_ip_artifact() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['ip_reputation_1:action_result.summary.malicious'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['ip_reputation_src_ip_ts:action_result.data.*.threat_type'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['whois_src_ip_ts:action_result.summary'], action_results=results)
    results_data_4 = phantom.collect2(container=container, datapath=['run_query_src_ip:action_result.summary.total_events'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:link_back_src_ip_to_artifact_record:condition_1:artifact:*.id', 'filtered-data:link_back_src_ip_to_artifact_record:condition_1:artifact:*.cef.sourceAddress'])
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
@phantom.playbook_block()
def link_back_src_ip_to_artifact_record(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('link_back_src_ip_to_artifact_record() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.sourceAddress", "in", "check_if_sourceaddress_external:custom_function:sourceAddressExternal"],
        ],
        name="link_back_src_ip_to_artifact_record:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_note_src_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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
        ],
        name="filter_out_destinationaddress:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        check_if_destinationaddress_external(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Check if destinationAddress external
"""
@phantom.playbook_block()
def check_if_destinationaddress_external(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_if_destinationaddress_external() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_out_destinationaddress:condition_1:artifact:*.cef.destinationAddress'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    check_if_destinationaddress_external__destinationAddressExternal = None
    check_if_destinationaddress_external__destinationAddressInternal = None

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
            
    check_if_destinationaddress_external__destinationAddressExternal = extemplist
    check_if_destinationaddress_external__destinationAddressInternal = intemplist
    ###################################################################
    ###################################################################
    ###################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='check_if_destinationaddress_external:destinationAddressExternal', value=json.dumps(check_if_destinationaddress_external__destinationAddressExternal))
    phantom.save_run_data(key='check_if_destinationaddress_external:destinationAddressInternal', value=json.dumps(check_if_destinationaddress_external__destinationAddressInternal))
    check_if_destinationaddress_is_private(container=container)

    return

"""
Check if sourceAddress is private
"""
@phantom.playbook_block()
def check_if_sourceaddress_is_private(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_if_sourceaddress_is_private() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["check_if_sourceaddress_external:custom_function:sourceAddressExternal", "!=", []],
        ],
        name="check_if_sourceaddress_is_private:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_src_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["check_if_sourceaddress_external:custom_function:sourceAddressInternal", "!=", []],
        ],
        name="check_if_sourceaddress_is_private:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        format_data_to_query_on_internal_src_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

"""
Check if destinationAddress is private
"""
@phantom.playbook_block()
def check_if_destinationaddress_is_private(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_if_destinationaddress_is_private() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["check_if_destinationaddress_external:custom_function:destinationAddressExternal", "!=", []],
        ],
        name="check_if_destinationaddress_is_private:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_dst_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["check_if_destinationaddress_external:custom_function:destinationAddressInternal", "!=", []],
        ],
        name="check_if_destinationaddress_is_private:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        format_data_to_query_on_internal_dst_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

"""
IP Reputation dst IP VT
"""
@phantom.playbook_block()
def ip_reputation_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_reputation_3() called')

    # collect data for 'ip_reputation_3' call
    formatted_data_1 = phantom.get_format_data(name='format_dst_ip')

    parameters = []
    
    # build parameters list for 'ip_reputation_3' call
    parameters.append({
        'ip': formatted_data_1,
    })

    phantom.act(action="ip reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=ip_reputation_dst_ip_ts, name="ip_reputation_3")

    return

"""
Format data to query on internal dst IP
"""
@phantom.playbook_block()
def format_data_to_query_on_internal_dst_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_data_to_query_on_internal_dst_ip() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "check_if_destinationaddress_external:custom_function:destinationAddressInternal",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_data_to_query_on_internal_dst_ip", separator=", ")

    run_query_on_internal_dst_ip(container=container)

    return

"""
Run query on internal dst IP
"""
@phantom.playbook_block()
def run_query_on_internal_dst_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_query_on_internal_dst_ip() called')

    # collect data for 'run_query_on_internal_dst_ip' call
    formatted_data_1 = phantom.get_format_data(name='format_data_to_query_on_internal_dst_ip')

    parameters = []
    
    # build parameters list for 'run_query_on_internal_dst_ip' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=add_note_details_on_internal_dst_ip, name="run_query_on_internal_dst_ip")

    return

"""
Add note details on internal dst IP
"""
@phantom.playbook_block()
def add_note_details_on_internal_dst_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_details_on_internal_dst_ip() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['run_query_on_internal_dst_ip:action_result.summary.total_events'], action_results=results)
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
@phantom.playbook_block()
def format_src_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_src_ip() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "check_if_sourceaddress_external:custom_function:sourceAddressExternal",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_src_ip", separator=", ")

    ip_reputation_1(container=container)

    return

"""
Format dst IP
"""
@phantom.playbook_block()
def format_dst_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_dst_ip() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "check_if_destinationaddress_external:custom_function:destinationAddressExternal",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_dst_ip", separator=", ")

    ip_reputation_3(container=container)

    return

"""
IP Reputation src IP TS
"""
@phantom.playbook_block()
def ip_reputation_dst_ip_ts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_reputation_dst_ip_ts() called')
    phantom.debug(results)   
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ip_reputation_dst_ip_ts' call
    formatted_data_1 = phantom.get_format_data(name='format_dst_ip')

    parameters = []
    
    # build parameters list for 'ip_reputation_dst_ip_ts' call
    parameters.append({
        'ip': formatted_data_1,
        'limit': 1000,
    })

    phantom.act(action="ip reputation", parameters=parameters, assets=['threatstream cloud'], callback=whois_dst_ip_ts, name="ip_reputation_dst_ip_ts", parent_action=action)

    return

"""
WhoIS dst IP TS
"""
@phantom.playbook_block()
def whois_dst_ip_ts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('whois_dst_ip_ts() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'whois_dst_ip_ts' call
    results_data_1 = phantom.collect2(container=container, datapath=['ip_reputation_3:action_result.parameter.ip', 'ip_reputation_3:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'whois_dst_ip_ts' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="whois ip", parameters=parameters, assets=['threatstream cloud'], callback=format_data_to_query_dst_ip, name="whois_dst_ip_ts", parent_action=action)

    return

"""
Format data to query dst IP
"""
@phantom.playbook_block()
def format_data_to_query_dst_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_data_to_query_dst_ip() called')
    
    template = """{0} earliest=-48h@h  latest=now `notable`"""

    # parameter list for template variable replacement
    parameters = [
        "ip_reputation_3:action_result.parameter.ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_data_to_query_dst_ip", separator=", ")

    run_query_dst_ip(container=container)

    return

"""
Run query dst IP
"""
@phantom.playbook_block()
def run_query_dst_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_query_dst_ip() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_query_dst_ip' call
    formatted_data_1 = phantom.get_format_data(name='format_data_to_query_dst_ip')

    parameters = []
    
    # build parameters list for 'run_query_dst_ip' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=link_back_dst_ip_to_artifact_record, name="run_query_dst_ip")

    return

"""
Link back dst IP to artifact record
"""
@phantom.playbook_block()
def link_back_dst_ip_to_artifact_record(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('link_back_dst_ip_to_artifact_record() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationAddress", "in", "check_if_destinationaddress_external:custom_function:destinationAddressExternal"],
        ],
        name="link_back_dst_ip_to_artifact_record:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_note_dst_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Add note dst IP
"""
@phantom.playbook_block()
def add_note_dst_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_dst_ip() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['ip_reputation_3:action_result.summary.detected_urls'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['ip_reputation_dst_ip_ts:action_result.summary'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['whois_dst_ip_ts:action_result.summary'], action_results=results)
    results_data_4 = phantom.collect2(container=container, datapath=['run_query_dst_ip:action_result.summary.total_events'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:link_back_dst_ip_to_artifact_record:condition_1:artifact:*.id', 'filtered-data:link_back_dst_ip_to_artifact_record:condition_1:artifact:*.cef.destinationAddress'])
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
    update_dst_ip_artifact(container=container)

    return

"""
Update dst IP artifact
"""
@phantom.playbook_block()
def update_dst_ip_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_dst_ip_artifact() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['ip_reputation_3:action_result.summary.malicious'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['ip_reputation_dst_ip_ts:action_result.summary'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['whois_dst_ip_ts:action_result.summary'], action_results=results)
    results_data_4 = phantom.collect2(container=container, datapath=['run_query_dst_ip:action_result.summary.total_events'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:link_back_dst_ip_to_artifact_record:condition_1:artifact:*.id', 'filtered-data:link_back_dst_ip_to_artifact_record:condition_1:artifact:*.cef.destinationAddress'])
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
@phantom.playbook_block()
def filter_out_requesturl(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_out_requesturl() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""],
        ],
        name="filter_out_requesturl:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        check_if_requesturl_external(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Check if requestURL external
"""
@phantom.playbook_block()
def check_if_requesturl_external(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_if_requesturl_external() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_out_requesturl:condition_1:artifact:*.cef.requestURL'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    check_if_requesturl_external__requestURLExternal = None
    check_if_requesturl_external__requestURLInternal = None

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
            
    check_if_requesturl_external__requestURLExternal = externaltemplist
    check_if_requesturl_external__requestURLInternal = internaltemplist
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='check_if_requesturl_external:requestURLExternal', value=json.dumps(check_if_requesturl_external__requestURLExternal))
    phantom.save_run_data(key='check_if_requesturl_external:requestURLInternal', value=json.dumps(check_if_requesturl_external__requestURLInternal))
    check_if_requesturl_is_private(container=container)

    return

"""
Check if requestURL is private
"""
@phantom.playbook_block()
def check_if_requesturl_is_private(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_if_requesturl_is_private() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["check_if_requesturl_external:custom_function:requestURLExternal", "!=", []],
        ],
        name="check_if_requesturl_is_private:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_url(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["check_if_requesturl_external:custom_function:requestURLInternal", "!=", []],
        ],
        name="check_if_requesturl_is_private:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        link_url_to_artifact_record(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

"""
Format URL
"""
@phantom.playbook_block()
def format_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_url() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "check_if_requesturl_external:custom_function:requestURLExternal",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_url", separator=", ")

    url_reputation_1(container=container)

    return

"""
URL Reputation VT
"""
@phantom.playbook_block()
def url_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_reputation_1() called')

    # collect data for 'url_reputation_1' call
    formatted_data_1 = phantom.get_format_data(name='format_url')

    parameters = []
    
    # build parameters list for 'url_reputation_1' call
    parameters.append({
        'url': formatted_data_1,
    })

    phantom.act(action="url reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=url_reputation_ts, name="url_reputation_1")

    return

"""
Link URL to artifact record
"""
@phantom.playbook_block()
def link_url_to_artifact_record(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('link_url_to_artifact_record() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "in", "check_if_requesturl_external:custom_function:requestURLInternal"],
        ],
        name="link_url_to_artifact_record:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        update_internal_requesturl_artifact(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Update internal requestURL artifact
"""
@phantom.playbook_block()
def update_internal_requesturl_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_internal_requesturl_artifact() called')

    # collect data for 'update_internal_requesturl_artifact' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:link_url_to_artifact_record:condition_1:artifact:*.id', 'filtered-data:link_url_to_artifact_record:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'update_internal_requesturl_artifact' call
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

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_internal_requesturl_artifact")

    return

"""
URL Reputation TS
"""
@phantom.playbook_block()
def url_reputation_ts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_reputation_ts() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'url_reputation_ts' call
    results_data_1 = phantom.collect2(container=container, datapath=['url_reputation_1:action_result.parameter.url', 'url_reputation_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'url_reputation_ts' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'url': results_item_1[0],
                'limit': 1000,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="url reputation", parameters=parameters, assets=['threatstream cloud'], callback=format_data_to_query_requesturl, name="url_reputation_ts", parent_action=action)

    return

"""
Format data to query requestURL
"""
@phantom.playbook_block()
def format_data_to_query_requesturl(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_data_to_query_requesturl() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "url_reputation_1:action_result.parameter.url",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_data_to_query_requesturl", separator=", ")

    run_query_requesturl(container=container)

    return

"""
Run query requestURL
"""
@phantom.playbook_block()
def run_query_requesturl(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_query_requesturl() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_query_requesturl' call
    formatted_data_1 = phantom.get_format_data(name='format_data_to_query_requesturl')

    parameters = []
    
    # build parameters list for 'run_query_requesturl' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=link_back_requesturl_to_artifact_record, name="run_query_requesturl")

    return

"""
Link back requestURL to artifact record
"""
@phantom.playbook_block()
def link_back_requesturl_to_artifact_record(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('link_back_requesturl_to_artifact_record() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.requestURL", "in", "check_if_requesturl_external:custom_function:requestURLExternal"],
        ],
        name="link_back_requesturl_to_artifact_record:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_note_requesturl(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Add note requestURL
"""
@phantom.playbook_block()
def add_note_requesturl(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_requesturl() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['url_reputation_1:action_result.summary.positives'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['url_reputation_ts:action_result.summary'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['run_query_requesturl:action_result.summary.total_events'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:link_back_requesturl_to_artifact_record:condition_1:artifact:*.id', 'filtered-data:link_back_requesturl_to_artifact_record:condition_1:artifact:*.cef.requestURL'])
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
    update_external_requesturl_artifact(container=container)

    return

"""
Update external requestURL artifact
"""
@phantom.playbook_block()
def update_external_requesturl_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_external_requesturl_artifact() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['url_reputation_1:action_result.summary.malicious'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['url_reputation_ts:action_result.summary'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['run_query_requesturl:action_result.summary.total_events'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:link_back_requesturl_to_artifact_record:condition_1:artifact:*.id', 'filtered-data:link_back_requesturl_to_artifact_record:condition_1:artifact:*.cef.requestURL'])
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
@phantom.playbook_block()
def filter_out_filehash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_out_filehash() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHash", "!=", ""],
        ],
        name="filter_out_filehash:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        file_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
File reputation VT
"""
@phantom.playbook_block()
def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('file_reputation_1() called')

    # collect data for 'file_reputation_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_out_filehash:condition_1:artifact:*.cef.fileHash', 'filtered-data:filter_out_filehash:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'hash': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="file reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=file_reputation_ts, name="file_reputation_1")

    return

"""
File reputation TS
"""
@phantom.playbook_block()
def file_reputation_ts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('file_reputation_ts() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'file_reputation_ts' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['file_reputation_1:artifact:*.cef.fileHash', 'file_reputation_1:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'file_reputation_ts' call
    for inputs_item_1 in inputs_data_1:
        if inputs_item_1[0]:
            parameters.append({
                'hash': inputs_item_1[0],
                'limit': 1000,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': inputs_item_1[1]},
            })

    phantom.act(action="file reputation", parameters=parameters, assets=['threatstream cloud'], callback=decision_2, name="file_reputation_ts", parent_action=action)

    return

"""
Format data to query fileHash
"""
@phantom.playbook_block()
def format_data_to_query_filehash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_data_to_query_filehash() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "file_reputation_1:action_result.parameter.hash",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_data_to_query_filehash", separator=", ")

    run_query_filehash(container=container)

    return

"""
Run query fileHash
"""
@phantom.playbook_block()
def run_query_filehash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_query_filehash() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_query_filehash' call
    formatted_data_1 = phantom.get_format_data(name='format_data_to_query_filehash')

    parameters = []
    
    # build parameters list for 'run_query_filehash' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=add_note_filehash, name="run_query_filehash")

    return

"""
Add note fileHash
"""
@phantom.playbook_block()
def add_note_filehash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_filehash() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['file_reputation_1:action_result.summary.malicious'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['file_reputation_ts:action_result.summary'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['run_query_filehash:action_result.summary.total_events'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_out_filehash:condition_1:artifact:*.id', 'filtered-data:filter_out_filehash:condition_1:artifact:*.cef.fileHash'])
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
    update_filehash(container=container)

    return

"""
Update fileHash
"""
@phantom.playbook_block()
def update_filehash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_filehash() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['file_reputation_1:action_result.summary.malicious'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['file_reputation_ts:action_result.summary'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['run_query_filehash:action_result.summary.total_events'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_out_filehash:condition_1:artifact:*.id', 'filtered-data:filter_out_filehash:condition_1:artifact:*.cef.fileHash'])
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
@phantom.playbook_block()
def filter_out_username(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_out_username() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.username", "!=", ""],
        ],
        name="filter_out_username:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_user_attribute(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Get user attribute
"""
@phantom.playbook_block()
def get_user_attribute(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_user_attribute() called')

    # collect data for 'get_user_attribute' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_out_username:condition_1:artifact:*.cef.username', 'filtered-data:filter_out_username:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_user_attribute' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'attributes': "sAMAccountName",
                'principals': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="get attributes", parameters=parameters, assets=['csoc ad ldap asset containment'], callback=join_add_note_username, name="get_user_attribute")

    return

"""
Create Artifact
User Email Address
"""
@phantom.playbook_block()
def create_artifact_user_email_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_artifact_user_email_address() called')
    
    id_value = container.get('id', None)
    results_data_1 = phantom.collect2(container=container, datapath=['get_user_attribute:action_result.message'], action_results=results)
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
    join_add_note_username(container=container)

    return

"""
Add note username
"""
@phantom.playbook_block()
def add_note_username(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_username() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['get_user_attribute:action_result.message'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_out_username:condition_1:artifact:*.id', 'filtered-data:filter_out_username:condition_1:artifact:*.cef.username'])
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

@phantom.playbook_block()
def join_add_note_username(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_add_note_username() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['get_user_attribute']):
        
        # call connected block "add_note_username"
        add_note_username(container=container, handle=handle)
    
    return

"""
Filter out destinationHostName
"""
@phantom.playbook_block()
def filter_out_destinationhostname(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_out_destinationhostname() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationHostName", "!=", ""],
        ],
        name="filter_out_destinationhostname:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_system_attribute(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Get system attribute
"""
@phantom.playbook_block()
def get_system_attribute(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_system_attribute() called')

    # collect data for 'get_system_attribute' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_out_destinationhostname:condition_1:artifact:*.cef.destinationHostName', 'filtered-data:filter_out_destinationhostname:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_system_attribute' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'attributes': "sAMAccountName ; distinguishedName ; userprincipalname",
                'principals': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="get attributes", parameters=parameters, assets=['csoc ad ldap asset containment'], callback=add_note_system, name="get_system_attribute")

    return

"""
Add note system
"""
@phantom.playbook_block()
def add_note_system(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_system() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['get_system_attribute:action_result.message'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_out_destinationhostname:condition_1:artifact:*.id', 'filtered-data:filter_out_destinationhostname:condition_1:artifact:*.cef.destinationHostName'])
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
@phantom.playbook_block()
def filter_out_destinationdnsdomain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_out_destinationdnsdomain() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationDnsDomain", "!=", ""],
        ],
        name="filter_out_destinationdnsdomain:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        check_if_destinationdnsdomain_external(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Check if destinationDnsDomain external
"""
@phantom.playbook_block()
def check_if_destinationdnsdomain_external(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_if_destinationdnsdomain_external() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_out_destinationdnsdomain:condition_1:artifact:*.cef.destinationDnsDomain'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    check_if_destinationdnsdomain_external__destinationDnsDomainExternal = None
    check_if_destinationdnsdomain_external__destinationDnsDomainInternal = None

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
            
    check_if_destinationdnsdomain_external__destinationDnsDomainExternal = externaltemplist
    check_if_destinationdnsdomain_external__destinationDnsDomainInternal = internaltemplist
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='check_if_destinationdnsdomain_external:destinationDnsDomainExternal', value=json.dumps(check_if_destinationdnsdomain_external__destinationDnsDomainExternal))
    phantom.save_run_data(key='check_if_destinationdnsdomain_external:destinationDnsDomainInternal', value=json.dumps(check_if_destinationdnsdomain_external__destinationDnsDomainInternal))
    check_if_destinationdnsdomain_is_private(container=container)

    return

"""
Check if destinationDnsDomain is private
"""
@phantom.playbook_block()
def check_if_destinationdnsdomain_is_private(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_if_destinationdnsdomain_is_private() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["check_if_destinationdnsdomain_external:custom_function:destinationDnsDomainExternal", "!=", []],
        ],
        name="check_if_destinationdnsdomain_is_private:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_domain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["check_if_destinationdnsdomain_external:custom_function:destinationDnsDomainInternal", "!=", []],
        ],
        name="check_if_destinationdnsdomain_is_private:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        link_domain_to_artifact_record(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

"""
Format domain
"""
@phantom.playbook_block()
def format_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_domain() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "check_if_destinationdnsdomain_external:custom_function:destinationDnsDomainExternal",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_domain", separator=", ")

    domain_reputation_vt(container=container)

    return

"""
Domain Reputation VT
"""
@phantom.playbook_block()
def domain_reputation_vt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_reputation_vt() called')

    # collect data for 'domain_reputation_vt' call
    formatted_data_1 = phantom.get_format_data(name='format_domain')

    parameters = []
    
    # build parameters list for 'domain_reputation_vt' call
    parameters.append({
        'domain': formatted_data_1,
    })

    phantom.act(action="domain reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=domain_reputation_ts, name="domain_reputation_vt")

    return

"""
Domain Reputation TS
"""
@phantom.playbook_block()
def domain_reputation_ts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_reputation_ts() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'domain_reputation_ts' call
    results_data_1 = phantom.collect2(container=container, datapath=['domain_reputation_vt:action_result.parameter.domain', 'domain_reputation_vt:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'domain_reputation_ts' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'limit': 1000,
                'domain': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="domain reputation", parameters=parameters, assets=['threatstream cloud'], callback=format_data_to_query_destinationdnsdomai, name="domain_reputation_ts", parent_action=action)

    return

"""
Format data to query destinationDnsDomai
"""
@phantom.playbook_block()
def format_data_to_query_destinationdnsdomai(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_data_to_query_destinationdnsdomai() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "domain_reputation_vt:action_result.parameter.domain",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_data_to_query_destinationdnsdomai", separator=", ")

    run_query_destinationdnsdomain(container=container)

    return

"""
Run query destinationDnsDomain
"""
@phantom.playbook_block()
def run_query_destinationdnsdomain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_query_destinationdnsdomain() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_query_destinationdnsdomain' call
    formatted_data_1 = phantom.get_format_data(name='format_data_to_query_destinationdnsdomai')

    parameters = []
    
    # build parameters list for 'run_query_destinationdnsdomain' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=link_back_destinationdnsdoman_to_artifac, name="run_query_destinationdnsdomain")

    return

"""
Link back destinationDnsDoman to artifact record
"""
@phantom.playbook_block()
def link_back_destinationdnsdoman_to_artifac(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('link_back_destinationdnsdoman_to_artifac() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationDnsDomain", "in", "check_if_destinationdnsdomain_external:custom_function:destinationDnsDomainExternal"],
        ],
        name="link_back_destinationdnsdoman_to_artifac:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_note_destinationdnsdomain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Add note destinationDnsDomain
"""
@phantom.playbook_block()
def add_note_destinationdnsdomain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_destinationdnsdomain() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['domain_reputation_vt:action_result.summary.detected_urls'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['domain_reputation_ts:action_result.summary'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['run_query_destinationdnsdomain:action_result.summary.total_events'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:link_back_destinationdnsdoman_to_artifac:condition_1:artifact:*.id', 'filtered-data:link_back_destinationdnsdoman_to_artifac:condition_1:artifact:*.cef.destinationDnsDomain'])
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
    update_external_destinationdnsdomain_art(container=container)

    return

"""
Update external destinationDnsDomain artifact
"""
@phantom.playbook_block()
def update_external_destinationdnsdomain_art(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_external_destinationdnsdomain_art() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['domain_reputation_vt:action_result.summary.malicious'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['domain_reputation_ts:action_result.summary'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['run_query_destinationdnsdomain:action_result.summary.total_events'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:link_back_destinationdnsdoman_to_artifac:condition_1:artifact:*.id', 'filtered-data:link_back_destinationdnsdoman_to_artifac:condition_1:artifact:*.cef.destinationDnsDomain'])
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
@phantom.playbook_block()
def link_domain_to_artifact_record(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('link_domain_to_artifact_record() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationDnsDomain", "in", "check_if_destinationdnsdomain_external:custom_function:destinationDnsDomainInternal"],
        ],
        name="link_domain_to_artifact_record:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        update_internal_destinationdnsdomain_art(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Update internal destinationDnsDomain artifact
"""
@phantom.playbook_block()
def update_internal_destinationdnsdomain_art(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_internal_destinationdnsdomain_art() called')

    # collect data for 'update_internal_destinationdnsdomain_art' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:link_domain_to_artifact_record:condition_1:artifact:*.id', 'filtered-data:link_domain_to_artifact_record:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'update_internal_destinationdnsdomain_art' call
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

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_internal_destinationdnsdomain_art")

    return

@phantom.playbook_block()
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

@phantom.playbook_block()
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
    get_user_attribute_CSOC(container=container)
    get_user_attribute_KTB(container=container)
    get_user_attribute_KTBCS(container=container)

    return

@phantom.playbook_block()
def get_user_attribute_CSOC(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_user_attribute_CSOC() called')

    retrieve_username__PrincipleName = json.loads(phantom.get_run_data(key='retrieve_username:PrincipleName'))
    # collect data for 'get_user_attribute_CSOC' call

    parameters = []
    
    # build parameters list for 'get_user_attribute_CSOC' call
    parameters.append({
        'attributes': "sAMAccountName ; distinguishedName ; userprincipalname",
        'principals': retrieve_username__PrincipleName,
    })

    phantom.act(action="get attributes", parameters=parameters, assets=['csoc ad ldap asset containment'], callback=join_query_result, name="get_user_attribute_CSOC")

    return

@phantom.playbook_block()
def get_user_attribute_KTB(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_user_attribute_KTB() called')

    retrieve_username__PrincipleName = json.loads(phantom.get_run_data(key='retrieve_username:PrincipleName'))
    # collect data for 'get_user_attribute_KTB' call

    parameters = []
    
    # build parameters list for 'get_user_attribute_KTB' call
    parameters.append({
        'attributes': "sAMAccountName ; distinguishedName ; userprincipalname",
        'principals': retrieve_username__PrincipleName,
    })

    phantom.act(action="get attributes", parameters=parameters, assets=['ktb domain ad'], callback=join_query_result, name="get_user_attribute_KTB")

    return

@phantom.playbook_block()
def get_user_attribute_KTBCS(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_user_attribute_KTBCS() called')

    retrieve_username__PrincipleName = json.loads(phantom.get_run_data(key='retrieve_username:PrincipleName'))
    # collect data for 'get_user_attribute_KTBCS' call

    parameters = []
    
    # build parameters list for 'get_user_attribute_KTBCS' call
    parameters.append({
        'attributes': "sAMAccountName ; distinguishedName ; userprincipalname",
        'principals': retrieve_username__PrincipleName,
    })

    phantom.act(action="get attributes", parameters=parameters, assets=['ktbcs domain ad'], callback=join_query_result, name="get_user_attribute_KTBCS")

    return

@phantom.playbook_block()
def query_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('query_result() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_user_attribute_CSOC:action_result.summary.total_objects", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        print_query_result(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_user_attribute_KTB:action_result.summary.total_objects", ">", 0],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        print_query_result(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 3
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_user_attribute_KTBCS:action_result.summary.total_objects", ">", 0],
        ])

    # call connected blocks if condition 3 matched
    if matched:
        print_query_result(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def join_query_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_query_result() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['get_user_attribute_CSOC', 'get_user_attribute_KTB', 'get_user_attribute_KTBCS']):
        
        # call connected block "query_result"
        query_result(container=container, handle=handle)
    
    return

@phantom.playbook_block()
def print_query_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('print_query_result() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['get_user_attribute_CSOC:action_result.summary.total_objects'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['get_user_attribute_KTB:action_result.summary.total_objects'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['get_user_attribute_KTBCS:action_result.summary.total_objects'], action_results=results)
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

@phantom.playbook_block()
def filter_out_hostname(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_out_hostname() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.deviceHostname", "!=", ""],
            ["artifact:*.cef.sourceAddress", "==", ""],
        ],
        logical_operator='and',
        name="filter_out_hostname:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        query_dns(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def query_dns(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('query_dns() called')

    # collect data for 'query_dns' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_out_hostname:condition_1:artifact:*.cef.deviceHostname', 'filtered-data:filter_out_hostname:condition_1:artifact:*.id'])

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

@phantom.playbook_block()
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

@phantom.playbook_block()
def join_filter_21(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_filter_21() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['run_query_dst_ip', 'run_query_src_ip', 'run_query_destinationdnsdomain', 'run_query_requesturl', 'run_query_filehash']):
        
        # call connected block "filter_21"
        filter_21(container=container, handle=handle)
    
    return

@phantom.playbook_block()
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
        format_data_to_query_filehash(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2

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