"""
This playbook takes an indicator as input and enriches it from threat intelligence sources based on the indicator type.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

import ipaddress
URL_CONTAIN_FAILED = False

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Fetch_Active_Threat_Feed' block
    Fetch_Active_Threat_Feed(container=container)

    return

def Domain_Reputation_on_Umbrella(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Domain_Reputation_on_Umbrella() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Domain_Reputation_on_Umbrella' call
    formatted_data_1 = phantom.get_format_data(name='Format_Domain__as_list')

    parameters = []
    
    # build parameters list for 'Domain_Reputation_on_Umbrella' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'domain': formatted_part_1,
        })

    phantom.act(action="domain reputation", parameters=parameters, assets=['ktb-umbrella-asset'], callback=join_filter_23, name="Domain_Reputation_on_Umbrella")

    return

def URL_Add_Investigated_and_Benign_Tags(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('URL_Add_Investigated_and_Benign_Tags() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'URL_Add_Investigated_and_Benign_Tags' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_40:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.id", "filtered-data:filter_40:condition_1:Fetch_Active_Threat_Feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'URL_Add_Investigated_and_Benign_Tags' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'id': filtered_results_item_1[0],
                'tlp': "green",
                'tags': "PhantomInvestigated,PhantomBenign",
                'source_user_id': 33862,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], name="URL_Add_Investigated_and_Benign_Tags")

    return

def Fetch_Active_Threat_Feed(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Fetch_Active_Threat_Feed() called')

    # collect data for 'Fetch_Active_Threat_Feed' call

    parameters = []
    
    # build parameters list for 'Fetch_Active_Threat_Feed' call
    parameters.append({
        'limit': 45,
        'query': "{\"q\":\"status=active AND tags=phantominput AND NOT tags=phantominvestigated\"}",
        'offset': "",
        'order_by': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['threatstream hybrid vm'], callback=Fetch_Active_Threat_Feed_callback, name="Fetch_Active_Threat_Feed")

    return

def Fetch_Active_Threat_Feed_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('Fetch_Active_Threat_Feed_callback() called')
    
    Filter_IOC_Domain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    Filter_IOC_URL(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    Filter_IOC_IP(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    Filter_IOC_File_Hash(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def Format_URL_Containment_Query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_URL_Containment_Query() called')
    
    template = """%%
summariesonly=t count as evt_count from datamodel=Web where (Web.url=\"{0}\") AND Web.sourcetype!=\"stream:http\"  AND Web.action=\"blocked\" earliest=-2d@d latest=now
| fields evt_count
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_29:condition_1:URL_Reputation_on_VT_v3:action_result.parameter.url",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_URL_Containment_Query", separator=", ")

    Run_URL_Containment_Query(container=container)

    return

def Run_URL_Containment_Query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Run_URL_Containment_Query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Run_URL_Containment_Query' call
    formatted_data_1 = phantom.get_format_data(name='Format_URL_Containment_Query__as_list')

    parameters = []
    
    # build parameters list for 'Run_URL_Containment_Query' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'query': formatted_part_1,
            'command': "tstats",
            'display': "evt_count",
            'parse_only': False,
        })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=decision_19, name="Run_URL_Containment_Query")

    return

def Format_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_IP() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Filter_IOC_IP:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_IP", separator=", ")

    IP_Reputation_on_VT_v3(container=container)

    return

def Format_URL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_URL() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Filter_IOC_URL:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_URL", separator=", ")

    URL_Reputation_on_VT_v3(container=container)

    return

def Format_Domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Domain() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Filter_IOC_Domain:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Domain", separator=", ")

    Domain_Reputation_on_Umbrella(container=container)
    Domain_Reputation_on_VT_v3(container=container)

    return

def Format_File_Hash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_File_Hash() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Filter_IOC_File_Hash:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_File_Hash", separator=", ")

    File_Reputation_on_VT_V(container=container)

    return

def Filter_IOC_URL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_IOC_URL() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Fetch_Active_Threat_Feed:action_result.data.*.type", "==", "url"],
        ],
        name="Filter_IOC_URL:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_URL(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Filter_IOC_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_IOC_IP() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Fetch_Active_Threat_Feed:action_result.data.*.type", "==", "ip"],
        ],
        name="Filter_IOC_IP:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_IP(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Filter_IOC_Domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_IOC_Domain() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Fetch_Active_Threat_Feed:action_result.data.*.type", "==", "domain"],
        ],
        name="Filter_IOC_Domain:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_Domain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Format_IP_Containment_Query_on_VT(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_IP_Containment_Query_on_VT() called')
    
    template = """%%
summariesonly=t count as evt_count from datamodel=Network_Traffic where Network_Traffic.sourcetype=\"pan:traffic\" AND Network_Traffic.action=\"deny\" AND ( Network_Traffic.dest_ip=\"{0}\" OR Network_Traffic.src_ip=\"{0}\" )
earliest=-7d@d latest=now
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_28:condition_1:IP_Reputation_on_VT_v3:action_result.parameter.ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_IP_Containment_Query_on_VT", separator=", ")

    Run_IP_Query_for_VT(container=container)

    return

def Run_IP_Query_for_VT(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Run_IP_Query_for_VT() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Run_IP_Query_for_VT' call
    formatted_data_1 = phantom.get_format_data(name='Format_IP_Containment_Query_on_VT__as_list')

    parameters = []
    
    # build parameters list for 'Run_IP_Query_for_VT' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'query': formatted_part_1,
            'command': "tstats",
            'display': "evt_count",
            'parse_only': False,
        })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=decision_13, name="Run_IP_Query_for_VT")

    return

def filter_23(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_23() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Domain_Reputation_on_VT_v3:action_result.summary.malicious", ">", 2],
            ["Domain_Reputation_on_Umbrella:action_result.summary.domain_status", "==", "MALICIOUS"],
        ],
        logical_operator='or',
        name="filter_23:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_33(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        join_Email_Content(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Domain_Reputation_on_Umbrella:action_result.summary.domain_status", "!=", "MALICIOUS"],
            ["Domain_Reputation_on_VT_v3:action_result.summary.malicious", "<=", 2],
        ],
        logical_operator='and',
        name="filter_23:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        filter_43(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def join_filter_23(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_filter_23() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_filter_23_called'):
        return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['Domain_Reputation_on_Umbrella']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_filter_23_called', value='filter_23')
        
        # call connected block "filter_23"
        filter_23(container=container, handle=handle)
    
    return

def Filter_IOC_File_Hash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_IOC_File_Hash() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Fetch_Active_Threat_Feed:action_result.data.*.type", "==", "md5"],
        ],
        name="Filter_IOC_File_Hash:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_File_Hash(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Add_Malicious_and_Contained_Tags_URL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_Malicious_and_Contained_Tags_URL() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Add_Malicious_and_Contained_Tags_URL' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_38:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.id", "filtered-data:filter_38:condition_1:Fetch_Active_Threat_Feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'Add_Malicious_and_Contained_Tags_URL' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'id': filtered_results_item_1[0],
                'tlp': "red",
                'tags': "PhantomInvestigated,PhantomMalicious,PhantomContained",
                'source_user_id': 33862,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], callback=add_note_71, name="Add_Malicious_and_Contained_Tags_URL")

    return

def decision_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_13() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Run_IP_Query_for_VT:action_result.data.*.evt_count", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        filter_34(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    Format_IP_for_Note(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def Format_IoC_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_IoC_IP() called')
    
    template = """Below Malicious IPs are NOT being contained and will be prompted to SoC Admin to decide whether executing containment:
%%
{0}

%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_28:condition_1:IP_Reputation_on_VT_v3:action_result.parameter.ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_IoC_IP", separator=", ")

    Prompt_Block_IP(container=container)

    return

def Format_Hash_Containment_Query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Hash_Containment_Query() called')
    
    template = """%%
summariesonly=t count as evt_count from datamodel=Intrusion_Detection where Intrusion_Detection.sourcetype=\"fortinet:sandbox:syslog\" AND Intrusion_Detection.file_hash={0} AND Intrusion_Detection.action=\"blocked\" AND Intrusion_Detection.action=\"block\" AND Intrusion_Detection.action=\"denied\" earliest=-7d@d latest=now
| fields evt_count
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_44:condition_1:File_Reputation_on_VT_V:action_result.parameter.hash",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Hash_Containment_Query", separator=", ")

    Run_Hash_Containment_Query(container=container)

    return

def Run_Hash_Containment_Query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Run_Hash_Containment_Query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Run_Hash_Containment_Query' call
    formatted_data_1 = phantom.get_format_data(name='Format_Hash_Containment_Query__as_list')

    parameters = []
    
    # build parameters list for 'Run_Hash_Containment_Query' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'query': formatted_part_1,
            'command': "tstats",
            'display': "evt_count",
            'parse_only': False,
        })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=decision_21, name="Run_Hash_Containment_Query")

    return

def Format_Email_to_SOC(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Email_to_SOC() called')
    
    template = """Below Malicious File Hash are NOT being contained:
%%
{0}

%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Filter_IOC_File_Hash:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Email_to_SOC", separator=", ")

    add_note_66(container=container)

    return

def Add_Investigated_and_Malicious_Tags_Hash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_Investigated_and_Malicious_Tags_Hash() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Add_Investigated_and_Malicious_Tags_Hash' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_47:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.id", "filtered-data:filter_47:condition_1:Fetch_Active_Threat_Feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'Add_Investigated_and_Malicious_Tags_Hash' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'id': filtered_results_item_1[0],
                'tlp': "red",
                'tags': "PhantomInvestigated,PhantomMalicious,PhantomNonContained",
                'source_user_id': 33862,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], callback=Format_Email_to_SOC, name="Add_Investigated_and_Malicious_Tags_Hash")

    return

def Prompt_Block_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Prompt_Block_IP() called')
    
    # set user and message variables for phantom.prompt call
    user = "Tier2 Analyst"
    message = """***WARNING*** 
Do you want to proceed with containment?

Attacker Info:
Source Address = {0}"""

    # parameter list for template variable replacement
    parameters = [
        "Format_IoC_IP:formatted_data",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=5, name="Prompt_Block_IP", separator=", ", parameters=parameters, response_types=response_types, callback=decision_15)

    return

def decision_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_15() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Prompt_Block_IP:action_result.summary.responses.0", "==", "Yes"],
            ["Prompt_Block_IP:action_result.status", "==", "success"],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        Get_total_amount_of_IP_address(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Prompt_Block_IP:action_result.summary.responses.0", "==", "No"],
            ["Prompt_Block_IP:action_result.status", "==", "success"],
        ],
        logical_operator='and')

    # call connected blocks if condition 2 matched
    if matched:
        filter_37(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 3
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Prompt_Block_IP:action_result.status", "==", "failed"],
        ])

    # call connected blocks if condition 3 matched
    if matched:
        filter_37(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def Email_Content(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Email_Content() called')
    
    template = """Malicious IOC URLs:
%%
{0}
%%

Malicious IOC IPs:
%%
{1}
%%

Malicious IOC Domains:
%%
{2}
%%

Malicious IOC Hashs
%%
{3}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_29:condition_1:URL_Reputation_on_VT_v3:action_result.parameter.url",
        "filtered-data:filter_28:condition_1:IP_Reputation_on_VT_v3:action_result.parameter.ip",
        "filtered-data:filter_23:condition_1:Domain_Reputation_on_VT_v3:action_result.parameter.domain",
        "filtered-data:filter_44:condition_1:File_Reputation_on_VT_V:action_result.parameter.hash",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Email_Content", separator=", ")

    Notify_SoC_Team_via_Email(container=container)

    return

def join_Email_Content(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_Email_Content() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['URL_Reputation_on_VT_v3', 'File_Reputation_on_VT_V', 'Domain_Reputation_on_VT_v3', 'Domain_Reputation_on_Umbrella', 'IP_Reputation_on_VT_v3']):
        
        # call connected block "Email_Content"
        Email_Content(container=container, handle=handle)
    
    return

def Notify_SoC_Team_via_Email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Notify_SoC_Team_via_Email() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Notify_SoC_Team_via_Email' call
    formatted_data_1 = phantom.get_format_data(name='Email_Content')

    parameters = []
    
    # build parameters list for 'Notify_SoC_Team_via_Email' call
    parameters.append({
        'cc': "",
        'to': "security-infra@ktbcs.co.th",
        'bcc': "",
        'body': formatted_data_1,
        'from': "no-reply-phantom@ktbcs.co.th",
        'headers': "",
        'subject': "Malicious URL are NOT being contained",
        'attachments': "",
    })

    phantom.act(action="send email", parameters=parameters, assets=['smtp asset'], name="Notify_SoC_Team_via_Email")

    return

def Prompt_URL_Containment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Prompt_URL_Containment() called')
    
    # set user and message variables for phantom.prompt call
    user = "Tier2 Analyst"
    message = """***WARNING*** 
Do you want to proceed with containment?

Malicious URL :
URL = {0}"""

    # parameter list for template variable replacement
    parameters = [
        "URL_Reputation_on_VT_v3:action_result.parameter.url",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=5, name="Prompt_URL_Containment", separator=", ", parameters=parameters, response_types=response_types, callback=decision_17)

    return

def decision_17(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_17() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Prompt_URL_Containment:action_result.status", "==", "success"],
            ["Prompt_URL_Containment:action_result.summary.responses.0", "==", "Yes"],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        Format_URL_for_Note(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Prompt_URL_Containment:action_result.status", "==", "success"],
            ["Prompt_URL_Containment:action_result.summary.responses.0", "==", "No"],
        ],
        logical_operator='and')

    # call connected blocks if condition 2 matched
    if matched:
        Add_Malicious_and_NonContained_Tags_URL(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        add_note_41(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 3
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Prompt_URL_Containment:action_result.status", "==", "failed"],
        ])

    # call connected blocks if condition 3 matched
    if matched:
        add_note_40(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        Add_Malicious_and_NonContained_Tags_URL(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def Add_Malicious_and_Contained_Tag_Hash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_Malicious_and_Contained_Tag_Hash() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Add_Malicious_and_Contained_Tag_Hash' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_46:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.id", "filtered-data:filter_46:condition_1:Fetch_Active_Threat_Feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'Add_Malicious_and_Contained_Tag_Hash' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'id': filtered_results_item_1[0],
                'tlp': "red",
                'tags': "PhantomInvestigated,PhantomMalicious,PhantomContained",
                'source_user_id': 33862,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], callback=Email_Content_Hash, name="Add_Malicious_and_Contained_Tag_Hash")

    return

def Email_Content_Hash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Email_Content_Hash() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Filter_IOC_File_Hash:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Email_Content_Hash", separator=", ")

    add_note_64(container=container)

    return

def add_note_40(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_40() called')

    note_title = "Can not get approval for Containment Action"
    note_content = "Can not get approval for Containment Action"
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def Add_Malicious_and_NonContained_Tags_URL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_Malicious_and_NonContained_Tags_URL() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Add_Malicious_and_NonContained_Tags_URL' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:Filter_IOC_URL:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.id", "filtered-data:Filter_IOC_URL:condition_1:Fetch_Active_Threat_Feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'Add_Malicious_and_NonContained_Tags_URL' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'id': filtered_results_item_1[0],
                'tlp': "red",
                'tags': "PhantomInvestigated,PhantomMalicious,PhantomNonContained",
                'source_user_id': 33862,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], name="Add_Malicious_and_NonContained_Tags_URL")

    return

def add_note_41(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_41() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_IOC_URL:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value'])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    note_title = "Containment Action is Not Approved"
    note_content = filtered_results_item_1_0
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def URL_Reputation_on_VT_v3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('URL_Reputation_on_VT_v3() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'URL_Reputation_on_VT_v3' call
    formatted_data_1 = phantom.get_format_data(name='Format_URL__as_list')

    parameters = []
    
    # build parameters list for 'URL_Reputation_on_VT_v3' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'url': formatted_part_1,
        })

    phantom.act(action="url reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=filter_29, name="URL_Reputation_on_VT_v3")

    return

def decision_19(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_19() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Run_URL_Containment_Query:action_result.data.*.evt_count", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        filter_38(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    join_filter_42(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def Add_Contained_Tag_URL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_Contained_Tag_URL() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Add_Contained_Tag_URL' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_41:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.id", "filtered-data:filter_41:condition_1:Fetch_Active_Threat_Feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'Add_Contained_Tag_URL' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'id': filtered_results_item_1[0],
                'tlp': "red",
                'tags': "PhantomInvestigated,PhantomContained,PhantomMalicious",
                'source_user_id': 33862,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], name="Add_Contained_Tag_URL")

    return

def Add_NonContained_Tag_URL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_NonContained_Tag_URL() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Add_NonContained_Tag_URL' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:Filter_IOC_URL:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.id", "filtered-data:Filter_IOC_URL:condition_1:Fetch_Active_Threat_Feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'Add_NonContained_Tag_URL' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'id': filtered_results_item_1[0],
                'tlp': "red",
                'tags': "PhantomInvestigated,PhantomNoncontained,PhantomMalicious",
                'source_user_id': 33862,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], name="Add_NonContained_Tag_URL")

    return

def add_note_51(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_51() called')

    Format_URL_for_Note__url_list_markdown = json.loads(phantom.get_run_data(key='Format_URL_for_Note:url_list_markdown'))

    note_title = "URL successfully blocked on FortiGate "
    note_content = Format_URL_for_Note__url_list_markdown
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def decision_21(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_21() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Run_Hash_Containment_Query:action_result.data.*.evt_count", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        filter_46(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    filter_47(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def File_Reputation_on_VT_V(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('File_Reputation_on_VT_V() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'File_Reputation_on_VT_V' call
    formatted_data_1 = phantom.get_format_data(name='Format_File_Hash__as_list')

    parameters = []
    
    # build parameters list for 'File_Reputation_on_VT_V' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'hash': formatted_part_1,
        })

    phantom.act(action="file reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=filter_44, name="File_Reputation_on_VT_V")

    return

def Add_Benign_and_Investigated_Tag(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_Benign_and_Investigated_Tag() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Add_Benign_and_Investigated_Tag' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_45:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.id", "filtered-data:filter_45:condition_1:Fetch_Active_Threat_Feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'Add_Benign_and_Investigated_Tag' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'id': filtered_results_item_1[0],
                'tlp': "green",
                'tags': "PhantomInvestigated,PhantomBenign",
                'source_user_id': 33862,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], callback=Form_Email_File_Hash, name="Add_Benign_and_Investigated_Tag")

    return

def Form_Email_File_Hash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Form_Email_File_Hash() called')
    
    template = """Hi SOC,
Below IOC File Hash have been taged as \" PhantomInvestigated\" and \"PhantomBenign\"
%%
{0}
%%
Thanks"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Filter_IOC_File_Hash:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Form_Email_File_Hash", separator=", ")

    add_note_65(container=container)

    return

def IP_Reputation_on_VT_v3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('IP_Reputation_on_VT_v3() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'IP_Reputation_on_VT_v3' call
    formatted_data_1 = phantom.get_format_data(name='Format_IP__as_list')

    parameters = []
    
    # build parameters list for 'IP_Reputation_on_VT_v3' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'ip': formatted_part_1,
        })

    phantom.act(action="ip reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=filter_28, name="IP_Reputation_on_VT_v3")

    return

def Add_NonContained_Tag_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_NonContained_Tag_IP() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Add_NonContained_Tag_IP' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_36:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.id", "filtered-data:filter_36:condition_1:Fetch_Active_Threat_Feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'Add_NonContained_Tag_IP' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'id': filtered_results_item_1[0],
                'tlp': "red",
                'tags': "PhantomInvestigated,PhantomNonContained,PhantomMalicious",
                'source_user_id': 33862,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], callback=add_note_74, name="Add_NonContained_Tag_IP")

    return

def Add_Contained_Tag_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_Contained_Tag_IP() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Add_Contained_Tag_IP' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_35:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.id", "filtered-data:filter_35:condition_1:Fetch_Active_Threat_Feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'Add_Contained_Tag_IP' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'id': filtered_results_item_1[0],
                'tlp': "red",
                'tags': "PhantomInvestigated,PhantomContained,PhantomMalicious",
                'source_user_id': 33862,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], callback=add_note_63, name="Add_Contained_Tag_IP")

    return

def Add_Malicious_and_Noncontained_Tag_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_Malicious_and_Noncontained_Tag_IP() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Add_Malicious_and_Noncontained_Tag_IP' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_37:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.id", "filtered-data:filter_37:condition_1:Fetch_Active_Threat_Feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'Add_Malicious_and_Noncontained_Tag_IP' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'id': filtered_results_item_1[0],
                'tlp': "red",
                'tags': "PhantomInvestigated,PhantomMalicious,PhantomNonContained",
                'source_user_id': 33862,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], name="Add_Malicious_and_Noncontained_Tag_IP")

    return

def Domain_Reputation_on_VT_v3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Domain_Reputation_on_VT_v3() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Domain_Reputation_on_VT_v3' call
    formatted_data_1 = phantom.get_format_data(name='Format_Domain__as_list')

    parameters = []
    
    # build parameters list for 'Domain_Reputation_on_VT_v3' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'domain': formatted_part_1,
        })

    phantom.act(action="domain reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=join_filter_23, name="Domain_Reputation_on_VT_v3")

    return

def add_note_53(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_53() called')

    formatted_data_1 = phantom.get_format_data(name='Format_VT_Failure')

    note_title = "Failure occurred on VirusTotal"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def Format_VT_Failure(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_VT_Failure() called')
    
    template = """IoC File Hash VirusTotal Failure
%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Filter_IOC_File_Hash:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_VT_Failure", separator=", ")

    add_note_53(container=container)

    return

def add_note_54(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_54() called')

    Format_URL_for_Note__url_list_markdown = json.loads(phantom.get_run_data(key='Format_URL_for_Note:url_list_markdown'))

    note_title = "URL IoC Failed to be blocked on FortiGate"
    note_content = Format_URL_for_Note__url_list_markdown
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def filter_28(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_28() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["IP_Reputation_on_VT_v3:action_result.summary.malicious", ">", 2],
            ["filtered-data:Filter_IOC_IP:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value", "!=", ""],
        ],
        logical_operator='and',
        name="filter_28:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_IP_Containment_Query_on_VT(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        join_Email_Content(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["IP_Reputation_on_VT_v3:action_result.summary.malicious", "<=", 2],
            ["filtered-data:Filter_IOC_IP:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value", "!=", ""],
        ],
        logical_operator='and',
        name="filter_28:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        filter_39(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def add_note_56(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_56() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_33:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value'])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    note_title = "Umbrella Malicious IoC Domain"
    note_content = filtered_results_item_1_0
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def Domain_IoC_Add_Malicious_Tag(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Domain_IoC_Add_Malicious_Tag() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Domain_IoC_Add_Malicious_Tag' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_33:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.id", "filtered-data:filter_33:condition_1:Fetch_Active_Threat_Feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'Domain_IoC_Add_Malicious_Tag' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'id': filtered_results_item_1[0],
                'tlp': "red",
                'tags': "PhantomMalicious,PhantomInvestigated",
                'source_user_id': 33862,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], callback=add_note_56, name="Domain_IoC_Add_Malicious_Tag")

    return

def Add_Malicious_and_Contained_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_Malicious_and_Contained_IP() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Add_Malicious_and_Contained_IP' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_34:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.id", "filtered-data:filter_34:condition_1:Fetch_Active_Threat_Feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'Add_Malicious_and_Contained_IP' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'id': filtered_results_item_1[0],
                'tlp': "red",
                'tags': "PhantomInvestigated,PhantomMalicious,PhantomContained",
                'source_user_id': 33862,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], callback=add_note_61, name="Add_Malicious_and_Contained_IP")

    return

def add_note_61(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_61() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_34:condition_1:IP_Reputation_on_VT_v3:action_result.parameter.ip'])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    note_title = "Investigated and Bening IoC IP"
    note_content = filtered_results_item_1_0
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def filter_29(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_29() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["URL_Reputation_on_VT_v3:action_result.summary.malicious", ">", 2],
            ["URL_Reputation_on_VT_v3:action_result.status", "==", "success"],
        ],
        logical_operator='and',
        name="filter_29:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_URL_Containment_Query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        join_Email_Content(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["URL_Reputation_on_VT_v3:action_result.summary.malicious", "<=", 2],
            ["URL_Reputation_on_VT_v3:action_result.status", "==", "success"],
        ],
        logical_operator='and',
        name="filter_29:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        filter_40(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["URL_Reputation_on_VT_v3:action_result.status", "==", "failed"],
        ],
        name="filter_29:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        add_note_77(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    return

def add_note_63(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_63() called')

    Format_IP_for_Note__ip_list_markdown = json.loads(phantom.get_run_data(key='Format_IP_for_Note:ip_list_markdown'))

    note_title = "IP address successfully added to the list waiting to contain"
    note_content = Format_IP_for_Note__ip_list_markdown
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def add_note_64(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_64() called')

    formatted_data_1 = phantom.get_format_data(name='Email_Content_Hash')

    note_title = "Malicious File Hash IoC"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def add_note_65(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_65() called')

    formatted_data_1 = phantom.get_format_data(name='Form_Email_File_Hash')

    note_title = "Benign File Hash IoC"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def add_note_66(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_66() called')

    formatted_data_1 = phantom.get_format_data(name='Format_Email_to_SOC')

    note_title = "NonContained File Hash IoC"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def add_note_68(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_68() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_43:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value'])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    note_title = "Benign Domain IoC -- Umbrella and VT"
    note_content = filtered_results_item_1_0
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def filter_33(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_33() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_23:condition_1:Domain_Reputation_on_VT_v3:action_result.parameter.domain", "==", "filtered-data:Filter_IOC_Domain:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value"],
        ],
        name="filter_33:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Domain_IoC_Add_Malicious_Tag(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_34(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_34() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_28:condition_1:IP_Reputation_on_VT_v3:action_result.parameter.ip", "==", "filtered-data:Filter_IOC_IP:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value"],
        ],
        name="filter_34:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Add_Malicious_and_Contained_IP(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_35(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_35() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_28:condition_1:IP_Reputation_on_VT_v3:action_result.parameter.ip", "==", "filtered-data:filter_28:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value"],
        ],
        name="filter_35:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Add_Contained_Tag_IP(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_36(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_36() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_28:condition_1:IP_Reputation_on_VT_v3:action_result.parameter.ip", "==", "filtered-data:filter_28:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value"],
        ],
        name="filter_36:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Add_NonContained_Tag_IP(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_37(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_37() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_28:condition_1:IP_Reputation_on_VT_v3:action_result.parameter.ip", "==", "filtered-data:filter_28:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value"],
        ],
        name="filter_37:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Add_Malicious_and_Noncontained_Tag_IP(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_38(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_38() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_29:condition_1:URL_Reputation_on_VT_v3:action_result.parameter.url", "==", "filtered-data:Filter_IOC_URL:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value"],
        ],
        name="filter_38:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Add_Malicious_and_Contained_Tags_URL(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def add_note_71(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_71() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_38:condition_1:URL_Reputation_on_VT_v3:action_result.parameter.url'])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    note_title = "Already contained URL IoC"
    note_content = filtered_results_item_1_0
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def filter_39(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_39() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_28:condition_2:IP_Reputation_on_VT_v3:action_result.parameter.ip", "==", "filtered-data:filter_28:condition_2:Fetch_Active_Threat_Feed:action_result.data.*.value"],
        ],
        name="filter_39:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Add_Benign_Tag_IP(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Add_Benign_Tag_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_Benign_Tag_IP() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Add_Benign_Tag_IP' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_39:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.id", "filtered-data:filter_39:condition_1:Fetch_Active_Threat_Feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'Add_Benign_Tag_IP' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'id': filtered_results_item_1[0],
                'tlp': "green",
                'tags': "PhantomInvestigated,PhantomBenign",
                'source_user_id': 33862,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], name="Add_Benign_Tag_IP")

    return

def filter_40(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_40() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_29:condition_2:URL_Reputation_on_VT_v3:action_result.parameter.url", "==", "filtered-data:Filter_IOC_URL:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value"],
        ],
        name="filter_40:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        URL_Add_Investigated_and_Benign_Tags(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_41(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_41() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_29:condition_1:URL_Reputation_on_VT_v3:action_result.parameter.url", "==", "filtered-data:Filter_IOC_URL:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value"],
        ],
        name="filter_41:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Add_Contained_Tag_URL(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_42(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_42() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_29:condition_1:URL_Reputation_on_VT_v3:action_result.parameter.url", "==", "filtered-data:Filter_IOC_URL:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value"],
        ],
        name="filter_42:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Add_NonContained_Tag_URL(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def join_filter_42(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_filter_42() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_filter_42_called'):
        return

    # no callbacks to check, call connected block "filter_42"
    phantom.save_run_data(key='join_filter_42_called', value='filter_42', auto=True)

    filter_42(container=container, handle=handle)
    
    return

def filter_43(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_43() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_23:condition_2:Domain_Reputation_on_VT_v3:action_result.parameter.domain", "==", "filtered-data:Filter_IOC_Domain:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value"],
        ],
        name="filter_43:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Add_Benign_Tag_Domain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Add_Benign_Tag_Domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_Benign_Tag_Domain() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Add_Benign_Tag_Domain' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_43:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.id", "filtered-data:filter_43:condition_1:Fetch_Active_Threat_Feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'Add_Benign_Tag_Domain' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'id': filtered_results_item_1[0],
                'tlp': "amber",
                'tags': "PhantomInvestigated,PhantomBenign",
                'source_user_id': 33862,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], callback=add_note_68, name="Add_Benign_Tag_Domain")

    return

def add_note_74(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_74() called')

    Format_IP_for_Note__ip_list_markdown = json.loads(phantom.get_run_data(key='Format_IP_for_Note:ip_list_markdown'))

    note_title = "Failed to contain IP address due to amount exceeded"
    note_content = Format_IP_for_Note__ip_list_markdown
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def filter_44(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_44() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["File_Reputation_on_VT_V:action_result.summary.malicious", ">", 2],
            ["File_Reputation_on_VT_V:action_result.status", "==", "success"],
        ],
        logical_operator='and',
        name="filter_44:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_Hash_Containment_Query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        join_Email_Content(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["File_Reputation_on_VT_V:action_result.summary.malicious", "<=", 2],
            ["File_Reputation_on_VT_V:action_result.status", "==", "success"],
        ],
        logical_operator='and',
        name="filter_44:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        filter_45(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["File_Reputation_on_VT_V:action_result.status", "==", "failed"],
        ],
        name="filter_44:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        Format_VT_Failure(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    return

def filter_45(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_45() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_44:condition_2:File_Reputation_on_VT_V:action_result.parameter.hash", "==", "filtered-data:Filter_IOC_File_Hash:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value"],
        ],
        name="filter_45:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Add_Benign_and_Investigated_Tag(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_46(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_46() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_44:condition_1:File_Reputation_on_VT_V:action_result.parameter.hash", "==", "filtered-data:Filter_IOC_File_Hash:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value"],
        ],
        name="filter_46:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Add_Malicious_and_Contained_Tag_Hash(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_47(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_47() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_44:condition_1:File_Reputation_on_VT_V:action_result.parameter.hash", "==", "filtered-data:Filter_IOC_File_Hash:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value"],
        ],
        name="filter_47:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Add_Investigated_and_Malicious_Tags_Hash(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def add_note_77(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_77() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_29:condition_3:URL_Reputation_on_VT_v3:action_result.parameter.url'])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    note_title = "IoC URL VT Failure"
    note_content = filtered_results_item_1_0
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

"""
Add malicious IP to custom list
"""
def Add_malicious_IP_to_custom_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_malicious_IP_to_custom_list() called')
    
    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_28:condition_1:IP_Reputation_on_VT_v3:action_result.parameter.ip'])
    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    IP_LIST_NAMES = [ 
        "Firepower - IP to contain",
        #"Fortigate - Src IP to contain",
        #"Fortigate - Dest IP to contain",
        "Fortimanager - Dest IP to contain",
        "Fortimanager - Src IP to contain",
        "PaloAlto - Dest IP to contain",
        "PaloAlto - Src IP to contain"
    ]
    
    for IP_LIST_NAME in IP_LIST_NAMES:
        for ip in filtered_results_item_1_0:
            success, message, num_of_matching_row = phantom.check_list(list_name=IP_LIST_NAME, value=ip, case_sensitive=True, substring=False)
            if num_of_matching_row == 0:
                phantom.add_list(list_name=IP_LIST_NAME, values=[ip])
                phantom.debug(f"List: `{IP_LIST_NAME}`, IP: {ip}")

    ################################################################################
    ## Custom Code End
    ################################################################################
    filter_35(container=container)

    return

"""
Get total amount of IP address
"""
def Get_total_amount_of_IP_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Get_total_amount_of_IP_address() called')
    
    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_28:condition_1:IP_Reputation_on_VT_v3:action_result.parameter.ip'])
    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    Get_total_amount_of_IP_address__total_num_of_ip = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    import ipaddress
    ipaddress_list = set(filtered_results_item_1_0)
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
    decision_26(container=container)

    return

def decision_26(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_26() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Get_total_amount_of_IP_address:custom_function:total_num_of_ip", "<=", 20],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Add_malicious_IP_to_custom_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    filter_36(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Collect all URL
"""
def Collect_all_URL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Collect_all_URL() called')
    
    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_IOC_URL:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value'])
    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    global URL_CONTAIN_FAILED
    # Reinitial Global Variables to ensure it will get reseted every runtime
    URL_CONTAIN_FAILED = False
    
    phantom.save_run_data(value=json.dumps(filtered_results_item_1_0), key="URL_LIST_TO_CONTAIN", auto=True)
    phantom.debug(filtered_results_item_1_0)
    phantom.debug('---')

    ################################################################################
    ## Custom Code End
    ################################################################################
    join_decision_27(container=container)

    return

def decision_27(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_27() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            [1, "==", 1],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Get_the_top_URL_from_the_array(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def join_decision_27(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_decision_27() called')
    
    # if the joined function has already been called, do nothing
    #if phantom.get_run_data(key='join_decision_27_called'):
    #    return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    #if phantom.completed(action_names=['Run_URL_Containment_Query']):
        
    # save the state that the joined function has now been called
    phantom.save_run_data(key='join_decision_27_called', value='decision_27')
        
    # call connected block "decision_27"
    decision_27(container=container, handle=handle)
    
    return

"""
Get the top URL from the array
"""
def Get_the_top_URL_from_the_array(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Get_the_top_URL_from_the_array() called')
    
    input_parameter_0 = ""

    Get_the_top_URL_from_the_array__top_url = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    URL_LIST_TO_CONTAIN = json.loads(phantom.get_run_data(key="URL_LIST_TO_CONTAIN"))
    phantom.debug(f"Starting loop with: {URL_LIST_TO_CONTAIN}")
    if len(URL_LIST_TO_CONTAIN) > 0:
        Get_the_top_URL_from_the_array__top_url = URL_LIST_TO_CONTAIN[0]

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Get_the_top_URL_from_the_array:top_url', value=json.dumps(Get_the_top_URL_from_the_array__top_url))
    decision_28(container=container)

    return

def decision_28(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_28() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Get_the_top_URL_from_the_array:custom_function:top_url", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Prepare_URL_artifact(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Prepare URL artifact
"""
def Prepare_URL_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Prepare_URL_artifact() called')
    
    template = """{{\"requestURL\": \"{0}\", \"requestURL_malicious\": \"True\"}}"""

    # parameter list for template variable replacement
    parameters = [
        "Get_the_top_URL_from_the_array:custom_function:top_url",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Prepare_URL_artifact", separator=", ")

    Add_URL_artifact(container=container)

    return

"""
Add URL artifact
"""
def Add_URL_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_URL_artifact() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    Get_the_top_URL_from_the_array__top_url = json.loads(phantom.get_run_data(key='Get_the_top_URL_from_the_array:top_url'))
    # collect data for 'Add_URL_artifact' call
    formatted_data_1 = phantom.get_format_data(name='Prepare_URL_artifact')

    parameters = []
    
    # build parameters list for 'Add_URL_artifact' call
    parameters.append({
        'name': "User created artifact",
        'label': "event",
        'cef_name': "",
        'contains': "",
        'cef_value': "",
        'container_id': "",
        'cef_dictionary': formatted_data_1,
        'run_automation': False,
        'source_data_identifier': Get_the_top_URL_from_the_array__top_url,
    })

    phantom.act(action="add artifact", parameters=parameters, assets=['phantom asset'], callback=FortiGate_Block_URL, name="Add_URL_artifact")

    return

"""
FortiGate Block URL
"""
def FortiGate_Block_URL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('FortiGate_Block_URL() called')
    
    URL_LIST_TO_CONTAIN = json.loads(phantom.get_run_data(key="URL_LIST_TO_CONTAIN"))

    # call playbook "local/PLAYBOOK-CONTAIN-INDICATOR-FORTIGATECSOC-URL", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/PLAYBOOK-CONTAIN-INDICATOR-FORTIGATEKTBCS-URL", container=container, name=f"FortiGate_Block_URL_{len(URL_LIST_TO_CONTAIN)}", callback=Sleep)

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

    phantom.act(action="no op", parameters=parameters, assets=['phantom asset'], callback=decision_29, name="Sleep")

    return

def decision_29(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_29() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.requestURL_ContainResult", "==", True],
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
    global URL_CONTAIN_FAILED
    URL_CONTAIN_FAILED = True
    phantom.debug("failed detected")

    ################################################################################
    ## Custom Code End
    ################################################################################
    join_Delete_the_created_artifact(container=container)

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
        
    ####
    ################################################################################
    ## Custom Code End
    ################################################################################
    Remove_the_top_URL_from_the_array(container=container)

    return

def join_Delete_the_created_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_Delete_the_created_artifact() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    #if phantom.completed(action_names=['Sleep']):
        
    # call connected block "Delete_the_created_artifact"
    Delete_the_created_artifact(container=container, handle=handle)
    
    return

"""
Remove the top URL from the array
"""
def Remove_the_top_URL_from_the_array(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Remove_the_top_URL_from_the_array() called')
    
    input_parameter_0 = ""

    Remove_the_top_URL_from_the_array__url_count = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    URL_LIST_TO_CONTAIN = json.loads(phantom.get_run_data(key="URL_LIST_TO_CONTAIN"))
    phantom.debug(f"Before popping: {URL_LIST_TO_CONTAIN}")
    URL_LIST_TO_CONTAIN.pop(0)
    phantom.debug(f"After popping: {URL_LIST_TO_CONTAIN}")
    phantom.save_run_data(value=json.dumps(URL_LIST_TO_CONTAIN), key="URL_LIST_TO_CONTAIN", auto=True)
    
    Remove_the_top_URL_from_the_array__url_count = len(URL_LIST_TO_CONTAIN)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Remove_the_top_URL_from_the_array:url_count', value=json.dumps(Remove_the_top_URL_from_the_array__url_count))
    decision_30(container=container)

    return

def decision_30(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_30() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Remove_the_top_URL_from_the_array:custom_function:url_count", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        join_decision_27(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    Get_containment_status(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

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
    global URL_CONTAIN_FAILED
    Get_containment_status__is_contain_failed = URL_CONTAIN_FAILED

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Get_containment_status:is_contain_failed', value=json.dumps(Get_containment_status__is_contain_failed))
    decision_31(container=container)

    return

def decision_31(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_31() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Get_containment_status:custom_function:is_contain_failed", "==", False],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        add_note_51(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        filter_41(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    join_filter_42(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    add_note_54(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Format IP for Note
"""
def Format_IP_for_Note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_IP_for_Note() called')
    
    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_28:condition_1:IP_Reputation_on_VT_v3:action_result.parameter.ip'])
    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    Format_IP_for_Note__ip_list_markdown = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    output = ""
    
    for ip in filtered_results_item_1_0:
        output += f"- `{ip}`\n"
        
    Format_IP_for_Note__ip_list_markdown = output

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Format_IP_for_Note:ip_list_markdown', value=json.dumps(Format_IP_for_Note__ip_list_markdown))
    Format_IoC_IP(container=container)

    return

"""
Format URL for Note
"""
def Format_URL_for_Note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_URL_for_Note() called')
    
    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_IOC_URL:condition_1:Fetch_Active_Threat_Feed:action_result.data.*.value'])
    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    Format_URL_for_Note__url_list_markdown = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    output = ""
    
    for url in filtered_results_item_1_0:
        output += f"- `{url}`\n"
        
    Format_URL_for_Note__url_list_markdown = output

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Format_URL_for_Note:url_list_markdown', value=json.dumps(Format_URL_for_Note__url_list_markdown))
    Collect_all_URL(container=container)

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