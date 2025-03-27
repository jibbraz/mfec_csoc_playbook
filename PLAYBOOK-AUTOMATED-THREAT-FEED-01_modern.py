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

@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'fetch_active_threat_feed' block
    fetch_active_threat_feed(container=container)

    return

@phantom.playbook_block()
def domain_reputation_on_umbrella(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_reputation_on_umbrella() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'domain_reputation_on_umbrella' call
    formatted_data_1 = phantom.get_format_data(name='format_domain__as_list')

    parameters = []
    
    # build parameters list for 'domain_reputation_on_umbrella' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'domain': formatted_part_1,
        })

    phantom.act(action="domain reputation", parameters=parameters, assets=['ktb-umbrella-asset'], callback=join_filter_23, name="domain_reputation_on_umbrella")

    return

@phantom.playbook_block()
def url_add_investigated_and_benign_tags(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_add_investigated_and_benign_tags() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'url_add_investigated_and_benign_tags' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_40:condition_1:fetch_active_threat_feed:action_result.data.*.id", "filtered-data:filter_40:condition_1:fetch_active_threat_feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'url_add_investigated_and_benign_tags' call
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

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], name="url_add_investigated_and_benign_tags")

    return

@phantom.playbook_block()
def fetch_active_threat_feed(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('fetch_active_threat_feed() called')

    # collect data for 'fetch_active_threat_feed' call

    parameters = []
    
    # build parameters list for 'fetch_active_threat_feed' call
    parameters.append({
        'limit': 45,
        'query': "{\"q\":\"status=active AND tags=phantominput AND NOT tags=phantominvestigated\"}",
        'offset': "",
        'order_by': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['threatstream hybrid vm'], callback=fetch_active_threat_feed_callback, name="fetch_active_threat_feed")

    return

@phantom.playbook_block()
def fetch_active_threat_feed_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('fetch_active_threat_feed_callback() called')
    
    filter_ioc_domain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    filter_ioc_url(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    filter_ioc_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    filter_ioc_file_hash(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

@phantom.playbook_block()
def format_url_Containment_Query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_url_Containment_Query() called')
    
    template = """%%
summariesonly=t count as evt_count from datamodel=Web where (Web.url=\"{0}\") AND Web.sourcetype!=\"stream:http\"  AND Web.action=\"blocked\" earliest=-2d@d latest=now
| fields evt_count
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_29:condition_1:url_reputation_on_vt_v3:action_result.parameter.url",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_url_Containment_Query", separator=", ")

    run_url_containment_query(container=container)

    return

@phantom.playbook_block()
def run_url_containment_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_url_containment_query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_url_containment_query' call
    formatted_data_1 = phantom.get_format_data(name='format_url_Containment_Query__as_list')

    parameters = []
    
    # build parameters list for 'run_url_containment_query' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'query': formatted_part_1,
            'command': "tstats",
            'display': "evt_count",
            'parse_only': False,
        })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=decision_19, name="run_url_containment_query")

    return

@phantom.playbook_block()
def format_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ip() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_ioc_ip:condition_1:fetch_active_threat_feed:action_result.data.*.value",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ip", separator=", ")

    ip_reputation_on_vt_v3(container=container)

    return

@phantom.playbook_block()
def format_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_url() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_ioc_url:condition_1:fetch_active_threat_feed:action_result.data.*.value",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_url", separator=", ")

    url_reputation_on_vt_v3(container=container)

    return

@phantom.playbook_block()
def format_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_domain() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_ioc_domain:condition_1:fetch_active_threat_feed:action_result.data.*.value",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_domain", separator=", ")

    domain_reputation_on_umbrella(container=container)
    domain_reputation_on_vt_v3(container=container)

    return

@phantom.playbook_block()
def format_file_hash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_file_hash() called')
    
    template = """%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_ioc_file_hash:condition_1:fetch_active_threat_feed:action_result.data.*.value",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_file_hash", separator=", ")

    file_reputation_on_vt_v(container=container)

    return

@phantom.playbook_block()
def filter_ioc_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_ioc_url() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["fetch_active_threat_feed:action_result.data.*.type", "==", "url"],
        ],
        name="filter_ioc_url:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_url(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def filter_ioc_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_ioc_ip() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["fetch_active_threat_feed:action_result.data.*.type", "==", "ip"],
        ],
        name="filter_ioc_ip:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def filter_ioc_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_ioc_domain() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["fetch_active_threat_feed:action_result.data.*.type", "==", "domain"],
        ],
        name="filter_ioc_domain:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_domain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def format_ip_Containment_Query_on_VT(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ip_Containment_Query_on_VT() called')
    
    template = """%%
summariesonly=t count as evt_count from datamodel=Network_Traffic where Network_Traffic.sourcetype=\"pan:traffic\" AND Network_Traffic.action=\"deny\" AND ( Network_Traffic.dest_ip=\"{0}\" OR Network_Traffic.src_ip=\"{0}\" )
earliest=-7d@d latest=now
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_28:condition_1:ip_reputation_on_vt_v3:action_result.parameter.ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ip_Containment_Query_on_VT", separator=", ")

    run_ip_query_for_vt(container=container)

    return

@phantom.playbook_block()
def run_ip_query_for_vt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_ip_query_for_vt() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_ip_query_for_vt' call
    formatted_data_1 = phantom.get_format_data(name='format_ip_Containment_Query_on_VT__as_list')

    parameters = []
    
    # build parameters list for 'run_ip_query_for_vt' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'query': formatted_part_1,
            'command': "tstats",
            'display': "evt_count",
            'parse_only': False,
        })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=decision_13, name="run_ip_query_for_vt")

    return

@phantom.playbook_block()
def filter_23(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_23() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["domain_reputation_on_vt_v3:action_result.summary.malicious", ">", 2],
            ["domain_reputation_on_umbrella:action_result.summary.domain_status", "==", "MALICIOUS"],
        ],
        logical_operator='or',
        name="filter_23:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_33(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        join_email_content(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["domain_reputation_on_umbrella:action_result.summary.domain_status", "!=", "MALICIOUS"],
            ["domain_reputation_on_vt_v3:action_result.summary.malicious", "<=", 2],
        ],
        logical_operator='and',
        name="filter_23:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        filter_43(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

@phantom.playbook_block()
def join_filter_23(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_filter_23() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_filter_23_called'):
        return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['domain_reputation_on_umbrella']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_filter_23_called', value='filter_23')
        
        # call connected block "filter_23"
        filter_23(container=container, handle=handle)
    
    return

@phantom.playbook_block()
def filter_ioc_file_hash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_ioc_file_hash() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["fetch_active_threat_feed:action_result.data.*.type", "==", "md5"],
        ],
        name="filter_ioc_file_hash:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_file_hash(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def add_malicious_and_contained_tags_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_malicious_and_contained_tags_url() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_malicious_and_contained_tags_url' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_38:condition_1:fetch_active_threat_feed:action_result.data.*.id", "filtered-data:filter_38:condition_1:fetch_active_threat_feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'add_malicious_and_contained_tags_url' call
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

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], callback=add_note_71, name="add_malicious_and_contained_tags_url")

    return

@phantom.playbook_block()
def decision_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_13() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["run_ip_query_for_vt:action_result.data.*.evt_count", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        filter_34(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    format_ip_for_Note(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

@phantom.playbook_block()
def format_ioc_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ioc_ip() called')
    
    template = """Below Malicious IPs are NOT being contained and will be prompted to SoC Admin to decide whether executing containment:
%%
{0}

%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_28:condition_1:ip_reputation_on_vt_v3:action_result.parameter.ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ioc_ip", separator=", ")

    prompt_block_ip(container=container)

    return

@phantom.playbook_block()
def format_hash_containment_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_hash_containment_query() called')
    
    template = """%%
summariesonly=t count as evt_count from datamodel=Intrusion_Detection where Intrusion_Detection.sourcetype=\"fortinet:sandbox:syslog\" AND Intrusion_Detection.file_hash={0} AND Intrusion_Detection.action=\"blocked\" AND Intrusion_Detection.action=\"block\" AND Intrusion_Detection.action=\"denied\" earliest=-7d@d latest=now
| fields evt_count
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_44:condition_1:file_reputation_on_vt_v:action_result.parameter.hash",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_hash_containment_query", separator=", ")

    run_hash_containment_query(container=container)

    return

@phantom.playbook_block()
def run_hash_containment_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_hash_containment_query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_hash_containment_query' call
    formatted_data_1 = phantom.get_format_data(name='format_hash_containment_query__as_list')

    parameters = []
    
    # build parameters list for 'run_hash_containment_query' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'query': formatted_part_1,
            'command': "tstats",
            'display': "evt_count",
            'parse_only': False,
        })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=decision_21, name="run_hash_containment_query")

    return

@phantom.playbook_block()
def format_email_to_soc(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_email_to_soc() called')
    
    template = """Below Malicious File Hash are NOT being contained:
%%
{0}

%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_ioc_file_hash:condition_1:fetch_active_threat_feed:action_result.data.*.value",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_email_to_soc", separator=", ")

    add_note_66(container=container)

    return

@phantom.playbook_block()
def add_investigated_and_malicious_tags_hash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_investigated_and_malicious_tags_hash() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_investigated_and_malicious_tags_hash' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_47:condition_1:fetch_active_threat_feed:action_result.data.*.id", "filtered-data:filter_47:condition_1:fetch_active_threat_feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'add_investigated_and_malicious_tags_hash' call
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

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], callback=format_email_to_soc, name="add_investigated_and_malicious_tags_hash")

    return

@phantom.playbook_block()
def prompt_block_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_block_ip() called')
    
    # set user and message variables for phantom.prompt call
    user = "Tier2 Analyst"
    message = """***WARNING*** 
Do you want to proceed with containment?

Attacker Info:
Source Address = {0}"""

    # parameter list for template variable replacement
    parameters = [
        "format_ioc_ip:formatted_data",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=5, name="prompt_block_ip", separator=", ", parameters=parameters, response_types=response_types, callback=decision_15)

    return

@phantom.playbook_block()
def decision_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_15() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_block_ip:action_result.summary.responses.0", "==", "Yes"],
            ["prompt_block_ip:action_result.status", "==", "success"],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        get_total_amount_of_ip_address(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_block_ip:action_result.summary.responses.0", "==", "No"],
            ["prompt_block_ip:action_result.status", "==", "success"],
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
            ["prompt_block_ip:action_result.status", "==", "failed"],
        ])

    # call connected blocks if condition 3 matched
    if matched:
        filter_37(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def email_content(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('email_content() called')
    
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
        "filtered-data:filter_29:condition_1:url_reputation_on_vt_v3:action_result.parameter.url",
        "filtered-data:filter_28:condition_1:ip_reputation_on_vt_v3:action_result.parameter.ip",
        "filtered-data:filter_23:condition_1:domain_reputation_on_vt_v3:action_result.parameter.domain",
        "filtered-data:filter_44:condition_1:file_reputation_on_vt_v:action_result.parameter.hash",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="email_content", separator=", ")

    notify_soc_team_via_email(container=container)

    return

@phantom.playbook_block()
def join_email_content(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_email_content() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['url_reputation_on_vt_v3', 'file_reputation_on_vt_v', 'domain_reputation_on_vt_v3', 'domain_reputation_on_umbrella', 'ip_reputation_on_vt_v3']):
        
        # call connected block "email_content"
        email_content(container=container, handle=handle)
    
    return

@phantom.playbook_block()
def notify_soc_team_via_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('notify_soc_team_via_email() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'notify_soc_team_via_email' call
    formatted_data_1 = phantom.get_format_data(name='email_content')

    parameters = []
    
    # build parameters list for 'notify_soc_team_via_email' call
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

    phantom.act(action="send email", parameters=parameters, assets=['smtp asset'], name="notify_soc_team_via_email")

    return

@phantom.playbook_block()
def prompt_url_containment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_url_containment() called')
    
    # set user and message variables for phantom.prompt call
    user = "Tier2 Analyst"
    message = """***WARNING*** 
Do you want to proceed with containment?

Malicious URL :
URL = {0}"""

    # parameter list for template variable replacement
    parameters = [
        "url_reputation_on_vt_v3:action_result.parameter.url",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=5, name="prompt_url_containment", separator=", ", parameters=parameters, response_types=response_types, callback=decision_17)

    return

@phantom.playbook_block()
def decision_17(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_17() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_url_containment:action_result.status", "==", "success"],
            ["prompt_url_containment:action_result.summary.responses.0", "==", "Yes"],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        format_url_for_Note(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_url_containment:action_result.status", "==", "success"],
            ["prompt_url_containment:action_result.summary.responses.0", "==", "No"],
        ],
        logical_operator='and')

    # call connected blocks if condition 2 matched
    if matched:
        add_malicious_and_noncontained_tags_url(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        add_note_41(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 3
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_url_containment:action_result.status", "==", "failed"],
        ])

    # call connected blocks if condition 3 matched
    if matched:
        add_note_40(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        add_malicious_and_noncontained_tags_url(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def add_malicious_and_contained_tag_hash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_malicious_and_contained_tag_hash() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_malicious_and_contained_tag_hash' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_46:condition_1:fetch_active_threat_feed:action_result.data.*.id", "filtered-data:filter_46:condition_1:fetch_active_threat_feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'add_malicious_and_contained_tag_hash' call
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

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], callback=email_content_hash, name="add_malicious_and_contained_tag_hash")

    return

@phantom.playbook_block()
def email_content_hash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('email_content_hash() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_ioc_file_hash:condition_1:fetch_active_threat_feed:action_result.data.*.value",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="email_content_hash", separator=", ")

    add_note_64(container=container)

    return

@phantom.playbook_block()
def add_note_40(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_40() called')

    note_title = "Can not get approval for Containment Action"
    note_content = "Can not get approval for Containment Action"
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

@phantom.playbook_block()
def add_malicious_and_noncontained_tags_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_malicious_and_noncontained_tags_url() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_malicious_and_noncontained_tags_url' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_ioc_url:condition_1:fetch_active_threat_feed:action_result.data.*.id", "filtered-data:filter_ioc_url:condition_1:fetch_active_threat_feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'add_malicious_and_noncontained_tags_url' call
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

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], name="add_malicious_and_noncontained_tags_url")

    return

@phantom.playbook_block()
def add_note_41(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_41() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_ioc_url:condition_1:fetch_active_threat_feed:action_result.data.*.value'])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    note_title = "Containment Action is Not Approved"
    note_content = filtered_results_item_1_0
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

@phantom.playbook_block()
def url_reputation_on_vt_v3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_reputation_on_vt_v3() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'url_reputation_on_vt_v3' call
    formatted_data_1 = phantom.get_format_data(name='format_url__as_list')

    parameters = []
    
    # build parameters list for 'url_reputation_on_vt_v3' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'url': formatted_part_1,
        })

    phantom.act(action="url reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=filter_29, name="url_reputation_on_vt_v3")

    return

@phantom.playbook_block()
def decision_19(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_19() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["run_url_containment_query:action_result.data.*.evt_count", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        filter_38(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    join_filter_42(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

@phantom.playbook_block()
def add_contained_tag_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_contained_tag_url() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_contained_tag_url' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_41:condition_1:fetch_active_threat_feed:action_result.data.*.id", "filtered-data:filter_41:condition_1:fetch_active_threat_feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'add_contained_tag_url' call
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

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], name="add_contained_tag_url")

    return

@phantom.playbook_block()
def add_noncontained_tag_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_noncontained_tag_url() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_noncontained_tag_url' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_ioc_url:condition_1:fetch_active_threat_feed:action_result.data.*.id", "filtered-data:filter_ioc_url:condition_1:fetch_active_threat_feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'add_noncontained_tag_url' call
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

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], name="add_noncontained_tag_url")

    return

@phantom.playbook_block()
def add_note_51(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_51() called')

    format_url_for_Note__url_list_markdown = json.loads(phantom.get_run_data(key='format_url_for_Note:url_list_markdown'))

    note_title = "URL successfully blocked on FortiGate "
    note_content = format_url_for_Note__url_list_markdown
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

@phantom.playbook_block()
def decision_21(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_21() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["run_hash_containment_query:action_result.data.*.evt_count", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        filter_46(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    filter_47(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

@phantom.playbook_block()
def file_reputation_on_vt_v(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('file_reputation_on_vt_v() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'file_reputation_on_vt_v' call
    formatted_data_1 = phantom.get_format_data(name='format_file_hash__as_list')

    parameters = []
    
    # build parameters list for 'file_reputation_on_vt_v' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'hash': formatted_part_1,
        })

    phantom.act(action="file reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=filter_44, name="file_reputation_on_vt_v")

    return

@phantom.playbook_block()
def add_benign_and_investigated_tag(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_benign_and_investigated_tag() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_benign_and_investigated_tag' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_45:condition_1:fetch_active_threat_feed:action_result.data.*.id", "filtered-data:filter_45:condition_1:fetch_active_threat_feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'add_benign_and_investigated_tag' call
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

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], callback=form_email_file_hash, name="add_benign_and_investigated_tag")

    return

@phantom.playbook_block()
def form_email_file_hash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('form_email_file_hash() called')
    
    template = """Hi SOC,
Below IOC File Hash have been taged as \" PhantomInvestigated\" and \"PhantomBenign\"
%%
{0}
%%
Thanks"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_ioc_file_hash:condition_1:fetch_active_threat_feed:action_result.data.*.value",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="form_email_file_hash", separator=", ")

    add_note_65(container=container)

    return

@phantom.playbook_block()
def ip_reputation_on_vt_v3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_reputation_on_vt_v3() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ip_reputation_on_vt_v3' call
    formatted_data_1 = phantom.get_format_data(name='format_ip__as_list')

    parameters = []
    
    # build parameters list for 'ip_reputation_on_vt_v3' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'ip': formatted_part_1,
        })

    phantom.act(action="ip reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=filter_28, name="ip_reputation_on_vt_v3")

    return

@phantom.playbook_block()
def add_noncontained_tag_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_noncontained_tag_ip() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_noncontained_tag_ip' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_36:condition_1:fetch_active_threat_feed:action_result.data.*.id", "filtered-data:filter_36:condition_1:fetch_active_threat_feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'add_noncontained_tag_ip' call
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

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], callback=add_note_74, name="add_noncontained_tag_ip")

    return

@phantom.playbook_block()
def add_contained_tag_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_contained_tag_ip() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_contained_tag_ip' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_35:condition_1:fetch_active_threat_feed:action_result.data.*.id", "filtered-data:filter_35:condition_1:fetch_active_threat_feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'add_contained_tag_ip' call
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

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], callback=add_note_63, name="add_contained_tag_ip")

    return

@phantom.playbook_block()
def add_malicious_and_noncontained_tag_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_malicious_and_noncontained_tag_ip() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_malicious_and_noncontained_tag_ip' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_37:condition_1:fetch_active_threat_feed:action_result.data.*.id", "filtered-data:filter_37:condition_1:fetch_active_threat_feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'add_malicious_and_noncontained_tag_ip' call
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

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], name="add_malicious_and_noncontained_tag_ip")

    return

@phantom.playbook_block()
def domain_reputation_on_vt_v3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_reputation_on_vt_v3() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'domain_reputation_on_vt_v3' call
    formatted_data_1 = phantom.get_format_data(name='format_domain__as_list')

    parameters = []
    
    # build parameters list for 'domain_reputation_on_vt_v3' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'domain': formatted_part_1,
        })

    phantom.act(action="domain reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=join_filter_23, name="domain_reputation_on_vt_v3")

    return

@phantom.playbook_block()
def add_note_53(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_53() called')

    formatted_data_1 = phantom.get_format_data(name='format_vt_failure')

    note_title = "Failure occurred on VirusTotal"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

@phantom.playbook_block()
def format_vt_failure(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_vt_failure() called')
    
    template = """IoC File Hash VirusTotal Failure
%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_ioc_file_hash:condition_1:fetch_active_threat_feed:action_result.data.*.value",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_vt_failure", separator=", ")

    add_note_53(container=container)

    return

@phantom.playbook_block()
def add_note_54(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_54() called')

    format_url_for_Note__url_list_markdown = json.loads(phantom.get_run_data(key='format_url_for_Note:url_list_markdown'))

    note_title = "URL IoC Failed to be blocked on FortiGate"
    note_content = format_url_for_Note__url_list_markdown
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

@phantom.playbook_block()
def filter_28(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_28() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ip_reputation_on_vt_v3:action_result.summary.malicious", ">", 2],
            ["filtered-data:filter_ioc_ip:condition_1:fetch_active_threat_feed:action_result.data.*.value", "!=", ""],
        ],
        logical_operator='and',
        name="filter_28:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_ip_Containment_Query_on_VT(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        join_email_content(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ip_reputation_on_vt_v3:action_result.summary.malicious", "<=", 2],
            ["filtered-data:filter_ioc_ip:condition_1:fetch_active_threat_feed:action_result.data.*.value", "!=", ""],
        ],
        logical_operator='and',
        name="filter_28:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        filter_39(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

@phantom.playbook_block()
def add_note_56(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_56() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_33:condition_1:fetch_active_threat_feed:action_result.data.*.value'])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    note_title = "Umbrella Malicious IoC Domain"
    note_content = filtered_results_item_1_0
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

@phantom.playbook_block()
def domain_ioc_add_malicious_tag(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_ioc_add_malicious_tag() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'domain_ioc_add_malicious_tag' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_33:condition_1:fetch_active_threat_feed:action_result.data.*.id", "filtered-data:filter_33:condition_1:fetch_active_threat_feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'domain_ioc_add_malicious_tag' call
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

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], callback=add_note_56, name="domain_ioc_add_malicious_tag")

    return

@phantom.playbook_block()
def add_malicious_and_contained_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_malicious_and_contained_ip() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_malicious_and_contained_ip' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_34:condition_1:fetch_active_threat_feed:action_result.data.*.id", "filtered-data:filter_34:condition_1:fetch_active_threat_feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'add_malicious_and_contained_ip' call
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

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], callback=add_note_61, name="add_malicious_and_contained_ip")

    return

@phantom.playbook_block()
def add_note_61(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_61() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_34:condition_1:ip_reputation_on_vt_v3:action_result.parameter.ip'])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    note_title = "Investigated and Bening IoC IP"
    note_content = filtered_results_item_1_0
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

@phantom.playbook_block()
def filter_29(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_29() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["url_reputation_on_vt_v3:action_result.summary.malicious", ">", 2],
            ["url_reputation_on_vt_v3:action_result.status", "==", "success"],
        ],
        logical_operator='and',
        name="filter_29:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_url_Containment_Query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        join_email_content(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["url_reputation_on_vt_v3:action_result.summary.malicious", "<=", 2],
            ["url_reputation_on_vt_v3:action_result.status", "==", "success"],
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
            ["url_reputation_on_vt_v3:action_result.status", "==", "failed"],
        ],
        name="filter_29:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        add_note_77(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    return

@phantom.playbook_block()
def add_note_63(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_63() called')

    format_ip_for_Note__ip_list_markdown = json.loads(phantom.get_run_data(key='format_ip_for_Note:ip_list_markdown'))

    note_title = "IP address successfully added to the list waiting to contain"
    note_content = format_ip_for_Note__ip_list_markdown
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

@phantom.playbook_block()
def add_note_64(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_64() called')

    formatted_data_1 = phantom.get_format_data(name='email_content_hash')

    note_title = "Malicious File Hash IoC"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

@phantom.playbook_block()
def add_note_65(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_65() called')

    formatted_data_1 = phantom.get_format_data(name='form_email_file_hash')

    note_title = "Benign File Hash IoC"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

@phantom.playbook_block()
def add_note_66(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_66() called')

    formatted_data_1 = phantom.get_format_data(name='format_email_to_soc')

    note_title = "NonContained File Hash IoC"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

@phantom.playbook_block()
def add_note_68(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_68() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_43:condition_1:fetch_active_threat_feed:action_result.data.*.value'])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    note_title = "Benign Domain IoC -- Umbrella and VT"
    note_content = filtered_results_item_1_0
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

@phantom.playbook_block()
def filter_33(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_33() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_23:condition_1:domain_reputation_on_vt_v3:action_result.parameter.domain", "==", "filtered-data:filter_ioc_domain:condition_1:fetch_active_threat_feed:action_result.data.*.value"],
        ],
        name="filter_33:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        domain_ioc_add_malicious_tag(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def filter_34(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_34() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_28:condition_1:ip_reputation_on_vt_v3:action_result.parameter.ip", "==", "filtered-data:filter_ioc_ip:condition_1:fetch_active_threat_feed:action_result.data.*.value"],
        ],
        name="filter_34:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_malicious_and_contained_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def filter_35(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_35() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_28:condition_1:ip_reputation_on_vt_v3:action_result.parameter.ip", "==", "filtered-data:filter_28:condition_1:fetch_active_threat_feed:action_result.data.*.value"],
        ],
        name="filter_35:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_contained_tag_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def filter_36(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_36() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_28:condition_1:ip_reputation_on_vt_v3:action_result.parameter.ip", "==", "filtered-data:filter_28:condition_1:fetch_active_threat_feed:action_result.data.*.value"],
        ],
        name="filter_36:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_noncontained_tag_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def filter_37(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_37() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_28:condition_1:ip_reputation_on_vt_v3:action_result.parameter.ip", "==", "filtered-data:filter_28:condition_1:fetch_active_threat_feed:action_result.data.*.value"],
        ],
        name="filter_37:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_malicious_and_noncontained_tag_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def filter_38(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_38() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_29:condition_1:url_reputation_on_vt_v3:action_result.parameter.url", "==", "filtered-data:filter_ioc_url:condition_1:fetch_active_threat_feed:action_result.data.*.value"],
        ],
        name="filter_38:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_malicious_and_contained_tags_url(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def add_note_71(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_71() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_38:condition_1:url_reputation_on_vt_v3:action_result.parameter.url'])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    note_title = "Already contained URL IoC"
    note_content = filtered_results_item_1_0
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

@phantom.playbook_block()
def filter_39(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_39() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_28:condition_2:ip_reputation_on_vt_v3:action_result.parameter.ip", "==", "filtered-data:filter_28:condition_2:fetch_active_threat_feed:action_result.data.*.value"],
        ],
        name="filter_39:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_benign_tag_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def add_benign_tag_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_benign_tag_ip() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_benign_tag_ip' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_39:condition_1:fetch_active_threat_feed:action_result.data.*.id", "filtered-data:filter_39:condition_1:fetch_active_threat_feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'add_benign_tag_ip' call
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

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], name="add_benign_tag_ip")

    return

@phantom.playbook_block()
def filter_40(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_40() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_29:condition_2:url_reputation_on_vt_v3:action_result.parameter.url", "==", "filtered-data:filter_ioc_url:condition_1:fetch_active_threat_feed:action_result.data.*.value"],
        ],
        name="filter_40:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        url_add_investigated_and_benign_tags(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def filter_41(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_41() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_29:condition_1:url_reputation_on_vt_v3:action_result.parameter.url", "==", "filtered-data:filter_ioc_url:condition_1:fetch_active_threat_feed:action_result.data.*.value"],
        ],
        name="filter_41:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_contained_tag_url(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def filter_42(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_42() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_29:condition_1:url_reputation_on_vt_v3:action_result.parameter.url", "==", "filtered-data:filter_ioc_url:condition_1:fetch_active_threat_feed:action_result.data.*.value"],
        ],
        name="filter_42:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_noncontained_tag_url(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def join_filter_42(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_filter_42() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_filter_42_called'):
        return

    # no callbacks to check, call connected block "filter_42"
    phantom.save_run_data(key='join_filter_42_called', value='filter_42', auto=True)

    filter_42(container=container, handle=handle)
    
    return

@phantom.playbook_block()
def filter_43(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_43() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_23:condition_2:domain_reputation_on_vt_v3:action_result.parameter.domain", "==", "filtered-data:filter_ioc_domain:condition_1:fetch_active_threat_feed:action_result.data.*.value"],
        ],
        name="filter_43:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_benign_tag_domain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def add_benign_tag_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_benign_tag_domain() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_benign_tag_domain' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_43:condition_1:fetch_active_threat_feed:action_result.data.*.id", "filtered-data:filter_43:condition_1:fetch_active_threat_feed:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'add_benign_tag_domain' call
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

    phantom.act(action="tag observable", parameters=parameters, assets=['threatstream hybrid vm'], callback=add_note_68, name="add_benign_tag_domain")

    return

@phantom.playbook_block()
def add_note_74(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_74() called')

    format_ip_for_Note__ip_list_markdown = json.loads(phantom.get_run_data(key='format_ip_for_Note:ip_list_markdown'))

    note_title = "Failed to contain IP address due to amount exceeded"
    note_content = format_ip_for_Note__ip_list_markdown
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

@phantom.playbook_block()
def filter_44(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_44() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_on_vt_v:action_result.summary.malicious", ">", 2],
            ["file_reputation_on_vt_v:action_result.status", "==", "success"],
        ],
        logical_operator='and',
        name="filter_44:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_hash_containment_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        join_email_content(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_on_vt_v:action_result.summary.malicious", "<=", 2],
            ["file_reputation_on_vt_v:action_result.status", "==", "success"],
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
            ["file_reputation_on_vt_v:action_result.status", "==", "failed"],
        ],
        name="filter_44:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        format_vt_failure(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    return

@phantom.playbook_block()
def filter_45(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_45() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_44:condition_2:file_reputation_on_vt_v:action_result.parameter.hash", "==", "filtered-data:filter_ioc_file_hash:condition_1:fetch_active_threat_feed:action_result.data.*.value"],
        ],
        name="filter_45:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_benign_and_investigated_tag(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def filter_46(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_46() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_44:condition_1:file_reputation_on_vt_v:action_result.parameter.hash", "==", "filtered-data:filter_ioc_file_hash:condition_1:fetch_active_threat_feed:action_result.data.*.value"],
        ],
        name="filter_46:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_malicious_and_contained_tag_hash(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def filter_47(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_47() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_44:condition_1:file_reputation_on_vt_v:action_result.parameter.hash", "==", "filtered-data:filter_ioc_file_hash:condition_1:fetch_active_threat_feed:action_result.data.*.value"],
        ],
        name="filter_47:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_investigated_and_malicious_tags_hash(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def add_note_77(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_77() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_29:condition_3:url_reputation_on_vt_v3:action_result.parameter.url'])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    note_title = "IoC URL VT Failure"
    note_content = filtered_results_item_1_0
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

"""
Add malicious IP to custom list
"""
@phantom.playbook_block()
def add_malicious_ip_to_custom_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_malicious_ip_to_custom_list() called')
    
    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_28:condition_1:ip_reputation_on_vt_v3:action_result.parameter.ip'])
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
@phantom.playbook_block()
def get_total_amount_of_ip_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_total_amount_of_ip_address() called')
    
    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_28:condition_1:ip_reputation_on_vt_v3:action_result.parameter.ip'])
    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    get_total_amount_of_ip_address__total_num_of_ip = None

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
    get_total_amount_of_ip_address__total_num_of_ip = len(ipaddress_list)
    phantom.debug(f"Total IP in the list + to be added: {get_total_amount_of_ip_address__total_num_of_ip}")

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='get_total_amount_of_ip_address:total_num_of_ip', value=json.dumps(get_total_amount_of_ip_address__total_num_of_ip))
    decision_26(container=container)

    return

@phantom.playbook_block()
def decision_26(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_26() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_total_amount_of_ip_address:custom_function:total_num_of_ip", "<=", 20],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        add_malicious_ip_to_custom_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    filter_36(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Collect all URL
"""
@phantom.playbook_block()
def collect_all_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('collect_all_url() called')
    
    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_ioc_url:condition_1:fetch_active_threat_feed:action_result.data.*.value'])
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

@phantom.playbook_block()
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
        get_the_top_url_from_the_array(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def join_decision_27(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_decision_27() called')
    
    # if the joined function has already been called, do nothing
    #if phantom.get_run_data(key='join_decision_27_called'):
    #    return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    #if phantom.completed(action_names=['run_url_containment_query']):
        
    # save the state that the joined function has now been called
    phantom.save_run_data(key='join_decision_27_called', value='decision_27')
        
    # call connected block "decision_27"
    decision_27(container=container, handle=handle)
    
    return

"""
Get the top URL from the array
"""
@phantom.playbook_block()
def get_the_top_url_from_the_array(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_the_top_url_from_the_array() called')
    
    input_parameter_0 = ""

    get_the_top_url_from_the_array__top_url = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    URL_LIST_TO_CONTAIN = json.loads(phantom.get_run_data(key="URL_LIST_TO_CONTAIN"))
    phantom.debug(f"Starting loop with: {URL_LIST_TO_CONTAIN}")
    if len(URL_LIST_TO_CONTAIN) > 0:
        get_the_top_url_from_the_array__top_url = URL_LIST_TO_CONTAIN[0]

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='get_the_top_url_from_the_array:top_url', value=json.dumps(get_the_top_url_from_the_array__top_url))
    decision_28(container=container)

    return

@phantom.playbook_block()
def decision_28(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_28() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_the_top_url_from_the_array:custom_function:top_url", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        prepare_url_artifact(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Prepare URL artifact
"""
@phantom.playbook_block()
def prepare_url_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prepare_url_artifact() called')
    
    template = """{{\"requestURL\": \"{0}\", \"requestURL_malicious\": \"True\"}}"""

    # parameter list for template variable replacement
    parameters = [
        "get_the_top_url_from_the_array:custom_function:top_url",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="prepare_url_artifact", separator=", ")

    add_url_artifact(container=container)

    return

"""
Add URL artifact
"""
@phantom.playbook_block()
def add_url_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_url_artifact() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    get_the_top_url_from_the_array__top_url = json.loads(phantom.get_run_data(key='get_the_top_url_from_the_array:top_url'))
    # collect data for 'add_url_artifact' call
    formatted_data_1 = phantom.get_format_data(name='prepare_url_artifact')

    parameters = []
    
    # build parameters list for 'add_url_artifact' call
    parameters.append({
        'name': "User created artifact",
        'label': "event",
        'cef_name': "",
        'contains': "",
        'cef_value': "",
        'container_id': "",
        'cef_dictionary': formatted_data_1,
        'run_automation': False,
        'source_data_identifier': get_the_top_url_from_the_array__top_url,
    })

    phantom.act(action="add artifact", parameters=parameters, assets=['phantom asset'], callback=fortigate_block_url, name="add_url_artifact")

    return

"""
FortiGate Block URL
"""
@phantom.playbook_block()
def fortigate_block_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('fortigate_block_url() called')
    
    URL_LIST_TO_CONTAIN = json.loads(phantom.get_run_data(key="URL_LIST_TO_CONTAIN"))

    # call playbook "local/PLAYBOOK-CONTAIN-INDICATOR-FORTIGATECSOC-URL", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/PLAYBOOK-CONTAIN-INDICATOR-FORTIGATEKTBCS-URL", container=container, name=f"fortigate_block_url_{len(URL_LIST_TO_CONTAIN)}", callback=sleep)

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

    phantom.act(action="no op", parameters=parameters, assets=['phantom asset'], callback=decision_29, name="sleep")

    return

@phantom.playbook_block()
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
    global URL_CONTAIN_FAILED
    URL_CONTAIN_FAILED = True
    phantom.debug("failed detected")

    ################################################################################
    ## Custom Code End
    ################################################################################
    join_delete_the_created_artifact(container=container)

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
        
    ####
    ################################################################################
    ## Custom Code End
    ################################################################################
    remove_the_top_url_from_the_array(container=container)

    return

@phantom.playbook_block()
def join_delete_the_created_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_delete_the_created_artifact() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    #if phantom.completed(action_names=['sleep']):
        
    # call connected block "delete_the_created_artifact"
    delete_the_created_artifact(container=container, handle=handle)
    
    return

"""
Remove the top URL from the array
"""
@phantom.playbook_block()
def remove_the_top_url_from_the_array(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('remove_the_top_url_from_the_array() called')
    
    input_parameter_0 = ""

    remove_the_top_url_from_the_array__url_count = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    URL_LIST_TO_CONTAIN = json.loads(phantom.get_run_data(key="URL_LIST_TO_CONTAIN"))
    phantom.debug(f"Before popping: {URL_LIST_TO_CONTAIN}")
    URL_LIST_TO_CONTAIN.pop(0)
    phantom.debug(f"After popping: {URL_LIST_TO_CONTAIN}")
    phantom.save_run_data(value=json.dumps(URL_LIST_TO_CONTAIN), key="URL_LIST_TO_CONTAIN", auto=True)
    
    remove_the_top_url_from_the_array__url_count = len(URL_LIST_TO_CONTAIN)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='remove_the_top_url_from_the_array:url_count', value=json.dumps(remove_the_top_url_from_the_array__url_count))
    decision_30(container=container)

    return

@phantom.playbook_block()
def decision_30(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_30() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["remove_the_top_url_from_the_array:custom_function:url_count", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        join_decision_27(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    get_containment_status(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

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
    global URL_CONTAIN_FAILED
    get_containment_status__is_contain_failed = URL_CONTAIN_FAILED

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='get_containment_status:is_contain_failed', value=json.dumps(get_containment_status__is_contain_failed))
    decision_31(container=container)

    return

@phantom.playbook_block()
def decision_31(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_31() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_containment_status:custom_function:is_contain_failed", "==", False],
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
@phantom.playbook_block()
def format_ip_for_Note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ip_for_Note() called')
    
    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_28:condition_1:ip_reputation_on_vt_v3:action_result.parameter.ip'])
    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    format_ip_for_Note__ip_list_markdown = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    output = ""
    
    for ip in filtered_results_item_1_0:
        output += f"- `{ip}`\n"
        
    format_ip_for_Note__ip_list_markdown = output

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='format_ip_for_Note:ip_list_markdown', value=json.dumps(format_ip_for_Note__ip_list_markdown))
    format_ioc_ip(container=container)

    return

"""
Format URL for Note
"""
@phantom.playbook_block()
def format_url_for_Note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_url_for_Note() called')
    
    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_ioc_url:condition_1:fetch_active_threat_feed:action_result.data.*.value'])
    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    format_url_for_Note__url_list_markdown = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    output = ""
    
    for url in filtered_results_item_1_0:
        output += f"- `{url}`\n"
        
    format_url_for_Note__url_list_markdown = output

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='format_url_for_Note:url_list_markdown', value=json.dumps(format_url_for_Note__url_list_markdown))
    collect_all_url(container=container)

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