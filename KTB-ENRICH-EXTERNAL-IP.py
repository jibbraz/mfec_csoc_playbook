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
Filter out external_ip
"""
def Filter_out_external_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_out_external_ip() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.external_ip", "!=", ""],
        ],
        name="Filter_out_external_ip:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        IP_Reputation_ext_IP_VT(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        WhoIS_ext_IP(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
IP Reputation ext IP VT
"""
def IP_Reputation_ext_IP_VT(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('IP_Reputation_ext_IP_VT() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'IP_Reputation_ext_IP_VT' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_external_ip:condition_1:artifact:*.cef.external_ip', 'filtered-data:Filter_out_external_ip:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'IP_Reputation_ext_IP_VT' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="ip reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=IP_Reputation_ext_IP_TS, name="IP_Reputation_ext_IP_VT")

    return

"""
IP Reputation ext IP TS
"""
def IP_Reputation_ext_IP_TS(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('IP_Reputation_ext_IP_TS() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'IP_Reputation_ext_IP_TS' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_external_ip:condition_1:artifact:*.cef.external_ip', 'filtered-data:Filter_out_external_ip:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'IP_Reputation_ext_IP_TS' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                'limit': 1000,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="ip reputation", parameters=parameters, assets=['threatstream hybrid vm','threatstream cloud'], callback=join_filter_32, name="IP_Reputation_ext_IP_TS", parent_action=action)

    return

"""
Add note ext IP
"""
def Add_note_ext_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_ext_IP() called')
    
    Collect_all_results_ext_IP__all_results_ext_IP = json.loads(phantom.get_run_data(key='Collect_all_results_ext_IP:all_results_ext_IP'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    data = Collect_all_results_ext_IP__all_results_ext_IP
    content = ""
    for artifact in data:
        content += f"Source IP address: {data[artifact]['ts']['ip']}\n\n"
        content += f"**VirusTotal IP Reputation**\n" 
        content += f"- Malicious count: {data[artifact]['vt']['summary_malicious']}\n\n"
        content += f"- Summary: {'N/A' if data[artifact]['vt']['summary_malicious'] == None else 'MALICIOUS' if data[artifact]['vt']['summary_malicious'] > 2 else 'NON-MALICIOUS'}\n\n"
        
        content += f"**ThreatStream IP Repuation**\n"
        content += f"- Threat type: {', '.join(data[artifact]['ts']['threat_types']) if data[artifact]['ts']['threat_types'] != [] else '-'}\n\n"
        content += f"- Summary: {'MALICIOUS' if len(data[artifact]['ts']['threat_types']) > 0 else 'NON-MALICIOUS'}\n\n"
        
        content += f"**WhoIS IP**\n"
        content += f"- Summary: {data[artifact]['whois_ts']['summary']}\n\n"
        content += "---\n"
        
    #phantom.debug(filtered_artifacts_item_1_1[0])
    #phantom.debug(str(results_item_1_0[0]))
    #phantom.debug(str(results_item_2_0[0]))
    #phantom.debug(str(results_item_3_0[0]))
    
    note_title = "External IP Investigation"
    note_content = content
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    ################################################################################
    ## Custom Code End
    ################################################################################
    Update_ext_IP_artifact(container=container)

    return

"""
Update ext IP artifact
"""
def Update_ext_IP_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Update_ext_IP_artifact() called')
    
    Collect_all_results_ext_IP__all_results_ext_IP = json.loads(phantom.get_run_data(key='Collect_all_results_ext_IP:all_results_ext_IP'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    data = Collect_all_results_ext_IP__all_results_ext_IP
    malicious_artifact_list = []
    
    for artifact in data:
        if data[artifact]['ts']['threat_types'] != [] or (data[artifact]['vt']['summary_malicious'] != None and data[artifact]['vt']['summary_malicious'] > 2):
            malicious_artifact_list.append(artifact)
    
    parameters = []
    cef_json = {"external_ip_malicious" : "True"}
    for artifact in malicious_artifact_list:
        # build parameters list for 'update_artifact_2' call
        parameters.append({
            'artifact_id': artifact,
            'name': "",
            'label': "",
            'severity': "",
            'cef_json': cef_json,
            'cef_types_json': "",
            'tags': "",
            'overwrite': "",
            'artifact_json': "",
        })
        
    if malicious_artifact_list:
        phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_ext_ip")

    parameters = []
    for artifact in malicious_artifact_list:
        parameters.append({
            'artifact_id': artifact,
            'add_tags': "indicator_malicious",
            'remove_tags': "",
        })
    
    if malicious_artifact_list:
        phantom.act(action="update artifact tags", parameters=parameters, assets=['phantom asset'], name="update_artifact_tags")

    ################################################################################
    ## Custom Code End
    ################################################################################

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
    phantom.custom_function(custom_function='local/Set_last_automated_action', parameters=parameters, name='cf_local_Set_last_automated_action_1', callback=Filter_out_external_ip)

    return

def filter_32(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_32() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            [1, "==", 1],
        ],
        name="filter_32:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Collect_all_results_ext_IP(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def join_filter_32(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_filter_32() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['IP_Reputation_ext_IP_TS', 'WhoIS_ext_IP']):
        
        # call connected block "filter_32"
        filter_32(container=container, handle=handle)
    
    return

"""
Collect all results ext IP
"""
def Collect_all_results_ext_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Collect_all_results_ext_IP() called')
    
    input_parameter_0 = ""

    Collect_all_results_ext_IP__all_results_ext_IP = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    all_results_ext_IP = {}
    # Get results from VT
    results_data_vt = phantom.collect2(scope="all", container=container, datapath=['IP_Reputation_ext_IP_VT:action_result.parameter.context.artifact_id', 'IP_Reputation_ext_IP_VT:action_result.summary.malicious'], action_results=results)
    for row in results_data_vt:
        #phantom.debug(f"{row[0]} ---- {row[1]}")
        artifact_id = row[0]
        summary_malicious = row[1]
        if all_results_ext_IP.get(artifact_id, None) == None:
            all_results_ext_IP[artifact_id] = {}
        if all_results_ext_IP[artifact_id].get('vt', None) == None:
            summary_malicious = 0 if summary_malicious == None else summary_malicious
            all_results_ext_IP[artifact_id]['vt'] = {'summary_malicious': summary_malicious}
        else:
            all_results_ext_IP[artifact_id]['vt']['summary_malicious'] = 0 if all_results_ext_IP[artifact_id]['vt']['summary_malicious'] == None else all_results_ext_IP[artifact_id]['vt']['summary_malicious']
            all_results_ext_IP[artifact_id] = {'vt': {'summary_malicious': max(summary_malicious, all_results_ext_IP[artifact_id]['vt']['summary_malicious'])}}
    
    # Get results from TS
    results_data_ts = phantom.collect2(scope="all", container=container, datapath=['IP_Reputation_ext_IP_TS:action_results'], action_results=results)
    results_item_ts = [item[0] for item in results_data_ts]
    for asset in results_item_ts:
        for artifact in asset:
            artifact_id = artifact['parameter']['context']['artifact_id']
            ip = artifact['parameter']['ip']
            status = artifact['status']
            
            if all_results_ext_IP.get(artifact_id, None) == None:
                all_results_ext_IP[artifact_id] = {}
            if all_results_ext_IP[artifact_id].get('ts', None) == None:
                all_results_ext_IP[artifact_id]['ts'] = {
                   'ip': ip,
                   'status': status,
                   'threat_types': []
               }
            
            for data in artifact['data']:
                threat_type = data.get('threat_type', None)
                status = data.get('status', None)
                if threat_type and status != 'falsepos' and threat_type not in all_results_ext_IP[artifact_id]['ts']['threat_types']:
                    all_results_ext_IP[artifact_id]['ts']['threat_types'].append(threat_type)
                #phantom.debug(f"artifact: {artifact['parameter']['context']['artifact_id']}, domain: {artifact['parameter']['url']}, status: {artifact['status']}, threat_type: {threat_types}")

    # Get results from WhoIS TS
    results_data_whois_ts = phantom.collect2(scope="all", container=container, datapath=['WhoIS_ext_IP:action_result.parameter.context.artifact_id', 'WhoIS_ext_IP:action_result.message'], action_results=results)
    for row in results_data_whois_ts:
        #phantom.debug(f"{row[0]} ---- {row[1]}")
        artifact_id = row[0]
        summary = row[1]
        if all_results_ext_IP.get(artifact_id, None) == None:
            all_results_ext_IP[artifact_id] = {}
        if all_results_ext_IP[artifact_id].get('whois_ts', None) == None:
            summary = '-' if summary == None else summary
            all_results_ext_IP[artifact_id]['whois_ts'] = {'summary': summary}
    Collect_all_results_ext_IP__all_results_ext_IP = all_results_ext_IP
    #phantom.debug(Collect_all_results_ext_IP__all_results_ext_IP)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Collect_all_results_ext_IP:all_results_ext_IP', value=json.dumps(Collect_all_results_ext_IP__all_results_ext_IP))
    Add_note_ext_IP(container=container)

    return

"""
WhoIS ext IP
"""
def WhoIS_ext_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('WhoIS_ext_IP() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'WhoIS_ext_IP' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_external_ip:condition_1:artifact:*.cef.external_ip', 'filtered-data:Filter_out_external_ip:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'WhoIS_ext_IP' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="whois ip", parameters=parameters, assets=['whois_rdap'], callback=join_filter_32, name="WhoIS_ext_IP")

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