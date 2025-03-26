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
        name="Filter_out_requestURL:condition_1",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Check_if_requestURL_external(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Check if requestURL external
"""
def Check_if_requestURL_external(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_if_requestURL_external() called')
    
    filtered_artifacts_data_1 = phantom.collect2(scope="all", container=container, datapath=['filtered-data:Filter_out_requestURL:condition_1:artifact:*.cef.requestURL'])
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
    url_raw_data = []
    for item in urllist:
        if not any(item in sublist for sublist in ktburllist):
            phantom.debug("{} is public".format(item))
            externaltemplist.append(item)
            #url_raw_data.append({'id': artifact_id_list[idx], 'url': item, 'is_external': True})
        else:
            phantom.debug("{} is private".format(item))
            internaltemplist.append(item)
            #url_raw_data.append({'id': artifact_id_list[idx], 'url': item, 'is_external': False})
            
    Check_if_requestURL_external__requestURLExternal = externaltemplist
    Check_if_requestURL_external__requestURLInternal = internaltemplist
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
    ###################################################
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
        name="Check_if_requestURL_is_private:condition_1",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Filter_External_URL_to_artifact_record(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Check_if_requestURL_external:custom_function:requestURLInternal", "!=", []],
        ],
        name="Check_if_requestURL_is_private:condition_2",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        Link_URL_to_artifact_record(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

"""
URL Reputation VT
"""
def URL_Reputation_VT(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('URL_Reputation_VT() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'URL_Reputation_VT' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_External_URL_to_artifact_record:condition_1:artifact:*.cef.requestURL', 'filtered-data:Filter_External_URL_to_artifact_record:condition_1:artifact:*.id'], scope="all")

    parameters = []
    
    # build parameters list for 'URL_Reputation_VT' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'url': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
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
        name="Link_URL_to_artifact_record:condition_1",
        scope="all")

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
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_External_URL_to_artifact_record:condition_1:artifact:*.cef.requestURL', 'filtered-data:Filter_External_URL_to_artifact_record:condition_1:artifact:*.id'], scope="all")

    parameters = []
    
    # build parameters list for 'URL_Reputation_TS' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'url': filtered_artifacts_item_1[0],
                'limit': 1000,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="url reputation", parameters=parameters, assets=['threatstream cloud','threatstream hybrid vm'], callback=Collect_all_results_requestURL, name="URL_Reputation_TS", parent_action=action)

    return

"""
Add note requestURL
"""
def Add_note_requestURL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_requestURL() called')
    
    Collect_all_results_requestURL__all_results_requestURL = json.loads(phantom.get_run_data(key='Collect_all_results_requestURL:all_results_requestURL'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    data = Collect_all_results_requestURL__all_results_requestURL
    content = ""
    for artifact in data:
        content += f"URL: `{data[artifact]['ts']['url']}`\n\n"
        content += f"**VirusTotal URL Reputation**\n" 
        content += f"- Malicious count: {data[artifact]['vt']['summary_malicious']}\n\n"
        content += f"- Summary: {'N/A' if data[artifact]['vt']['summary_malicious'] == None else 'MALICIOUS' if data[artifact]['vt']['summary_malicious'] > 2 else 'NON-MALICIOUS'}\n\n"
    
        content += f"**ThreatStream URL Repuation**\n"
        content += f"- Threat type: {', '.join(data[artifact]['ts']['threat_types']) if data[artifact]['ts']['threat_types'] != [] else '-'}\n\n"
        content += f"- Summary: {'MALICIOUS' if len(data[artifact]['ts']['threat_types']) > 0 else 'NON-MALICIOUS'}\n\n"
        content += "---\n"
    
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
    
    Collect_all_results_requestURL__all_results_requestURL = json.loads(phantom.get_run_data(key='Collect_all_results_requestURL:all_results_requestURL'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    data = Collect_all_results_requestURL__all_results_requestURL
    malicious_artifact_list = []
    
    for artifact in data:
        if data[artifact]['ts']['threat_types'] != [] or (data[artifact]['vt']['summary_malicious'] != None and data[artifact]['vt']['summary_malicious'] > 2):
            malicious_artifact_list.append(artifact)

    parameters = []
    cef_json = {"requestURL_malicious" : "True"}
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
        phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_requestURL")

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
            ["artifact:*.cef.fileHashSha256", "!=", ""],
        ],
        name="Filter_out_fileHash:condition_1",
        scope="all")

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
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_fileHash:condition_1:artifact:*.cef.fileHashSha256', 'filtered-data:Filter_out_fileHash:condition_1:artifact:*.id'])

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
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_fileHash:condition_1:artifact:*.cef.fileHashSha256', 'filtered-data:Filter_out_fileHash:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'File_reputation_TS' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'hash': filtered_artifacts_item_1[0],
                'limit': 1000,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="file reputation", parameters=parameters, assets=['threatstream cloud','threatstream hybrid vm'], callback=Collect_all_results_fileHash, name="File_reputation_TS", parent_action=action)

    return

"""
Add note fileHash
"""
def Add_note_fileHash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_fileHash() called')
    
    Collect_all_results_fileHash__all_results_fileHash = json.loads(phantom.get_run_data(key='Collect_all_results_fileHash:all_results_fileHash'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    data = Collect_all_results_fileHash__all_results_fileHash
    content = ""
    for artifact in data:    
        content += f"fileHash: {data[artifact]['ts']['hash']}\n\n"
        content += f"**VirusTotal File Reputation**\n" 
        content += f"- Malicious count: {data[artifact]['vt']['summary_malicious']}\n\n"
        content += f"- Summary: {'N/A' if data[artifact]['vt']['summary_malicious'] == None else 'MALICIOUS' if data[artifact]['vt']['summary_malicious'] > 2 else 'NON-MALICIOUS'}\n\n"
        
        content += f"**ThreatStream File Repuation**\n"
        content += f"- Threat type: {', '.join(data[artifact]['ts']['threat_types']) if data[artifact]['ts']['threat_types'] != [] else '-'}\n\n"
        content += f"- Summary: {'MALICIOUS' if len(data[artifact]['ts']['threat_types']) > 0 else 'NON-MALICIOUS'}\n\n"
        content += "---\n"

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
    
    Collect_all_results_fileHash__all_results_fileHash = json.loads(phantom.get_run_data(key='Collect_all_results_fileHash:all_results_fileHash'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    data = Collect_all_results_fileHash__all_results_fileHash
    malicious_artifact_list = []
    
    for artifact in data:
        if data[artifact]['ts']['threat_types'] != [] or (data[artifact]['vt']['summary_malicious'] != None and data[artifact]['vt']['summary_malicious'] > 2):
            malicious_artifact_list.append(artifact)

    parameters = []
    cef_json = {"fileHash_malicious" : "True"}
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
        phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_fileHash")

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
        name="Filter_out_destinationDnsDomain:condition_1",
        scope="all")

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
        Filter_External_Domain_to_artifact_recor(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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
Domain Reputation VT
"""
def Domain_Reputation_VT(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Domain_Reputation_VT() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Domain_Reputation_VT' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_External_Domain_to_artifact_recor:condition_1:artifact:*.cef.destinationDnsDomain', 'filtered-data:Filter_External_Domain_to_artifact_recor:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'Domain_Reputation_VT' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'domain': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
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
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_External_Domain_to_artifact_recor:condition_1:artifact:*.cef.destinationDnsDomain', 'filtered-data:Filter_External_Domain_to_artifact_recor:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'Domain_Reputation_TS' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'limit': 1000,
                'domain': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="domain reputation", parameters=parameters, assets=['threatstream cloud','threatstream hybrid vm'], callback=Domain_Reputation_UBL, name="Domain_Reputation_TS", parent_action=action)

    return

"""
Add note destinationDnsDomain
"""
def Add_note_destinationDnsDomain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_destinationDnsDomain() called')
    
    Collect_all_results_destinationDnsDomain__all_results_destinationDnsDomain = json.loads(phantom.get_run_data(key='Collect_all_results_destinationDnsDomain:all_results_destinationDnsDomain'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    #content = "Domain: " +  filtered_artifacts_item_1_1[0] +"\n" + "\n" + "VirusTotal Domain Reputation" +"\n" + "Summary Malicious: " + str(results_item_1_0[0]) +"\n" + "\n" + "ThreatStream Domain Repuation" +"\n" + "Summary: " + str(results_item_2_0[0]) +"\n" + "\n" + "Umbrella Domain Reputation" +"\n" + "Domain status: " + str(results_item_3_0[0]) 

    data = Collect_all_results_destinationDnsDomain__all_results_destinationDnsDomain
    content = ""
    for artifact in data:     
        content += f"Domain: {data[artifact]['ts']['domain']}\n\n"
        content += f"**VirusTotal Domain Reputation**\n" 
        content += f"- Malicious count: {data[artifact]['vt']['summary_malicious']}\n\n"
        content += f"- Summary: {'N/A' if data[artifact]['vt']['summary_malicious'] == None else 'MALICIOUS' if data[artifact]['vt']['summary_malicious'] > 2 else 'NON-MALICIOUS'}\n\n"
        
        content += f"**ThreatStream Domain Repuation**\n"
        content += f"- Threat type: {', '.join(data[artifact]['ts']['threat_types']) if data[artifact]['ts']['threat_types'] != [] else '-'}\n\n"
        content += f"- Summary: {'MALICIOUS' if len(data[artifact]['ts']['threat_types']) > 0 else 'NON-MALICIOUS'}\n\n"
        
        content += f"**Umbrella Domain Reputation**\n"
        content += f"- Summary: {data[artifact]['ubl']['summary_domain_status'] if data[artifact]['ubl']['summary_domain_status'] else '-'}\n"
        content += "---\n"
    
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
    
    Collect_all_results_destinationDnsDomain__all_results_destinationDnsDomain = json.loads(phantom.get_run_data(key='Collect_all_results_destinationDnsDomain:all_results_destinationDnsDomain'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    data = Collect_all_results_destinationDnsDomain__all_results_destinationDnsDomain
    malicious_artifact_list = []
    
    for artifact in data:
        if data[artifact]['ts']['threat_types'] != [] or (data[artifact]['vt']['summary_malicious'] != None and data[artifact]['vt']['summary_malicious'] > 2) or data[artifact]['ubl']['summary_domain_status'] == "MALICIOUS":
            malicious_artifact_list.append(artifact)

    parameters = []
    cef_json = {"destinationDnsDomain_malicious" : "True"}
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
        phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_destinationDnsDomain")

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
        name="Link_domain_to_artifact_record:condition_1",
        scope="all")

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
    if phantom.completed(action_names=['Domain_Reputation_UBL', 'URL_Reputation_TS', 'File_reputation_TS', 'Email_reputation_TS']):
        
        # call connected block "filter_21"
        filter_21(container=container, handle=handle)
    
    return

"""
Domain Reputation UBL
"""
def Domain_Reputation_UBL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Domain_Reputation_UBL() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Domain_Reputation_UBL' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_External_Domain_to_artifact_recor:condition_1:artifact:*.cef.destinationDnsDomain', 'filtered-data:Filter_External_Domain_to_artifact_recor:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'Domain_Reputation_UBL' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'domain': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="domain reputation", parameters=parameters, assets=['ktb-umbrella-asset'], callback=Collect_all_results_destinationDnsDomain, name="Domain_Reputation_UBL", parent_action=action)

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
            ["artifact:*.cef.fromEmail", "!=", ""],
        ],
        name="Filter_out_user_email:condition_1",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Retrieve_the_actual_sender_of_each_email(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Email_reputation_TS(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Email_reputation_TS() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Email_reputation_TS' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_actual_sender_email:condition_1:artifact:*.cef.fromEmail_actual_sender', 'filtered-data:filter_actual_sender_email:condition_1:artifact:*.id'], scope="all")

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

    phantom.act(action="email reputation", parameters=parameters, assets=['threatstream cloud','threatstream hybrid vm'], callback=Collect_all_results_email, name="Email_reputation_TS")

    return

"""
Add note user_email
"""
def Add_note_user_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_user_email() called')
    
    Collect_all_results_email__all_results_email = json.loads(phantom.get_run_data(key='Collect_all_results_email:all_results_email'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    data = Collect_all_results_email__all_results_email
    content = ""
    for artifact in data:  
        content += f"Source Email: {data[artifact]['ts']['email']}\n\n"
        
        content += f"**ThreatStream E-mail Repuation**\n"
        content += f"- Threat type: {', '.join(data[artifact]['ts']['threat_types']) if data[artifact]['ts']['threat_types'] != [] else '-'}\n\n"
        content += f"- Summary: {'MALICIOUS' if len(data[artifact]['ts']['threat_types']) > 0 else 'NON-MALICIOUS'}\n\n"
        content += "---\n"

    note_title = "Email Investigation"
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
    
    Collect_all_results_email__all_results_email = json.loads(phantom.get_run_data(key='Collect_all_results_email:all_results_email'))

    ################################################################################
    ## Custom Code Start
    ################################################################################
    data = Collect_all_results_email__all_results_email
    malicious_artifact_list = []
    
    for artifact in data:
        if data[artifact]['ts']['threat_types'] != []:
            malicious_artifact_list.append(artifact)

    parameters = []
    cef_json = {"fromEmail_actual_sender_malicious" : "True"}
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
        phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_email")

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
    join_filter_21(container=container)

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
    
    Filter_out_user_email(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    Filter_out_fileHash(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    Filter_out_destinationDnsDomain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    Filter_out_requestURL(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Filter External URL to artifact record
"""
def Filter_External_URL_to_artifact_record(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_External_URL_to_artifact_record() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.requestURL", "in", "Check_if_requestURL_external:custom_function:requestURLExternal"],
        ],
        name="Filter_External_URL_to_artifact_record:condition_1",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        URL_Reputation_VT(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Collect all results requestURL
"""
def Collect_all_results_requestURL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Collect_all_results_requestURL() called')
    
    input_parameter_0 = ""

    Collect_all_results_requestURL__all_results_requestURL = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    all_results_requestURL = {}
    # Get results from VT
    results_data_vt = phantom.collect2(scope="all", container=container, datapath=['URL_Reputation_VT:action_result.parameter.context.artifact_id', 'URL_Reputation_VT:action_result.summary.malicious'], action_results=results)
    for row in results_data_vt:
        #phantom.debug(f"{row[0]} ---- {row[1]}")
        artifact_id = row[0]
        summary_malicious = row[1]
        if all_results_requestURL.get(artifact_id, None) == None:
            all_results_requestURL[artifact_id] = {}
        if all_results_requestURL[artifact_id].get('vt', None) == None:
            summary_malicious = 0 if summary_malicious == None else summary_malicious
            all_results_requestURL[artifact_id]['vt'] = {'summary_malicious': summary_malicious}
        else:
            all_results_requestURL[artifact_id]['vt']['summary_malicious'] = 0 if all_results_requestURL[artifact_id]['vt']['summary_malicious'] == None else all_results_requestURL[artifact_id]['vt']['summary_malicious']
            all_results_requestURL[artifact_id] = {'vt': {'summary_malicious': max(summary_malicious, all_results_requestURL[artifact_id]['vt']['summary_malicious'])}}
    
    # Get results from TS
    results_data_ts = phantom.collect2(scope="all", container=container, datapath=['URL_Reputation_TS:action_results'], action_results=results)
    results_item_ts = [item[0] for item in results_data_ts]
    for asset in results_item_ts:
        for artifact in asset:
            artifact_id = artifact['parameter']['context']['artifact_id']
            url = artifact['parameter']['url']
            status = artifact['status']
            
            if all_results_requestURL.get(artifact_id, None) == None:
                all_results_requestURL[artifact_id] = {}
            if all_results_requestURL[artifact_id].get('ts', None) == None:
                all_results_requestURL[artifact_id]['ts'] = {
                   'url': url,
                   'status': status,
                   'threat_types': []
               }
            
            for data in artifact['data']:
                threat_type = data.get('threat_type', None)
                status = data.get('status', None)
                if threat_type and status != 'falsepos' and threat_type not in all_results_requestURL[artifact_id]['ts']['threat_types']:
                    all_results_requestURL[artifact_id]['ts']['threat_types'].append(threat_type)
                #phantom.debug(f"artifact: {artifact['parameter']['context']['artifact_id']}, domain: {artifact['parameter']['url']}, status: {artifact['status']}, threat_type: {threat_types}")
                
    #phantom.debug(all_results_requestURL)
    Collect_all_results_requestURL__all_results_requestURL = all_results_requestURL

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Collect_all_results_requestURL:all_results_requestURL', value=json.dumps(Collect_all_results_requestURL__all_results_requestURL))
    Add_note_requestURL(container=container)

    return

"""
Filter External Domain to artifact record
"""
def Filter_External_Domain_to_artifact_recor(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_External_Domain_to_artifact_recor() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationDnsDomain", "in", "Check_if_destinationDnsDomain_external:custom_function:destinationDnsDomainExternal"],
        ],
        name="Filter_External_Domain_to_artifact_recor:condition_1",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Domain_Reputation_VT(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Collect all results destinationDnsDomain
"""
def Collect_all_results_destinationDnsDomain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Collect_all_results_destinationDnsDomain() called')
    
    input_parameter_0 = ""

    Collect_all_results_destinationDnsDomain__all_results_destinationDnsDomain = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    all_results_destinationDnsDomain = {}
    # Get results from VT
    results_data_vt = phantom.collect2(scope="all", container=container, datapath=['Domain_Reputation_VT:action_result.parameter.context.artifact_id', 'Domain_Reputation_VT:action_result.summary.malicious'], action_results=results)
    for row in results_data_vt:
        #phantom.debug(f"{row[0]} ---- {row[1]}")
        artifact_id = row[0]
        summary_malicious = row[1]
        if all_results_destinationDnsDomain.get(artifact_id, None) == None:
            all_results_destinationDnsDomain[artifact_id] = {}
        if all_results_destinationDnsDomain[artifact_id].get('vt', None) == None:
            summary_malicious = 0 if summary_malicious == None else summary_malicious
            all_results_destinationDnsDomain[artifact_id]['vt'] = {'summary_malicious': summary_malicious}
        else:
            all_results_destinationDnsDomain[artifact_id]['vt']['summary_malicious'] = 0 if all_results_destinationDnsDomain[artifact_id]['vt']['summary_malicious'] == None else all_results_destinationDnsDomain[artifact_id]['vt']['summary_malicious']
            all_results_destinationDnsDomain[artifact_id] = {'vt': {'summary_malicious': max(summary_malicious, all_results_destinationDnsDomain[artifact_id]['vt']['summary_malicious'])}}
    
    # Get results from TS
    results_data_ts = phantom.collect2(scope="all", container=container, datapath=['Domain_Reputation_TS:action_results'], action_results=results)
    results_item_ts = [item[0] for item in results_data_ts]
    for asset in results_item_ts:
        for artifact in asset:
            artifact_id = artifact['parameter']['context']['artifact_id']
            domain = artifact['parameter']['domain']
            status = artifact['status']
            
            if all_results_destinationDnsDomain.get(artifact_id, None) == None:
                all_results_destinationDnsDomain[artifact_id] = {}
            if all_results_destinationDnsDomain[artifact_id].get('ts', None) == None:
                all_results_destinationDnsDomain[artifact_id]['ts'] = {
                   'domain': domain,
                   'status': status,
                   'threat_types': []
               }
            
            for data in artifact['data']:
                threat_type = data.get('threat_type', None)
                status = data.get('status', None)
                if threat_type and status != 'falsepos' and threat_type not in all_results_destinationDnsDomain[artifact_id]['ts']['threat_types']:
                    all_results_destinationDnsDomain[artifact_id]['ts']['threat_types'].append(threat_type)
                #phantom.debug(f"artifact: {artifact['parameter']['context']['artifact_id']}, domain: {artifact['parameter']['url']}, status: {artifact['status']}, threat_type: {threat_types}")

    # Get results from UBL
    results_data_ubl = phantom.collect2(scope="all", container=container, datapath=['Domain_Reputation_UBL:action_result.parameter.context.artifact_id', 'Domain_Reputation_UBL:action_result.summary.domain_status'], action_results=results)
    for row in results_data_ubl:
        #phantom.debug(f"{row[0]} ---- {row[1]}")
        artifact_id = row[0]
        summary_domain_status = row[1]
        if all_results_destinationDnsDomain.get(artifact_id, None) == None:
            all_results_destinationDnsDomain[artifact_id] = {}
        if all_results_destinationDnsDomain[artifact_id].get('ubl', None) == None:
            summary_domain_status = 0 if summary_domain_status == None else summary_domain_status
            all_results_destinationDnsDomain[artifact_id]['ubl'] = {'summary_domain_status': summary_domain_status}
        else:
            all_results_destinationDnsDomain[artifact_id]['ubl']['summary_domain_status'] = 0 if all_results_destinationDnsDomain[artifact_id]['ubl']['summary_domain_status'] == None else all_results_destinationDnsDomain[artifact_id]['ubl']['summary_domain_status']
            all_results_destinationDnsDomain[artifact_id] = {'ubl': {'summary_domain_status': max(summary_domain_status, all_results_destinationDnsDomain[artifact_id]['ubl']['summary_domain_status'])}}
            
    #phantom.debug(all_results_destinationDnsDomain)
    Collect_all_results_destinationDnsDomain__all_results_destinationDnsDomain = all_results_destinationDnsDomain

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Collect_all_results_destinationDnsDomain:all_results_destinationDnsDomain', value=json.dumps(Collect_all_results_destinationDnsDomain__all_results_destinationDnsDomain))
    Add_note_destinationDnsDomain(container=container)

    return

"""
Collect all results fileHash
"""
def Collect_all_results_fileHash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Collect_all_results_fileHash() called')
    
    input_parameter_0 = ""

    Collect_all_results_fileHash__all_results_fileHash = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    all_results_fileHash = {}
    # Get results from VT
    results_data_vt = phantom.collect2(scope="all", container=container, datapath=['File_reputation_VT:action_result.parameter.context.artifact_id', 'File_reputation_VT:action_result.summary.malicious'], action_results=results)
    for row in results_data_vt:
        #phantom.debug(f"{row[0]} ---- {row[1]}")
        artifact_id = row[0]
        summary_malicious = row[1]
        if all_results_fileHash.get(artifact_id, None) == None:
            all_results_fileHash[artifact_id] = {}
        if all_results_fileHash[artifact_id].get('vt', None) == None:
            summary_malicious = 0 if summary_malicious == None else summary_malicious
            all_results_fileHash[artifact_id]['vt'] = {'summary_malicious': summary_malicious}
        else:
            all_results_fileHash[artifact_id]['vt']['summary_malicious'] = 0 if all_results_fileHash[artifact_id]['vt']['summary_malicious'] == None else all_results_fileHash[artifact_id]['vt']['summary_malicious']
            all_results_fileHash[artifact_id] = {'vt': {'summary_malicious': max(summary_malicious, all_results_fileHash[artifact_id]['vt']['summary_malicious'])}}
    
    # Get results from TS
    results_data_ts = phantom.collect2(scope="all", container=container, datapath=['File_reputation_TS:action_results'], action_results=results)
    results_item_ts = [item[0] for item in results_data_ts]
    for asset in results_item_ts:
        for artifact in asset:
            artifact_id = artifact['parameter']['context']['artifact_id']
            filehash = artifact['parameter']['hash']
            status = artifact['status']
            
            if all_results_fileHash.get(artifact_id, None) == None:
                all_results_fileHash[artifact_id] = {}
            if all_results_fileHash[artifact_id].get('ts', None) == None:
                all_results_fileHash[artifact_id]['ts'] = {
                   'hash': filehash,
                   'status': status,
                   'threat_types': []
               }
            
            for data in artifact['data']:
                threat_type = data.get('threat_type', None)
                status = data.get('status', None)
                if threat_type and status != 'falsepos' and threat_type not in all_results_fileHash[artifact_id]['ts']['threat_types']:
                    all_results_fileHash[artifact_id]['ts']['threat_types'].append(threat_type)
                #phantom.debug(f"artifact: {artifact['parameter']['context']['artifact_id']}, hash: {artifact['parameter']['hash']}, status: {artifact['status']}, threat_type: {threat_types}")

    #phantom.debug(all_results_fileHash)
    Collect_all_results_fileHash__all_results_fileHash = all_results_fileHash

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Collect_all_results_fileHash:all_results_fileHash', value=json.dumps(Collect_all_results_fileHash__all_results_fileHash))
    Add_note_fileHash(container=container)

    return

"""
Retrieve the actual sender of each email
"""
def Retrieve_the_actual_sender_of_each_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Retrieve_the_actual_sender_of_each_email() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_user_email:condition_1:artifact:*.id', 'filtered-data:Filter_out_user_email:condition_1:artifact:*.cef.fromEmail'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]

    Retrieve_the_actual_sender_of_each_email__email_list = None
    Retrieve_the_actual_sender_of_each_email__total_email_count = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    import re
    
    artifact_list = filtered_artifacts_item_1_0
    bodytext_list = filtered_artifacts_item_1_1
    
    email_list = {}
    
    init_search_pattern = r'(([^<>])*<)(\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+)(>)'
    email_search_pattern = r'\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+'
    init_pattern = re.compile(init_search_pattern)
    email_pattern = re.compile(email_search_pattern)
    
    for i in range(len(artifact_list)):
        target_line = init_pattern.search(bodytext_list[i])
        if target_line:
            target_line = target_line.group(0)
            email = email_pattern.search(target_line)
            if email:
                email_list[artifact_list[i]] = email.group(0)
            
    Retrieve_the_actual_sender_of_each_email__email_list = email_list
    Retrieve_the_actual_sender_of_each_email__total_email_count = len(email_list)
    phantom.debug(Retrieve_the_actual_sender_of_each_email__email_list)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Retrieve_the_actual_sender_of_each_email:email_list', value=json.dumps(Retrieve_the_actual_sender_of_each_email__email_list))
    phantom.save_run_data(key='Retrieve_the_actual_sender_of_each_email:total_email_count', value=json.dumps(Retrieve_the_actual_sender_of_each_email__total_email_count))
    check_result_from_getting_email_address(container=container)

    return

"""
Add actual sender's email address
"""
def Add_actual_senders_email_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_actual_senders_email_address() called')
    
    Retrieve_the_actual_sender_of_each_email__email_list = json.loads(phantom.get_run_data(key='Retrieve_the_actual_sender_of_each_email:email_list'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    parameters = []
    data = Retrieve_the_actual_sender_of_each_email__email_list
    for artifact in data:
        cef_json = {"fromEmail_actual_sender" : data[artifact]}
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

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_email", callback=filter_actual_sender_email)
    return

    ################################################################################
    ## Custom Code End
    ################################################################################
    filter_actual_sender_email(container=container)

    return

"""
filter actual sender email
"""
def filter_actual_sender_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_actual_sender_email() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:Filter_out_user_email:condition_1:artifact:*.cef.fromEmail_actual_sender", "!=", ""],
        ],
        name="filter_actual_sender_email:condition_1",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Email_reputation_TS(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
check result from getting email address
"""
def check_result_from_getting_email_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_result_from_getting_email_address() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Retrieve_the_actual_sender_of_each_email:custom_function:total_email_count", ">", 0],
        ],
        scope="all")

    # call connected blocks if condition 1 matched
    if matched:
        Add_actual_senders_email_address(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    Prepare_Error_Note_Email(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Add note Email Error
"""
def Add_note_Email_Error(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_Email_Error() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Add_note_Email_Error' call
    formatted_data_1 = phantom.get_format_data(name='Prepare_Error_Note_Email')

    parameters = []
    
    # build parameters list for 'Add_note_Email_Error' call
    parameters.append({
        'title': "Email address cannot be retrieved",
        'content': formatted_data_1,
        'phase_id': "",
        'container_id': "",
    })

    phantom.act(action="add note", parameters=parameters, assets=['phantom asset'], name="Add_note_Email_Error")

    return

"""
Prepare Error Note Email
"""
def Prepare_Error_Note_Email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Prepare_Error_Note_Email() called')
    
    template = """ERROR: Email address cannot be retrieved, please check the field \"fromEmail\" in the Email Artifact whether it contains the sender's email address.

Artifact ID: `{0}`

fromEmail:
```
{1}
```"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Filter_out_user_email:condition_1:artifact:*.id",
        "filtered-data:Filter_out_user_email:condition_1:artifact:*.cef.fromEmail",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Prepare_Error_Note_Email", separator=", ")

    Add_note_Email_Error(container=container)

    return

"""
Collect all results email
"""
def Collect_all_results_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Collect_all_results_email() called')
    
    input_parameter_0 = ""

    Collect_all_results_email__all_results_email = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    all_results_email = {}

    # Get results from TS
    results_data_ts = phantom.collect2(scope="all", container=container, datapath=['Email_reputation_TS:action_results'], action_results=results)
    results_item_ts = [item[0] for item in results_data_ts]
    for asset in results_item_ts:
        for artifact in asset:
            artifact_id = artifact['parameter']['context']['artifact_id']
            email = artifact['parameter']['email']
            status = artifact['status']
            
            if all_results_email.get(artifact_id, None) == None:
                all_results_email[artifact_id] = {}
            if all_results_email[artifact_id].get('ts', None) == None:
                all_results_email[artifact_id]['ts'] = {
                   'email': email,
                   'status': status,
                   'threat_types': []
               }
            
            for data in artifact['data']:
                threat_type = data.get('threat_type', None)
                status = data.get('status', None)
                if threat_type and status != 'falsepos' and threat_type not in all_results_email[artifact_id]['ts']['threat_types']:
                    all_results_email[artifact_id]['ts']['threat_types'].append(threat_type)
                #phantom.debug(f"artifact: {artifact['parameter']['context']['artifact_id']}, email: {artifact['parameter']['email']}, status: {artifact['status']}, threat_type: {threat_types}")

    phantom.debug(all_results_email)
    Collect_all_results_email__all_results_email = all_results_email

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Collect_all_results_email:all_results_email', value=json.dumps(Collect_all_results_email__all_results_email))
    Add_note_user_email(container=container)

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