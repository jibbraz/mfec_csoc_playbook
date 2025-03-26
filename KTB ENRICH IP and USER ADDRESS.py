"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'decision_2' block
    decision_2(container=container)

    # call 'decision_7' block
    decision_7(container=container)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        format_amp_query_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2

    return

"""
Gets information about an endpoint where Cisco AMP is installed.
"""
def get_device_info_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_device_info_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    count_guid__connector_guid = json.loads(phantom.get_run_data(key='count_guid:connector_guid'))
    # collect data for 'get_device_info_2' call

    parameters = []
    
    # build parameters list for 'get_device_info_2' call
    parameters.append({
        'connector_guid': count_guid__connector_guid,
    })

    phantom.act(action="get device info", parameters=parameters, assets=['cisco fireamp asset'], callback=check_active_IP_match_source_Address, name="get_device_info_2")

    return

"""
check recent IP in each result to match sourceaddress from container
"""
def check_active_IP_match_source_Address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_active_IP_match_source_Address() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])
    results_data_1 = phantom.collect2(container=container, datapath=['get_device_info_2:action_result.data.*.data.active', 'get_device_info_2:action_result.data.*.data.internal_ips', 'get_device_info_2:action_result.data.*.data.connector_guid', 'get_device_info_2:action_result.data.*.data.network_addresses.*.mac'], action_results=results)
    container_item_0 = [item[0] for item in container_data]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_1_1 = [item[1] for item in results_data_1]
    results_item_1_2 = [item[2] for item in results_data_1]
    results_item_1_3 = [item[3] for item in results_data_1]

    check_active_IP_match_source_Address__matched_guid = None
    check_active_IP_match_source_Address__matched_guid_count = None
    check_active_IP_match_source_Address__matched_mac = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    #phantom.debug(results_data_1)
    matched_guid = []
    matched_mac = []
    matched_guid_count = 0
    phantom.debug(container_item_0)
    phantom.debug(results_data_1)
    for cguid in results_data_1:
        if  cguid[0] == True and container_item_0[0] in cguid[1]:
            matched_guid.append(cguid[2])
            matched_mac.append(cguid[3])
            matched_guid_count += 1
    phantom.debug(matched_guid)
    
    check_active_IP_match_source_Address__matched_guid = matched_guid
    check_active_IP_match_source_Address__matched_guid_count = matched_guid_count
    check_active_IP_match_source_Address__matched_mac = matched_mac

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='check_active_IP_match_source_Address:matched_guid', value=json.dumps(check_active_IP_match_source_Address__matched_guid))
    phantom.save_run_data(key='check_active_IP_match_source_Address:matched_guid_count', value=json.dumps(check_active_IP_match_source_Address__matched_guid_count))
    phantom.save_run_data(key='check_active_IP_match_source_Address:matched_mac', value=json.dumps(check_active_IP_match_source_Address__matched_mac))
    update_artifact_connector_guid(container=container)

    return

def format_ISE_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ISE_query() called')
    
    template = """index=ktb_mgmt_default earliest=-15m@m latest=now sourcetype=\"cisco:ise:syslog\"  Framed_IP_Address={0} |  dedup Framed_IP_Address"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ISE_query", separator=", ")

    run_query_1(container=container)

    return

def run_query_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_query_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_query_1' call
    formatted_data_1 = phantom.get_format_data(name='format_ISE_query')

    parameters = []
    
    # build parameters list for 'run_query_1' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=decision_3, name="run_query_1")

    return

def update_artifact_macaddr_from_ise(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_artifact_macaddr_from_ise() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.id'])
    results_data_1 = phantom.collect2(container=container, datapath=['run_query_1:action_result.data.*.raw_msg'], action_results=results)
    container_item_0 = [item[0] for item in container_data]
    results_item_1_0 = [item[0] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    parameters = []

    for item in results_item_1_0:
        ltmp = item.split(',')
        for item2 in ltmp:
            if item2.split('=')[0].strip() == "Calling-Station-ID":
                cef_json = {"sourceAddress_MacAddress" : item2.split('=')[1].replace('-',':') , "sourceAddress_QueryFrom" : "ISE" }
                
    # build parameters list for 'update_mac' call
    parameters.append({
    'artifact_id': container_item_0[0],
    'name': "",
    'label': "",
    'severity': "",
    'cef_json': cef_json,
    'cef_types_json': "",
    'tags': "",
    'overwrite': "",
    'artifact_json': "",
    })
    
    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_sourceAddress_mac")
    #####################################
    #####################################
    #####################################
    #####################################
    #####################################
    #####################################
    #####################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["run_query_1:action_result.summary.total_events", "==", 1],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        update_artifact_macaddr_from_ise(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def format_amp_query_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_amp_query_ip() called')
    
    template = """/v1/computers?internal_ip={0}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_amp_query_ip", separator=", ")

    get_amp_event_data(container=container)

    return

def get_amp_event_data(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_amp_event_data() called')

    # collect data for 'get_amp_event_data' call
    formatted_data_1 = phantom.get_format_data(name='format_amp_query_ip')

    parameters = []
    
    # build parameters list for 'get_amp_event_data' call
    parameters.append({
        'headers': "{\"Authorization\": \"Basic NzU4MWVjYTU3YjAzMjZhMTJiM2U6ODJjNGFhZmYtNzExMS00N2JmLTg4YjUtNzg2N2E0MTQzZTY1\"}",
        'location': formatted_data_1,
        'verify_certificate': False,
    })

    phantom.act(action="get data", parameters=parameters, assets=['cisco amp base64'], callback=decision_4, name="get_amp_event_data")

    return

def count_guid(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('count_guid() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['get_amp_event_data:action_result.status', 'get_amp_event_data:action_result.data.*.response_body'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_1_1 = [item[1] for item in results_data_1]

    count_guid__connector_guid = None
    count_guid__connector_guid_count = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    connector_guid = 0
    connector_guid_count = 0
    #phantom.debug(results_item_1_0)
    for item in results_item_1_1[0]['data']:
        if item['connector_guid']:
            connector_guid = item['connector_guid']
            connector_guid_count += 1
            
    count_guid__connector_guid = connector_guid
    count_guid__connector_guid_count = connector_guid_count

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='count_guid:connector_guid', value=json.dumps(count_guid__connector_guid))
    phantom.save_run_data(key='count_guid:connector_guid_count', value=json.dumps(count_guid__connector_guid_count))
    decision_6(container=container)

    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_amp_event_data:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        count_guid(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def decision_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_6() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["count_guid:custom_function:connector_guid_count", "==", 1],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        get_device_info_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["count_guid:custom_function:connector_guid_count", ">", 1],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        format_multiple_active_guid_found(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 3
    format_ISE_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def format_multiple_active_guid_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_multiple_active_guid_found() called')
    
    template = """Active IP {2} on {0} endpoints with following connector_guid:

%%
{1}

%%"""

    # parameter list for template variable replacement
    parameters = [
        "count_guid:custom_function:connector_guid_count",
        "count_guid:custom_function:connector_guid",
        "artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_multiple_active_guid_found", separator=", ")

    add_note_2(container=container)

    return

def add_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_2() called')

    formatted_data_1 = phantom.get_format_data(name='format_multiple_active_guid_found')

    note_title = "update connector_guid found"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def update_artifact_connector_guid(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_artifact_connector_guid() called')
    
    check_active_IP_match_source_Address__matched_guid = json.loads(phantom.get_run_data(key='check_active_IP_match_source_Address:matched_guid'))
    check_active_IP_match_source_Address__matched_mac = json.loads(phantom.get_run_data(key='check_active_IP_match_source_Address:matched_mac'))
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    parameters = []
    
    cef_json = {"sourceAddress_connector_guid" : check_active_IP_match_source_Address__matched_guid[0] , "sourceAddress_MacAddresss" : check_active_IP_match_source_Address__matched_mac[0] , "sourceAddress_QueryFrom" : "AMP" }
    
    # build parameters list for 'update_guid' call
    parameters.append({
    'artifact_id': container_item_0[0],
    'name': "",
    'label': "",
    'severity': "",
    'cef_json': cef_json,
    'cef_types_json': "",
    'tags': "",
    'overwrite': "",
    'artifact_json': "",
    })
    
    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_sourceAddress_guid")

    ################################################################################
    ## Custom Code End
    ################################################################################

    return

def decision_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_7() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationUserName", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        format_user_AD_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def format_user_AD_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_user_AD_query() called')
    
    template = """(&(|(samaccountname={0})(userprincipalname={0}))(objectclass=user))"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationUserName",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_user_AD_query", separator=", ")

    run_query_against_3_ad(container=container)

    return

def run_query_against_3_ad(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_query_against_3_ad() called')

    # collect data for 'run_query_against_3_ad' call
    formatted_data_1 = phantom.get_format_data(name='format_user_AD_query')

    parameters = []
    
    # build parameters list for 'run_query_against_3_ad' call
    parameters.append({
        'filter': formatted_data_1,
        'attributes': "samaccountname;mail;userprincipalname;distinguishedname",
        'search_base': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['csoc ad ldap asset containment','ktb domain ad','ktbcs domain ad'], callback=update_artifact_active_directory, name="run_query_against_3_ad")

    return

"""
run query against 3 AD (csoc, ktb and ktbcs). append artifact regarding AD found.
"""
def update_artifact_active_directory(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_artifact_active_directory() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.id'])
    results_data_1 = phantom.collect2(container=container, datapath=['run_query_against_3_ad:action_result.data.*.entries.*.attributes'], action_results=results)
    container_item_0 = [item[0] for item in container_data]
    results_item_1_0 = [item[0] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    user_found = False
    for item in results_item_1_0:
        if item and item['distinguishedname'].find('OU=CSOC-Users,DC=csoc,DC=krungthai,DC=local') != -1:
            phantom.debug(item['userprincipalname'])
            phantom.debug(item['distinguishedname'])
            parameters = []
            cef_json = {"destinationUserName_AD" : "CSOC AD" }
            # build parameters list for 'update_guid' call
            parameters.append({
            'artifact_id': container_item_0[0],
            'name': "",
            'label': "",
            'severity': "",
            'cef_json': cef_json,
            'cef_types_json': "",
            'tags': "",
            'overwrite': "",
            'artifact_json': "",
            })
            phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_ad")
            user_found = True
        elif item and item['distinguishedname'].find('DC=KTBDOMAIN') != -1:
            phantom.debug(item['userprincipalname'])
            phantom.debug(item['distinguishedname'])
            parameters = []
            cef_json = {"destinationUserName_AD" : "KTB AD" }
            # build parameters list for 'update_guid' call
            parameters.append({
            'artifact_id': container_item_0[0],
            'name': "",
            'label': "",
            'severity': "",
            'cef_json': cef_json,
            'cef_types_json': "",
            'tags': "",
            'overwrite': "",
            'artifact_json': "",
            })
            phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_ad")
            user_found = True
        elif item and item['distinguishedname'].find('DC=ktbcs') != -1:
            phantom.debug(item['userprincipalname'])
            phantom.debug(item['distinguishedname'])
            parameters = []
            cef_json = {"destinationUserName_AD" : "KTBCS AD" }
            # build parameters list for 'update_guid' call
            parameters.append({
            'artifact_id': container_item_0[0],
            'name': "",
            'label': "",
            'severity': "",
            'cef_json': cef_json,
            'cef_types_json': "",
            'tags': "",
            'overwrite': "",
            'artifact_json': "",
            })
            phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_ad")
            user_found = True
    if not user_found:
            parameters = []
            cef_json = {"destinationUserName_AD" : "user not found" }
            # build parameters list for 'update_guid' call
            parameters.append({
            'artifact_id': container_item_0[0],
            'name': "",
            'label': "",
            'severity': "",
            'cef_json': cef_json,
            'cef_types_json': "",
            'tags': "",
            'overwrite': "",
            'artifact_json': "",
            })
            phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_ad")
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