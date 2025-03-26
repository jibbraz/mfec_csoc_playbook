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

    # call 'decision_8' block
    decision_8(container=container)

    # call 'decision_10' block
    decision_10(container=container)

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

    return

"""
Gets information about an endpoint where Cisco AMP is installed.
"""
def get_device_info_src_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_device_info_src_ip() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    count_guid_src_ip__connector_guid = json.loads(phantom.get_run_data(key='count_guid_src_ip:connector_guid'))
    # collect data for 'get_device_info_src_ip' call

    parameters = []
    
    # build parameters list for 'get_device_info_src_ip' call
    parameters.append({
        'connector_guid': count_guid_src_ip__connector_guid,
    })

    phantom.act(action="get device info", parameters=parameters, assets=['cisco fireamp asset'], callback=format_user_query, name="get_device_info_src_ip")

    return

"""
check recent IP in each result to match sourceaddress from container
"""
def check_active_IP_match_src_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_active_IP_match_src_IP() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id', 'artifact:*.id'])
    results_data_1 = phantom.collect2(container=container, datapath=['get_device_info_src_ip:action_result.data.*.data.active', 'get_device_info_src_ip:action_result.data.*.data.internal_ips', 'get_device_info_src_ip:action_result.data.*.data.connector_guid', 'get_device_info_src_ip:action_result.data.*.data.network_addresses.*.mac', 'get_device_info_src_ip:action_result.data.*.data.hostname'], action_results=results)
    container_item_0 = [item[0] for item in container_data]
    container_item_1 = [item[1] for item in container_data]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_1_1 = [item[1] for item in results_data_1]
    results_item_1_2 = [item[2] for item in results_data_1]
    results_item_1_3 = [item[3] for item in results_data_1]
    results_item_1_4 = [item[4] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    #phantom.debug(results_data_1)
    matched_guid = []
    matched_mac = []
    matched_hostname = []
    matched_guid_count = 0
    phantom.debug(container_item_0)
    phantom.debug(results_data_1)
    for cguid in results_data_1:
        if  cguid[0] == True and container_item_0[0] in cguid[1]:
            matched_guid.append(cguid[2])
            matched_mac.append(cguid[3])
            matched_hostname.append(cguid[4])
            matched_guid_count += 1
    phantom.debug(matched_guid)
    
    parameters = []
    
    cef_json = {"sourceAddress_connector_guid" : matched_guid[0] , "sourceAddress_MacAddresss" : matched_mac[0] ,"sourceAddress_hostname" : matched_hostname[0].split(".")[0] ,"sourceAddress_fullhostname" : matched_hostname[0] , "sourceAddress_QueryFrom" : "AMP" }
    
    # build parameters list for 'update_guid' call
    parameters.append({
    'artifact_id': container_item_1[0],
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

def format_ISE_query_src_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ISE_query_src_IP() called')
    
    template = """index=ktb_mgmt_default earliest=-15m@m latest=now sourcetype=\"cisco:ise:syslog\"  Framed_IP_Address={0} |  dedup Framed_IP_Address"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ISE_query_src_IP", separator=", ")

    run_ISE_query_src_IP(container=container)

    return

def run_ISE_query_src_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_ISE_query_src_IP() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_ISE_query_src_IP' call
    formatted_data_1 = phantom.get_format_data(name='format_ISE_query_src_IP')

    parameters = []
    
    # build parameters list for 'run_ISE_query_src_IP' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=decision_3, name="run_ISE_query_src_IP")

    return

def update_artifact_src_macaddr_from_ise(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_artifact_src_macaddr_from_ise() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.id'])
    results_data_1 = phantom.collect2(container=container, datapath=['run_ISE_query_src_IP:action_result.data.*.raw_msg'], action_results=results)
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
            ["run_ISE_query_src_IP:action_result.summary.total_events", "==", 1],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        update_artifact_src_macaddr_from_ise(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
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

    get_amp_event_data_src_ip(container=container)

    return

def get_amp_event_data_src_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_amp_event_data_src_ip() called')

    # collect data for 'get_amp_event_data_src_ip' call
    formatted_data_1 = phantom.get_format_data(name='format_amp_query_ip')

    parameters = []
    
    # build parameters list for 'get_amp_event_data_src_ip' call
    parameters.append({
        'headers': "{\"Authorization\": \"Basic NzU4MWVjYTU3YjAzMjZhMTJiM2U6ODJjNGFhZmYtNzExMS00N2JmLTg4YjUtNzg2N2E0MTQzZTY1\"}",
        'location': formatted_data_1,
        'verify_certificate': False,
    })

    phantom.act(action="get data", parameters=parameters, assets=['cisco amp base64'], callback=decision_4, name="get_amp_event_data_src_ip")

    return

def count_guid_src_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('count_guid_src_ip() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['get_amp_event_data_src_ip:action_result.status', 'get_amp_event_data_src_ip:action_result.data.*.response_body'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_1_1 = [item[1] for item in results_data_1]

    count_guid_src_ip__connector_guid = None
    count_guid_src_ip__connector_guid_count = None

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
            
    count_guid_src_ip__connector_guid = connector_guid
    count_guid_src_ip__connector_guid_count = connector_guid_count

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='count_guid_src_ip:connector_guid', value=json.dumps(count_guid_src_ip__connector_guid))
    phantom.save_run_data(key='count_guid_src_ip:connector_guid_count', value=json.dumps(count_guid_src_ip__connector_guid_count))
    decision_6(container=container)

    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_amp_event_data_src_ip:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        count_guid_src_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def decision_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_6() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["count_guid_src_ip:custom_function:connector_guid_count", "==", 1],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        get_device_info_src_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["count_guid_src_ip:custom_function:connector_guid_count", ">", 1],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        format_multiple_guid_src_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 3
    format_ISE_query_src_IP(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def format_multiple_guid_src_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_multiple_guid_src_ip() called')
    
    template = """{0} below endpoint guid found using same active IP {2}

%%
{1}

%%"""

    # parameter list for template variable replacement
    parameters = [
        "count_guid_src_ip:custom_function:connector_guid_count",
        "count_guid_src_ip:custom_function:connector_guid",
        "artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_multiple_guid_src_ip", separator=", ")

    add_note_2(container=container)

    return

def add_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_2() called')

    formatted_data_1 = phantom.get_format_data(name='format_multiple_guid_src_ip')

    note_title = "Multiple Active GUID detected"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

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
        'attributes': "*",
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
    UAC_FLAG = {
    "SCRIPT" : 0x0001 ,
    "ACCOUNTDISABLE" : 0x0002 ,
    "HOMEDIR_REQUIRED" : 0x0008 ,
    "LOCKOUT" : 0x0010 ,
    "PASSWD_NOTREQD" : 0x0020 ,
    "PASSWD_CANT_CHANGE" : 0x0040 ,
    "ENCRYPTED_TEXT_PWD_ALLOWED" : 0x0080 ,
    "TEMP_DUPLICATE_ACCOUNT" : 0x0100 ,
    "NORMAL_ACCOUNT" : 0x0200 ,
    "INTERDOMAIN_TRUST_ACCOUNT" : 0x0800 ,
    "WORKSTATION_TRUST_ACCOUNT" : 0x1000 ,
    "SERVER_TRUST_ACCOUNT" : 0x2000 ,
    "DONT_EXPIRE_PASSWORD" : 0x10000 ,
    "MNS_LOGON_ACCOUNT" : 0x20000 ,
    "SMARTCARD_REQUIRED" : 0x40000 ,
    "TRUSTED_FOR_DELEGATION" : 0x80000 ,
    "NOT_DELEGATED" : 0x100000 ,
    "USE_DES_KEY_ONLY" : 0x200000 ,
    "DONT_REQ_PREAUTH" : 0x400000 ,
    "PASSWORD_EXPIRED" : 0x800000 ,
    "TRUSTED_TO_AUTH_FOR_DELEGATION" : 0x1000000 ,
    "PARTIAL_SECRETS_ACCOUNT" : 0x04000000
    }
    uac_flag = ""
    for item in results_item_1_0:
        if item:
            user_uac = item['useraccountcontrol']
            uac_flag = str(user_uac)
            for flag in UAC_FLAG:
                if UAC_FLAG[flag] & int(hex(user_uac),16):
    	            uac_flag += "," + flag
        #phantom.debug("uac flag = " + uac_flag)
        if item and item['distinguishedname'].find('OU=CSOC-Users,DC=csoc,DC=krungthai,DC=local') != -1:
            #phantom.debug(item['useraccountcontrol'])
            parameters = []
            cef_json = {"destinationUserName_AD" : "CSOC AD"  , "destinationUserName_UAC" : uac_flag}
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
            #phantom.debug(item['useraccountcontrol'])
            parameters = []
            cef_json = {"destinationUserName_AD" : "KTB AD"  , "destinationUserName_UAC" : uac_flag}
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
            #phantom.debug(item['useraccountcontrol'])
            parameters = []
            cef_json = {"destinationUserName_AD" : "KTBCS AD" , "destinationUserName_UAC" : uac_flag}
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

    return

def decision_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_8() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        for_amp_query_dst_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def for_amp_query_dst_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('for_amp_query_dst_ip() called')
    
    template = """/v1/computers?internal_ip={0}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="for_amp_query_dst_ip", separator=", ")

    get_amp_event_data_dst_ip(container=container)

    return

def get_amp_event_data_dst_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_amp_event_data_dst_ip() called')

    # collect data for 'get_amp_event_data_dst_ip' call
    formatted_data_1 = phantom.get_format_data(name='for_amp_query_dst_ip')

    parameters = []
    
    # build parameters list for 'get_amp_event_data_dst_ip' call
    parameters.append({
        'headers': "{\"Authorization\": \"Basic NzU4MWVjYTU3YjAzMjZhMTJiM2U6ODJjNGFhZmYtNzExMS00N2JmLTg4YjUtNzg2N2E0MTQzZTY1\"}",
        'location': formatted_data_1,
        'verify_certificate': False,
    })

    phantom.act(action="get data", parameters=parameters, assets=['cisco amp base64'], callback=decision_9, name="get_amp_event_data_dst_ip")

    return

def decision_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_9() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_amp_event_data_dst_ip:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        count_guid_dst_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def count_guid_dst_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('count_guid_dst_ip() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['get_amp_event_data_dst_ip:action_result.status', 'get_amp_event_data_dst_ip:action_result.data.*.response_body'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_1_1 = [item[1] for item in results_data_1]

    count_guid_dst_ip__connector_guid = None
    count_guid_dst_ip__connector_guid_count = None

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
            
    count_guid_dst_ip__connector_guid = connector_guid
    count_guid_dst_ip__connector_guid_count = connector_guid_count

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='count_guid_dst_ip:connector_guid', value=json.dumps(count_guid_dst_ip__connector_guid))
    phantom.save_run_data(key='count_guid_dst_ip:connector_guid_count', value=json.dumps(count_guid_dst_ip__connector_guid_count))
    decision_11(container=container)

    return

def decision_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_10() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationHostName", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        format_kaspersky_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        format_amp_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        format_mcafee_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def decision_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_11() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["count_guid_dst_ip:custom_function:connector_guid_count", "==", 1],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        get_device_info_dst_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["count_guid_dst_ip:custom_function:connector_guid_count", ">", 1],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        format_multiple_guid_dst_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 3
    format_ISE_query_dst_IP(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def get_device_info_dst_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_device_info_dst_ip() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    count_guid_dst_ip__connector_guid = json.loads(phantom.get_run_data(key='count_guid_dst_ip:connector_guid'))
    # collect data for 'get_device_info_dst_ip' call

    parameters = []
    
    # build parameters list for 'get_device_info_dst_ip' call
    parameters.append({
        'connector_guid': count_guid_dst_ip__connector_guid,
    })

    phantom.act(action="get device info", parameters=parameters, assets=['cisco fireamp asset'], callback=format_dst_user_query, name="get_device_info_dst_ip")

    return

def check_active_IP_match_dst_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_active_IP_match_dst_IP() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id', 'artifact:*.id'])
    results_data_1 = phantom.collect2(container=container, datapath=['get_device_info_dst_ip:action_result.data.*.data.active', 'get_device_info_dst_ip:action_result.data.*.data.internal_ips', 'get_device_info_dst_ip:action_result.data.*.data.connector_guid', 'get_device_info_dst_ip:action_result.data.*.data.network_addresses.*.mac', 'get_device_info_dst_ip:action_result.data.*.data.hostname'], action_results=results)
    container_item_0 = [item[0] for item in container_data]
    container_item_1 = [item[1] for item in container_data]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_1_1 = [item[1] for item in results_data_1]
    results_item_1_2 = [item[2] for item in results_data_1]
    results_item_1_3 = [item[3] for item in results_data_1]
    results_item_1_4 = [item[4] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    matched_guid = []
    matched_mac = []
    matched_hostname = []
    matched_guid_count = 0
    phantom.debug(container_item_0)
    phantom.debug(results_data_1)
    for cguid in results_data_1:
        if  cguid[0] == True and container_item_0[0] in cguid[1]:
            matched_guid.append(cguid[2])
            matched_mac.append(cguid[3])
            matched_hostname.append(cguid[4])
            matched_guid_count += 1
    phantom.debug(matched_guid)
    
    parameters = []
    cef_json = {"destinationAddress_connector_guid" : matched_guid[0] , "destinationAddress_MacAddresss" : matched_mac[0] ,"destinationAddress_hostname" : matched_hostname[0].split(".")[0] ,"destinationAddress_fullhostname" : matched_hostname[0] , "destinationAddress_QueryFrom" : "AMP" }
    
    # build parameters list for 'update_guid' call
    parameters.append({
    'artifact_id': container_item_1[0],
    'name': "",
    'label': "",
    'severity': "",
    'cef_json': cef_json,
    'cef_types_json': "",
    'tags': "",
    'overwrite': "",
    'artifact_json': "",
    })
    
    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_destinationAddress_guid")

    ################################################################################
    ## Custom Code End
    ################################################################################

    return

def format_multiple_guid_dst_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_multiple_guid_dst_ip() called')
    
    template = """{0} below endpoint guid found using same active IP {2}

%%
{1}

%%"""

    # parameter list for template variable replacement
    parameters = [
        "count_guid_dst_ip:custom_function:connector_guid_count",
        "count_guid_dst_ip:custom_function:connector_guid",
        "artifact:*.cef.destinationAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_multiple_guid_dst_ip", separator=", ")

    add_note_3(container=container)

    return

def add_note_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_3() called')

    formatted_data_1 = phantom.get_format_data(name='format_multiple_guid_dst_ip')

    note_title = "Multiple Active GUID detected"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def format_ISE_query_dst_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ISE_query_dst_IP() called')
    
    template = """index=ktb_mgmt_default earliest=-15m@m latest=now sourcetype=\"cisco:ise:syslog\"  Framed_IP_Address={0} |  dedup Framed_IP_Address"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ISE_query_dst_IP", separator=", ")

    run_ISE_query_dst_IP(container=container)

    return

def run_ISE_query_dst_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_ISE_query_dst_IP() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_ISE_query_dst_IP' call
    formatted_data_1 = phantom.get_format_data(name='format_ISE_query_dst_IP')

    parameters = []
    
    # build parameters list for 'run_ISE_query_dst_IP' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=decision_12, name="run_ISE_query_dst_IP")

    return

def decision_12(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_12() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["run_ISE_query_dst_IP:action_result.summary.total_events", "==", 1],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        update_artifact_dst_macaddr_from_ise(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def update_artifact_dst_macaddr_from_ise(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_artifact_dst_macaddr_from_ise() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.id'])
    results_data_1 = phantom.collect2(container=container, datapath=['run_ISE_query_dst_IP:action_result.data.*.raw_msg'], action_results=results)
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
                cef_json = {"destinationAddress_MacAddress" : item2.split('=')[1].replace('-',':') , "destinationAddress_QueryFrom" : "ISE" }
                
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
    
    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_destinationAddress_mac")
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    return

def format_kaspersky_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_kaspersky_query() called')
    
    template = """earliest = -7d@d index=ktb_mgmt_default sourcetype =\"kaspersky:klprci\"| search identNetBios= {0}
| sort 0 - _time
| eval time = _time
|convert timeformat=\"%d-%m-%Y %H:%M:%S\" ctime(time) AS time

| table time,identNetBios,src
| dedup identNetBios,src"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationHostName",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_kaspersky_query", separator=", ")

    run_kaspersky_query(container=container)

    return

def run_kaspersky_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_kaspersky_query() called')

    # collect data for 'run_kaspersky_query' call
    formatted_data_1 = phantom.get_format_data(name='format_kaspersky_query')

    parameters = []
    
    # build parameters list for 'run_kaspersky_query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=join_custom_function_ip_result, name="run_kaspersky_query")

    return

def custom_function_ip_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('custom_function_ip_result() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['run_kaspersky_query:action_result.status', 'run_kaspersky_query:action_result.data.*.src'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['run_amp_query:action_result.status', 'run_amp_query:action_result.data.*.ip', 'run_amp_query:action_result.data.*.connector_guid'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['run_mcafee_query:action_result.status', 'run_mcafee_query:action_result.data.*.dest_ip'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_1_1 = [item[1] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]
    results_item_2_1 = [item[1] for item in results_data_2]
    results_item_2_2 = [item[2] for item in results_data_2]
    results_item_3_0 = [item[0] for item in results_data_3]
    results_item_3_1 = [item[1] for item in results_data_3]

    custom_function_ip_result__unique_ip = None
    custom_function_ip_result__target_ip = None
    custom_function_ip_result__sources = None
    custom_function_ip_result__connector_guid = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    target_ip = []
    sources = []
    unique_ip = 0
    connector_guid = ""
    
    if results_item_1_1[0]:
        target_ip.append(results_item_1_1[0])
        sources.append("KASPERSKY")
    if results_item_2_1[0]:
        target_ip.append(results_item_2_1[0])
        sources.append("AMP")
        connector_guid = results_item_2_2[0]
    if results_item_3_1[0]:
        target_ip.append(results_item_3_1[0])
        sources.append("MCAFEE")
    
    unique_ip = len(set(target_ip))
    
    custom_function_ip_result__unique_ip = unique_ip
    custom_function_ip_result__target_ip = target_ip
    custom_function_ip_result__sources = sources
    custom_function_ip_result__connector_guid = connector_guid

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='custom_function_ip_result:unique_ip', value=json.dumps(custom_function_ip_result__unique_ip))
    phantom.save_run_data(key='custom_function_ip_result:target_ip', value=json.dumps(custom_function_ip_result__target_ip))
    phantom.save_run_data(key='custom_function_ip_result:sources', value=json.dumps(custom_function_ip_result__sources))
    phantom.save_run_data(key='custom_function_ip_result:connector_guid', value=json.dumps(custom_function_ip_result__connector_guid))
    decision_13(container=container)

    return

def join_custom_function_ip_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_custom_function_ip_result() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['run_kaspersky_query', 'run_mcafee_query', 'run_amp_query']):
        
        # call connected block "custom_function_ip_result"
        custom_function_ip_result(container=container, handle=handle)
    
    return

def format_amp_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_amp_query() called')
    
    template = """earliest = -7d@d index=ktb_csoc_default sourcetype= \"cisco:amp:event\"
| sort 0 - _time
| eval time = _time
|convert timeformat=\"%d-%m-%Y %H:%M:%S\" ctime(time) AS time
| spath \"event.computer.hostname\" | search \"event.computer.hostname\"=\"{0}*\"
| table time,event.computer.hostname ,event.computer.network_addresses{{}}.ip ,event.computer.network_addresses{{}}.mac ,event.computer.connector_guid
| dedup event.computer.connector_guid
| rename event.computer.network_addresses{{}}.ip  as ip 
| rename event.computer.network_addresses{{}}.mac as mac
| rename event.computer.connector_guid as connector_guid"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationHostName",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_amp_query", separator=", ")

    run_amp_query(container=container)

    return

def format_mcafee_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_mcafee_query() called')
    
    template = """earliest = -7d@d index=ktb_mgmt_default sourcetype=\"mcafee:epo\" dest_dns={0}
| sort 0 - _time
| eval time = _time
|convert timeformat=\"%d-%m-%Y %H:%M:%S\" ctime(time) AS time
| table time,dest_dns ,dest_ip,dest_mac,os,sp
| dedup dest_dns ,dest_ip"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationHostName",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_mcafee_query", separator=", ")

    run_mcafee_query(container=container)

    return

def run_amp_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_amp_query() called')

    # collect data for 'run_amp_query' call
    formatted_data_1 = phantom.get_format_data(name='format_amp_query')

    parameters = []
    
    # build parameters list for 'run_amp_query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=join_custom_function_ip_result, name="run_amp_query")

    return

def run_mcafee_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_mcafee_query() called')

    # collect data for 'run_mcafee_query' call
    formatted_data_1 = phantom.get_format_data(name='format_mcafee_query')

    parameters = []
    
    # build parameters list for 'run_mcafee_query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=join_custom_function_ip_result, name="run_mcafee_query")

    return

def decision_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_13() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["custom_function_ip_result:custom_function:unique_ip", "==", 1],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        decision_14(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["custom_function_ip_result:custom_function:unique_ip", ">", 1],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        format_multiple_matched_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 3
    add_note_5(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def format_multiple_matched_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_multiple_matched_ip() called')
    
    template = """Target hostname ({0}) matched multiple IPs

List of IP:
%%
IP: {1}

Source: {2}

%%"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationHostName",
        "custom_function_ip_result:custom_function:target_ip",
        "custom_function_ip_result:custom_function:sources",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_multiple_matched_ip", separator=", ")

    add_note_4(container=container)

    return

def add_note_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_4() called')

    formatted_data_1 = phantom.get_format_data(name='format_multiple_matched_ip')

    note_title = "Note from Automated Playbook"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def decision_14(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_14() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["AMP", "in", "custom_function_ip_result:custom_function:sources"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        get_device_info_hostname(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["KASPERSKY", "in", "custom_function_ip_result:custom_function:sources"],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        format_ISE_query_kaspersky(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 3
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["MCAFEE", "in", "custom_function_ip_result:custom_function:sources"],
        ])

    # call connected blocks if condition 3 matched
    if matched:
        format_mcafee_user_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def add_note_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_5() called')

    note_title = "Note from Automated Playbook"
    note_content = "hostname not found"
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def get_device_info_hostname(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_device_info_hostname() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    custom_function_ip_result__connector_guid = json.loads(phantom.get_run_data(key='custom_function_ip_result:connector_guid'))
    # collect data for 'get_device_info_hostname' call

    parameters = []
    
    # build parameters list for 'get_device_info_hostname' call
    parameters.append({
        'connector_guid': custom_function_ip_result__connector_guid,
    })

    phantom.act(action="get device info", parameters=parameters, assets=['cisco fireamp asset'], callback=format_amp_user_query, name="get_device_info_hostname")

    return

def update_artifact_amp(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_artifact_amp() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationHostName', 'artifact:*.id', 'artifact:*.id'])
    results_data_1 = phantom.collect2(container=container, datapath=['get_device_info_hostname:action_result.data.*.data.active', 'get_device_info_hostname:action_result.data.*.data.internal_ips', 'get_device_info_hostname:action_result.data.*.data.network_addresses.*.ip', 'get_device_info_hostname:action_result.data.*.data.network_addresses.*.mac', 'get_device_info_hostname:action_result.data.*.data.connector_guid', 'get_device_info_hostname:action_result.data.*.data.operating_system'], action_results=results)
    container_item_0 = [item[0] for item in container_data]
    container_item_1 = [item[1] for item in container_data]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_1_1 = [item[1] for item in results_data_1]
    results_item_1_2 = [item[2] for item in results_data_1]
    results_item_1_3 = [item[3] for item in results_data_1]
    results_item_1_4 = [item[4] for item in results_data_1]
    results_item_1_5 = [item[5] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    parameters = []
    
    cef_json = {
    "destinationHostName_connector_guid" : results_item_1_4[0] ,
    "destinationHostName_MacAddress" : results_item_1_3[0] ,
    "destinationHostName_IP" : results_item_1_2[0] ,
    "destinationHostName_OS" : results_item_1_5[0] ,
    "destinationHostName_QueryFrom" : "AMP" }
    
    # build parameters list for 'update_guid' call
    parameters.append({
    'artifact_id': container_item_1[0],
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
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    return

def update_artifact_kasper_ise(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_artifact_kasper_ise() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.cef.destinationHostName', 'artifact:*.id'])
    results_data_1 = phantom.collect2(container=container, datapath=['run_kaspersky_query:action_result.data.*.src'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['run_ISE_query_kaspersky:action_result.data.*._raw'], action_results=results)
    container_item_0 = [item[0] for item in container_data]
    container_item_1 = [item[1] for item in container_data]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    parameters = []
    cef_json = {
    "destinationHostName_IP" : results_item_1_0[0] ,
    "destinationHostName_QueryFrom" : "KASPERSKY" }
    
    phantom.debug(len(results_item_2_0))

    for item in results_item_2_0:
        ltmp = item.split(',')
        for item2 in ltmp:
            if item2.split('=')[0].strip() == "Calling-Station-ID":
                cef_json = {"destinationAddress_MacAddress" : 
                item2.split('=')[1].replace('-',':') , 
                "destinationAddress_QueryFrom" : "KASPERSKY+ISE" }

    # build parameters list for 'update_guid' call
    parameters.append({
    'artifact_id': container_item_1[0],
    'name': "",
    'label': "",
    'severity': "",
    'cef_json': cef_json,
    'cef_types_json': "",
    'tags': "",
    'overwrite': "",
    'artifact_json': "",
    })
    
    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_destinationHostName")
     
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

def update_artifact_mcafee(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_artifact_mcafee() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.cef.destinationHostName', 'artifact:*.id'])
    results_data_1 = phantom.collect2(container=container, datapath=['run_mcafee_query:action_result.data.*.dest_ip', 'run_mcafee_query:action_result.data.*.dest_mac', 'run_mcafee_query:action_result.data.*.os'], action_results=results)
    container_item_0 = [item[0] for item in container_data]
    container_item_1 = [item[1] for item in container_data]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_1_1 = [item[1] for item in results_data_1]
    results_item_1_2 = [item[2] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    parameters = []
    
    cef_json = {
    "destinationHostName_MacAddresss" : results_item_1_1[0] ,
    "destinationHostName_IP" : results_item_1_0[0] ,
    "destinationHostName_OS" : results_item_1_2[0] ,
    "destinationHostName_QueryFrom" : "MCAFEE" }
    
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
    
    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_destinationHostName")

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

def format_ISE_query_kaspersky(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ISE_query_kaspersky() called')
    
    template = """index=ktb_mgmt_default earliest=-15m@m latest=now sourcetype=\"cisco:ise:syslog\"  Framed_IP_Address={0} |  dedup Framed_IP_Address"""

    # parameter list for template variable replacement
    parameters = [
        "run_kaspersky_query:action_result.data.*.src",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ISE_query_kaspersky", separator=", ")

    run_ISE_query_kaspersky(container=container)

    return

def run_ISE_query_kaspersky(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_ISE_query_kaspersky() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_ISE_query_kaspersky' call
    formatted_data_1 = phantom.get_format_data(name='format_ISE_query_kaspersky')

    parameters = []
    
    # build parameters list for 'run_ISE_query_kaspersky' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=decision_15, name="run_ISE_query_kaspersky")

    return

def decision_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_15() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["run_ISE_query_kaspersky:action_result.summary.total_events", "==", 1],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        format_kaspersky_user_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["run_ISE_query_kaspersky:action_result.summary.total_events", "==", 0],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        update_artifact_kasper(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def update_artifact_kasper(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_artifact_kasper() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.cef.destinationHostName', 'artifact:*.id'])
    results_data_1 = phantom.collect2(container=container, datapath=['run_kaspersky_query:action_result.data.*.src'], action_results=results)
    container_item_0 = [item[0] for item in container_data]
    container_item_1 = [item[1] for item in container_data]
    results_item_1_0 = [item[0] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    parameters = []
    cef_json = {
    "destinationHostName_IP" : results_item_1_0[0] ,
    "destinationHostName_QueryFrom" : "KASPERSKY" }
    
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
    
    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_destinationHostName")

    ################################################################################
    ## Custom Code End
    ################################################################################

    return

def format_user_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_user_query() called')
    
    template = """summariesonly=true count max(_time) as _time from datamodel=Authentication where Authentication.user!=unknown AND (Authentication.src={1}* OR Authentication.src={0}) AND Authentication.user!=\"$\" Authentication.action=success earliest=-24d latest=now by Authentication.user Authentication.src Authentication.dest Authentication.action
| rename Authentication.* AS *
| rename _time as time 
| convert timeformat=\"%m-%d-%Y %H:%M:%S\" ctime(time) AS time"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
        "get_device_info_src_ip:action_result.data.*.data.hostname",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_user_query", separator=", ")

    run_src_user_query(container=container)

    return

def run_src_user_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_src_user_query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_src_user_query' call
    formatted_data_1 = phantom.get_format_data(name='format_user_query')

    parameters = []
    
    # build parameters list for 'run_src_user_query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "tstats",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=format_34, name="run_src_user_query")

    return

def format_dst_user_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_dst_user_query() called')
    
    template = """summariesonly=true count max(_time) as _time from datamodel=Authentication where Authentication.user!=unknown AND (Authentication.src={1}* OR Authentication.src={0}) AND Authentication.user!=\"$\" Authentication.action=success earliest=-24d latest=now by Authentication.user Authentication.src Authentication.dest Authentication.action
| rename Authentication.* AS *
| rename _time as time 
| convert timeformat=\"%m-%d-%Y %H:%M:%S\" ctime(time) AS time"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationAddress",
        "get_device_info_dst_ip:action_result.data.*.data.hostname",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_dst_user_query", separator=", ")

    run_dst_user_query(container=container)

    return

def run_dst_user_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_dst_user_query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_dst_user_query' call
    formatted_data_1 = phantom.get_format_data(name='format_dst_user_query')

    parameters = []
    
    # build parameters list for 'run_dst_user_query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "tstats",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=format_33, name="run_dst_user_query")

    return

def format_mcafee_user_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_mcafee_user_query() called')
    
    template = """summariesonly=true count max(_time) as _time from datamodel=Authentication where Authentication.user!=unknown AND (Authentication.src={1}* OR Authentication.src={0}) AND Authentication.user!=\"$\" Authentication.action=success earliest=-24d latest=now by Authentication.user Authentication.src Authentication.dest Authentication.action
| rename Authentication.* AS *
| rename _time as time 
| convert timeformat=\"%m-%d-%Y %H:%M:%S\" ctime(time) AS time"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationHostName",
        "run_mcafee_query:action_result.data.*.dest_ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_mcafee_user_query", separator=", ")

    run_mcafee_user_query(container=container)

    return

def format_amp_user_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_amp_user_query() called')
    
    template = """summariesonly=true count max(_time) as _time from datamodel=Authentication where Authentication.user!=unknown AND (Authentication.src={1}* OR Authentication.src={0}) AND Authentication.user!=\"$\" Authentication.action=success earliest=-24d latest=now by Authentication.user Authentication.src Authentication.dest Authentication.action
| rename Authentication.* AS *
| rename _time as time 
| convert timeformat=\"%m-%d-%Y %H:%M:%S\" ctime(time) AS time"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationHostName",
        "get_device_info_hostname:action_result.data.*.data.network_addresses.*.ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_amp_user_query", separator=", ")

    run_amp_user_query(container=container)

    return

def format_kaspersky_user_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_kaspersky_user_query() called')
    
    template = """summariesonly=true count max(_time) as _time from datamodel=Authentication where Authentication.user!=unknown AND (Authentication.src={1}* OR Authentication.src={0}) AND Authentication.user!=\"$\" Authentication.action=success earliest=-24d latest=now by Authentication.user Authentication.src Authentication.dest Authentication.action
| rename Authentication.* AS *
| rename _time as time 
| convert timeformat=\"%m-%d-%Y %H:%M:%S\" ctime(time) AS time"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationHostName",
        "run_kaspersky_query:action_result.data.*.src",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_kaspersky_user_query", separator=", ")

    run_kaspersky_user_query(container=container)

    return

def run_mcafee_user_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_mcafee_user_query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_mcafee_user_query' call
    formatted_data_1 = phantom.get_format_data(name='format_mcafee_user_query')

    parameters = []
    
    # build parameters list for 'run_mcafee_user_query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "tstats",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=format_31, name="run_mcafee_user_query")

    return

def run_amp_user_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_amp_user_query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_amp_user_query' call
    formatted_data_1 = phantom.get_format_data(name='format_amp_user_query')

    parameters = []
    
    # build parameters list for 'run_amp_user_query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "tstats",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=format_30, name="run_amp_user_query")

    return

def run_kaspersky_user_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_kaspersky_user_query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_kaspersky_user_query' call
    formatted_data_1 = phantom.get_format_data(name='format_kaspersky_user_query')

    parameters = []
    
    # build parameters list for 'run_kaspersky_user_query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "tstats",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=format_32, name="run_kaspersky_user_query")

    return

def format_30(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_30() called')
    
    template = """|user|src|dest|time|count|
| :--- | :--- | :--- | :--- | :--- |
%%
|{0}|{1}|{2}|{3}|{4}|
%%"""

    # parameter list for template variable replacement
    parameters = [
        "run_amp_user_query:action_result.data.*.user",
        "run_amp_user_query:action_result.data.*.src",
        "run_amp_user_query:action_result.data.*.dest",
        "run_amp_user_query:action_result.data.*.time",
        "run_amp_user_query:action_result.data.*.count",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_30", separator=", ")

    add_note_7(container=container)

    return

def add_note_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_7() called')

    formatted_data_1 = phantom.get_format_data(name='format_30')

    note_title = "AMP User"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    update_artifact_amp(container=container)

    return

def format_31(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_31() called')
    
    template = """|user|src|dest|time|count|
| :--- | :--- | :--- | :--- | :--- |
%%
|{0}||{2}|{3}|{4}|
%%"""

    # parameter list for template variable replacement
    parameters = [
        "run_mcafee_user_query:action_result.data.*.user",
        "run_mcafee_user_query:action_result.data.*.src",
        "run_mcafee_user_query:action_result.data.*.dest",
        "run_mcafee_user_query:action_result.data.*.time",
        "run_mcafee_user_query:action_result.data.*.count",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_31", separator=", ")

    add_note_8(container=container)

    return

def add_note_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_8() called')

    formatted_data_1 = phantom.get_format_data(name='format_31')

    note_title = "McAfee User"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    update_artifact_mcafee(container=container)

    return

def format_32(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_32() called')
    
    template = """|user|src|dest|time|count|
| :--- | :--- | :--- | :--- | :--- |
%%
|{0}|{1}|{2}|{3}|{4}|
%%"""

    # parameter list for template variable replacement
    parameters = [
        "run_kaspersky_user_query:action_result.data.*.user",
        "run_kaspersky_user_query:action_result.data.*.src",
        "run_kaspersky_user_query:action_result.data.*.dest",
        "run_kaspersky_user_query:action_result.data.*.time",
        "run_kaspersky_user_query:action_result.data.*.count",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_32", separator=", ")

    add_note_9(container=container)

    return

def add_note_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_9() called')

    formatted_data_1 = phantom.get_format_data(name='format_32')

    note_title = "McAfee User"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    update_artifact_kasper_ise(container=container)

    return

def format_33(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_33() called')
    
    template = """|user|src|dest|time|count|
| :--- | :--- | :--- | :--- | :--- |
%%
|{0}||{2}|{3}|{4}|
%%"""

    # parameter list for template variable replacement
    parameters = [
        "run_dst_user_query:action_result.data.*.user",
        "run_dst_user_query:action_result.data.*.src",
        "run_dst_user_query:action_result.data.*.dest",
        "run_dst_user_query:action_result.data.*.time",
        "run_dst_user_query:action_result.data.*.count",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_33", separator=", ")

    add_note_11(container=container)

    return

def format_34(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_34() called')
    
    template = """|user|src|dest|time|count|
| :--- | :--- | :--- | :--- | :--- |
%%
|{0}|{1}|{2}|{3}|{4}|
%%"""

    # parameter list for template variable replacement
    parameters = [
        "run_src_user_query:action_result.data.*.user",
        "run_src_user_query:action_result.data.*.src",
        "run_src_user_query:action_result.data.*.dest",
        "run_src_user_query:action_result.data.*.time",
        "run_src_user_query:action_result.data.*.count",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_34", separator=", ")

    add_note_10(container=container)

    return

def add_note_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_10() called')

    formatted_data_1 = phantom.get_format_data(name='format_34')

    note_title = "Source User"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    check_active_IP_match_src_IP(container=container)

    return

def add_note_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_11() called')

    formatted_data_1 = phantom.get_format_data(name='format_33')

    note_title = "Destination User"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    check_active_IP_match_dst_IP(container=container)

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