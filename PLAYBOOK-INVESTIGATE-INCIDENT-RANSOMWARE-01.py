"""
USE CASE: This playbook will call triage playbook, make decision to assign to analyst or create incident
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'playbook_local_KTB_Master_Playbook_1' block
    playbook_local_KTB_Master_Playbook_1(container=container)

    return

"""
Is
Malware
quarantined
based on
‘action’ field in
notable
"""
def Is_Malware_quarantined_based_on_action(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Is_Malware_quarantined_based_on_action() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["device_quarantined", "not in", "artifact:*.tags"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        add_note_20(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        decision_22(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    decision_18(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Check Malware
detected on
server or
critical
desktop
"""
def Check_Malware_detected_on_server_or_crit(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_Malware_detected_on_server_or_crit() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Malre_detect_on_server:custom_function:criticalDevice", "!=", []],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Set_severity_to_High_quarantined_malware(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    join_quarantine_not_critical_Filter_signature(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Set severity to
High quarantined malware 
"""
def Set_severity_to_High_quarantined_malware(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Set_severity_to_High_quarantined_malware() called')

    phantom.set_severity(container=container, severity="High")

    return

"""
not quarantined Malware
detected on
server or
critical
desktop
"""
def not_quarantined_Malware_detected_on_serv(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('not_quarantined_Malware_detected_on_serv() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.deviceHostname', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]

    not_quarantined_Malware_detected_on_serv__noncriticalDevice = None
    not_quarantined_Malware_detected_on_serv__criticalDevice = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    criticalDevice = []
    noncriticalDevice = []
    success, message, devicelist = phantom.get_list(list_name='Servers and Critical desktops')
    if devicelist is not None:        
        for item in container_item_0:
            if devicelist is not None:
                if not any(item in device for device in devicelist):
                    noncriticalDevice.append(item)
                else:
                    criticalDevice.append(item)

    phantom.debug(noncriticalDevice)
    phantom.debug(criticalDevice)
    not_quarantined_Malware_detected_on_serv__noncriticalDevice = noncriticalDevice
    not_quarantined_Malware_detected_on_serv__criticalDevice = criticalDevice

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='not_quarantined_Malware_detected_on_serv:noncriticalDevice', value=json.dumps(not_quarantined_Malware_detected_on_serv__noncriticalDevice))
    phantom.save_run_data(key='not_quarantined_Malware_detected_on_serv:criticalDevice', value=json.dumps(not_quarantined_Malware_detected_on_serv__criticalDevice))
    Check_not_quarantined_Malware_detected_o(container=container)

    return

"""
Check not quarantined Malware
detected on
server or
critical
desktop
"""
def Check_not_quarantined_Malware_detected_o(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_not_quarantined_Malware_detected_o() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["not_quarantined_Malware_detected_on_serv:custom_function:criticalDevice", "!=", []],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Set_severity_to_High_not_quarantined_mal(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        add_note_22(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    Filter_out_deviceHostname(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Set severity to
High not quarantined malware 
"""
def Set_severity_to_High_not_quarantined_mal(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Set_severity_to_High_not_quarantined_mal() called')

    phantom.set_severity(container=container, severity="High")

    return

"""
not quarantined Filter
signature from 
container
"""
def not_quarantined_Filter_signature_from_c(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('not_quarantined_Filter_signature_from_c() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.signature", "!=", ""],
        ],
        name="not_quarantined_Filter_signature_from_c:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        not_quarantined_not_critical_Format_data(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def join_not_quarantined_Filter_signature_from_c(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_not_quarantined_Filter_signature_from_c() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_not_quarantined_Filter_signature_from_c_called'):
        return

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(playbook_names=['playbook_local_KTB_Master_Playbook_1']):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_not_quarantined_Filter_signature_from_c_called', value='not_quarantined_Filter_signature_from_c')
        
        # call connected block "not_quarantined_Filter_signature_from_c"
        not_quarantined_Filter_signature_from_c(container=container, handle=handle)
    
    return

"""
not quarantined not critical Format data to
Run Query
"""
def not_quarantined_not_critical_Format_data(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('not_quarantined_not_critical_Format_data() called')
    
    template = """index=* sourcetype = kaspersky:gnrl OR sourcetype = *cisco:amp* OR sourcetype = mcafee*  earliest=-8h@h latest=now
| search \"{0}\"
| dedup dest"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.signature",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="not_quarantined_not_critical_Format_data", separator=", ")

    not_quarantined_not_critical_Run_query_g(container=container)

    return

"""
not quarantined not critical Run query get number of host
with the same
signature
"""
def not_quarantined_not_critical_Run_query_g(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('not_quarantined_not_critical_Run_query_g() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'not_quarantined_not_critical_Run_query_g' call
    formatted_data_1 = phantom.get_format_data(name='not_quarantined_not_critical_Format_data')

    parameters = []
    
    # build parameters list for 'not_quarantined_not_critical_Run_query_g' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=not_quarantined_not_critical_Check_numbe, name="not_quarantined_not_critical_Run_query_g")

    return

"""
not quarantined not critical Check number of hosts with the same signature
"""
def not_quarantined_not_critical_Check_numbe(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('not_quarantined_not_critical_Check_numbe() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["not_quarantined_not_critical_Run_query_g:action_result.summary.total_events", ">=", 10],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        not_quarantined_not_critical_check_sever(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        add_note_23(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    not_quarantined_not_critical_Assign_Ana(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
not quarantined not critical  Assign Analyst
to make final decision
"""
def not_quarantined_not_critical_Assign_Ana(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('not_quarantined_not_critical_Assign_Ana() called')

    note_title = "Number of affected host with  same  signature"
    note_content = "Less than 10"
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

"""
not quarantined not critical check severity low
"""
def not_quarantined_not_critical_check_sever(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('not_quarantined_not_critical_check_sever() called')
    
    severity_param = container.get('severity', None)

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            [severity_param, "!=", "low"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        return

    # call connected blocks for 'else' condition 2
    not_quarantined_not_critical_Set_severit(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
not quarantined not critical Set severity to
Medium
"""
def not_quarantined_not_critical_Set_severit(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('not_quarantined_not_critical_Set_severit() called')

    phantom.set_severity(container=container, severity="Medium")

    return

"""
quarantined not critical Filter
signature from 
container
"""
def quarantine_not_critical_Filter_signature(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('quarantine_not_critical_Filter_signature() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.signature", "!=", ""],
        ],
        name="quarantine_not_critical_Filter_signature:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        quarantined_not_critical_Format_data_to(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def join_quarantine_not_critical_Filter_signature(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_quarantine_not_critical_Filter_signature() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_quarantine_not_critical_Filter_signature_called'):
        return

    # no callbacks to check, call connected block "quarantine_not_critical_Filter_signature"
    phantom.save_run_data(key='join_quarantine_not_critical_Filter_signature_called', value='quarantine_not_critical_Filter_signature', auto=True)

    quarantine_not_critical_Filter_signature(container=container, handle=handle)
    
    return

"""
quarantined not critical Format data to
Run Query
"""
def quarantined_not_critical_Format_data_to(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('quarantined_not_critical_Format_data_to() called')
    
    template = """index=* sourcetype = kaspersky:gnrl OR sourcetype = *cisco:amp* OR sourcetype = mcafee*  earliest=-8h@h latest=now
| search \"{0}\"
| dedup dest"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.signature",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="quarantined_not_critical_Format_data_to", separator=", ")

    quarantined_not_critical_Run_query_get_n(container=container)

    return

"""
quarantined not critical Run query get number of host
with the same
signature
"""
def quarantined_not_critical_Run_query_get_n(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('quarantined_not_critical_Run_query_get_n() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'quarantined_not_critical_Run_query_get_n' call
    formatted_data_1 = phantom.get_format_data(name='quarantined_not_critical_Format_data_to')

    parameters = []
    
    # build parameters list for 'quarantined_not_critical_Run_query_get_n' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=quarantined_not_critical_Check_number_of, name="quarantined_not_critical_Run_query_get_n")

    return

"""
quarantined not critical Check number of hosts with the same signature
"""
def quarantined_not_critical_Check_number_of(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('quarantined_not_critical_Check_number_of() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["quarantined_not_critical_Run_query_get_n:action_result.summary.total_events", ">=", 10],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        quarantined_not_critical_check_severity(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    quarantined_not_critical_Assign_Analyst(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
quarantined not critical check severity low
"""
def quarantined_not_critical_check_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('quarantined_not_critical_check_severity() called')
    
    severity_param = container.get('severity', None)

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            [severity_param, "!=", "low"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        return

    # call connected blocks for 'else' condition 2
    quarantined_not_critical_Set_severity_to(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
quarantined not critical  Assign Analyst
to make final decision
"""
def quarantined_not_critical_Assign_Analyst(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('quarantined_not_critical_Assign_Analyst() called')

    note_title = "Number of hosts with same signature"
    note_content = "Less than 10"
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

"""
quarantined not critical Set severity to
Medium
"""
def quarantined_not_critical_Set_severity_to(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('quarantined_not_critical_Set_severity_to() called')

    phantom.set_severity(container=container, severity="Medium")

    return

"""
Is it in the list of NO
containment Or is a
server (subnets for
servers)
"""
def Is_it_in_the_list_of_NO_containment_Or_i(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Is_it_in_the_list_of_NO_containment_Or_i() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_out_deviceHostname:condition_1:artifact:*.cef.deviceHostname'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    Is_it_in_the_list_of_NO_containment_Or_i__noContainmentTrue = None
    Is_it_in_the_list_of_NO_containment_Or_i__noContainmentFalse = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    success, message, nocontainmentlist = phantom.get_list(list_name='nocontainmentlist')
    
    urllist = filtered_artifacts_item_1_0
    noContainmentTrue = []
    noContainmentFalse = []
    for item in urllist:
        if not any(item in sublist for sublist in nocontainmentlist):
            phantom.debug("{} is public".format(item))
            phantom.debug("*******in noContainment********")
            phantom.debug(item)
            phantom.debug(nocontainmentlist)
            noContainmentFalse.append(item)
        else:
            phantom.debug("{} is private".format(item))
            phantom.debug("*******in Containment********")
            phantom.debug(item)
            noContainmentTrue.append(item)
            
    Is_it_in_the_list_of_NO_containment_Or_i__noContainmentTrue = noContainmentTrue
    Is_it_in_the_list_of_NO_containment_Or_i__noContainmentFalse = noContainmentFalse
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Is_it_in_the_list_of_NO_containment_Or_i:noContainmentTrue', value=json.dumps(Is_it_in_the_list_of_NO_containment_Or_i__noContainmentTrue))
    phantom.save_run_data(key='Is_it_in_the_list_of_NO_containment_Or_i:noContainmentFalse', value=json.dumps(Is_it_in_the_list_of_NO_containment_Or_i__noContainmentFalse))
    Check_Is_it_in_the_list_of_NO_containmen(container=container)

    return

"""
Check Is it in the list of NO
containment Or is a
server (subnets for
servers)
"""
def Check_Is_it_in_the_list_of_NO_containmen(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_Is_it_in_the_list_of_NO_containmen() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Is_it_in_the_list_of_NO_containment_Or_i:custom_function:noContainmentTrue", "!=", []],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        not_quarantined_no_containment_Filter_si(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    join_decision_17(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    add_note_19(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Filter out deviceHostname
"""
def Filter_out_deviceHostname(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_out_deviceHostname() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.deviceHostname", "!=", ""],
        ],
        name="Filter_out_deviceHostname:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Is_it_in_the_list_of_NO_containment_Or_i(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
not quarantined no containment Filter
signature from 
container
"""
def not_quarantined_no_containment_Filter_si(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('not_quarantined_no_containment_Filter_si() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.signature", "!=", ""],
        ],
        name="not_quarantined_no_containment_Filter_si:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        not_quarantined_No_containment_Format_da(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
not quarantined No containment Format data to
Run Query
"""
def not_quarantined_No_containment_Format_da(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('not_quarantined_No_containment_Format_da() called')
    
    template = """index=* sourcetype = kaspersky:gnrl OR sourcetype = *cisco:amp* OR sourcetype = mcafee*  earliest=-8h@h latest=now
| search \"{0}\"
| dedup dest"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.signature",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="not_quarantined_No_containment_Format_da", separator=", ")

    not_quarantined_No_containment_Run_query(container=container)

    return

"""
not quarantined No containment Run query get number of host
with the same
signature
"""
def not_quarantined_No_containment_Run_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('not_quarantined_No_containment_Run_query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'not_quarantined_No_containment_Run_query' call
    formatted_data_1 = phantom.get_format_data(name='not_quarantined_No_containment_Format_da')

    parameters = []
    
    # build parameters list for 'not_quarantined_No_containment_Run_query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=not_quarantined_No_containment_Check_num, name="not_quarantined_No_containment_Run_query")

    return

"""
not quarantined No containment Check number of hosts with the same signature
"""
def not_quarantined_No_containment_Check_num(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('not_quarantined_No_containment_Check_num() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["not_quarantined_No_containment_Run_query:action_result.summary.total_events", ">=", 10],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        not_quarantined_No_containment_check_sev(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    not_quarantined_No_containment_Assign_A(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
not quarantined No containment  Assign Analyst
to make final decision
"""
def not_quarantined_No_containment_Assign_A(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('not_quarantined_No_containment_Assign_A() called')

    note_title = "Number of host affected with same signature"
    note_content = "Less than 10"
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

"""
not quarantined No containment check severity low
"""
def not_quarantined_No_containment_check_sev(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('not_quarantined_No_containment_check_sev() called')
    
    severity_param = container.get('severity', None)

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            [severity_param, "!=", "low"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        return

    # call connected blocks for 'else' condition 2
    not_quarantined_No_containment_Set_sever(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
not quarantined No containment Set severity to
Medium
"""
def not_quarantined_No_containment_Set_sever(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('not_quarantined_No_containment_Set_sever() called')

    phantom.set_severity(container=container, severity="Medium")

    return

def get_trajectory_by_hostname_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_trajectory_by_hostname_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_trajectory_by_hostname_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.deviceHostname', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_trajectory_by_hostname_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hostName': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="get_trajectory_by_hostname", parameters=parameters, assets=['amp-test'], callback=get_trajectory_by_hostname_1_callback, name="get_trajectory_by_hostname_1")

    return

def get_trajectory_by_hostname_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('get_trajectory_by_hostname_1_callback() called')
    
    join_Malre_detect_on_server(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    add_note_18(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def Malre_detect_on_server(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Malre_detect_on_server() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.deviceHostname', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]

    Malre_detect_on_server__noncriticalDevice = None
    Malre_detect_on_server__criticalDevice = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    criticalDevice = []
    noncriticalDevice = []
    success, message, devicelist = phantom.get_list(list_name='Servers and Critical desktops')
    if devicelist is not None:        
        for item in container_item_0:
            if devicelist is not None:
                if not any(item in device for device in devicelist):
                    noncriticalDevice.append(item)
                else:
                    criticalDevice.append(item)
                
    Malre_detect_on_server__noncriticalDevice = noncriticalDevice
    Malre_detect_on_server__criticalDevice = criticalDevice
    phantom.debug(criticalDevice)
    phantom.debug(noncriticalDevice)
    phantom.debug("---------------------------------")  
    
    #########################################################################
    #########################################################################
    #########################################################################
    #########################################################################
    #########################################################################
    #########################################################################
    #########################################################################
    #########################################################################
    #########################################################################
    #########################################################################
    #########################################################################
    #########################################################################
    #########################################################################
    #########################################################################
    #########################################################################
    #########################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Malre_detect_on_server:noncriticalDevice', value=json.dumps(Malre_detect_on_server__noncriticalDevice))
    phantom.save_run_data(key='Malre_detect_on_server:criticalDevice', value=json.dumps(Malre_detect_on_server__criticalDevice))
    Check_Malware_detected_on_server_or_crit(container=container)

    return

def join_Malre_detect_on_server(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_Malre_detect_on_server() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_Malre_detect_on_server_called'):
        return

    # no callbacks to check, call connected block "Malre_detect_on_server"
    phantom.save_run_data(key='join_Malre_detect_on_server_called', value='Malre_detect_on_server', auto=True)

    Malre_detect_on_server(container=container, handle=handle)
    
    return

def decision_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_15() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.sourceAddress_malicious", "==", True],
            ["artifact:*.cef.destinationAddress_malicious", "==", True],
            ["artifact:*.cef.requestURL_malicious", "==", True],
            ["artifact:*.cef.fileHash_malicious", "==", True],
            ["indicator_malicious", "in", "artifact:*.cef.tags"],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        decision_21(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    join_not_quarantined_Filter_signature_from_c(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
ktb
"""
def Identify_if_case_is_closed(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Identify_if_case_is_closed() called')
    
    status_param = container.get('status', None)

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            [status_param, "==", "closed"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        return

    # call connected blocks for 'else' condition 2
    Is_Malware_quarantined_based_on_action(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def playbook_local_KTB_Master_Playbook_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_KTB_Master_Playbook_1() called')
    
    # call playbook "local/KTB Master Playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/KTB Master Playbook", container=container, name="playbook_local_KTB_Master_Playbook_1", callback=Identify_if_case_is_closed)

    return

def decision_17(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_17() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["stealthwatch", "in", "artifact:*.cef.sourcetype"],
            ["forti", "==", "artifact:*.cef.sourcetype"],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        decision_15(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    join_not_quarantined_Filter_signature_from_c(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def join_decision_17(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_decision_17() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_decision_17_called'):
        return

    # no callbacks to check, call connected block "decision_17"
    phantom.save_run_data(key='join_decision_17_called', value='decision_17', auto=True)

    decision_17(container=container, handle=handle)
    
    return

def add_note_18(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_18() called')

    results_data_1 = phantom.collect2(container=container, datapath=['get_trajectory_by_hostname_1:action_result.message'], action_results=results)

    results_item_1_0 = [item[0] for item in results_data_1]

    note_title = "Device trajectory  note"
    note_content = results_item_1_0
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def decision_18(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_18() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["amp", "in", "artifact:*.cef.sourcetype"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        get_trajectory_by_hostname_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    decision_23(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def add_note_19(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_19() called')

    not_quarantined_Malware_detected_on_serv__criticalDevice = json.loads(phantom.get_run_data(key='not_quarantined_Malware_detected_on_serv:criticalDevice'))

    note_title = "Non Contained - non-Critial-no conain"
    note_content = not_quarantined_Malware_detected_on_serv__criticalDevice
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def add_note_20(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_20() called')

    note_title = "Non-Contained Notes"
    note_content = "Non-Contained Flow"
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def add_note_22(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_22() called')

    not_quarantined_Malware_detected_on_serv__criticalDevice = json.loads(phantom.get_run_data(key='not_quarantined_Malware_detected_on_serv:criticalDevice'))

    note_title = "device note critcal"
    note_content = not_quarantined_Malware_detected_on_serv__criticalDevice
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def add_note_23(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_23() called')

    results_data_1 = phantom.collect2(container=container, datapath=['not_quarantined_not_critical_Run_query_g:action_result.summary.total_events'], action_results=results)

    results_item_1_0 = [item[0] for item in results_data_1]

    note_title = "Number of host with same signature"
    note_content = results_item_1_0
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
            ["Address_blocked", "in", "artifact:*.tags"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        add_note_26(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    playbook_local_KTB_Approve_Playbook_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def add_note_26(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_26() called')

    note_title = "Contained Notes"
    note_content = "Contain has been done before"
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    join_not_quarantined_Filter_signature_from_c(container=container)

    return

def decision_22(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_22() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.deviceHostname", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        not_quarantined_Malware_detected_on_serv(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    join_decision_17(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def decision_23(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_23() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.deviceHostname", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        join_Malre_detect_on_server(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    join_quarantine_not_critical_Filter_signature(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def playbook_local_KTB_Malware_Contain_Playbook_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_KTB_Malware_Contain_Playbook_1() called')
    
    # call playbook "local/KTB Malware Contain Playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/KTB Malware Contain Playbook", container=container, name="playbook_local_KTB_Malware_Contain_Playbook_1", callback=decision_24)

    return

def decision_24(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_24() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Address_blocked", "in", "artifact:*.tags"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        set_status_27(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    join_not_quarantined_Filter_signature_from_c(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def set_status_27(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_27() called')

    phantom.set_status(container=container, status="Resolved")
    join_not_quarantined_Filter_signature_from_c(container=container)

    return

def playbook_local_KTB_Approve_Playbook_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_KTB_Approve_Playbook_2() called')
    
    # call playbook "local/KTB Approve Playbook", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/KTB Approve Playbook", container=container, name="playbook_local_KTB_Approve_Playbook_2", callback=decision_25)

    return

def decision_25(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_25() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["contain_approved", "in", "artifact:*.tags"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        playbook_local_KTB_Malware_Contain_Playbook_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    join_not_quarantined_Filter_signature_from_c(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

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