"""
The playbook automates tasks related to the triage, investigation and containment of persistent external attacks on ORG public servers by an intrusion detection/prevention system that monitors for incoming external request to publicly hosted services in ORG.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'playbook_local_KTB_Triage_Playbook_for_Generic_Label_1' block
    playbook_local_KTB_Triage_Playbook_for_Generic_Label_1(container=container)

    return

def playbook_local_KTB_ENRICH_EXTERNAL_IP_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_KTB_ENRICH_EXTERNAL_IP_1() called')
    
    # call playbook "local/KTB-ENRICH-EXTERNAL-IP", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/KTB-ENRICH-EXTERNAL-IP", container=container, name="playbook_local_KTB_ENRICH_EXTERNAL_IP_1", callback=decision_7)

    return

def playbook_local_KTB_Triage_Playbook_for_Generic_Label_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_KTB_Triage_Playbook_for_Generic_Label_1() called')
    
    # call playbook "local/KTB Triage Playbook for Generic Label", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/KTB Triage Playbook for Generic Label", container=container, name="playbook_local_KTB_Triage_Playbook_for_Generic_Label_1", callback=decision_10)

    return

def Public_IP_in_white_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Public_IP_in_white_list() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_3:condition_1:artifact:*.cef.external_ip'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    Public_IP_in_white_list__InWhitelist = None
    Public_IP_in_white_list__NonWhitellist = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    Watchlist = []
    NonWatchlist = []
    success, message, iplist = phantom.get_list(list_name='nocontainmentlist')
    phantom.debug(iplist)
    phantom.debug(filtered_artifacts_item_1_0)
    if iplist is not None:
        for item in filtered_artifacts_item_1_0:
            if not any(item in ip for ip in iplist):
                NonWatchlist.append(item)
            else:
                Watchlist.append(item)

    Public_IP_in_white_list__InWhitelist = Watchlist
    Public_IP_in_white_list__NonWhitellist = NonWatchlist
    
    phantom.debug(Public_IP_in_white_list__NonWhitellist)
    # Write your custom code here...
    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Public_IP_in_white_list:InWhitelist', value=json.dumps(Public_IP_in_white_list__InWhitelist))
    phantom.save_run_data(key='Public_IP_in_white_list:NonWhitellist', value=json.dumps(Public_IP_in_white_list__NonWhitellist))
    decision_8(container=container)

    return

def Filter_Existing_Observations(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_Existing_Observations() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.observation_id", "!=", ""],
        ],
        name="Filter_Existing_Observations:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Clear_all_existing_observation_artifacts(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Filter_SW_Alert(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_SW_Alert() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.alert_id", "!=", ""],
        ],
        name="Filter_SW_Alert:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Format_data_to_get_observations(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Clear_all_existing_observation_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Clear_all_existing_observation_artifacts() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_Existing_Observations:condition_1:artifact:*.id'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    for artifact in filtered_artifacts_item_1_0:
        result = phantom.delete_artifact(artifact_id=artifact)
        phantom.debug('phantom.delete_artifact results: {} '.format(result))
        
    ####
    ################################################################################
    ## Custom Code End
    ################################################################################

    return

def Format_data_to_get_observations(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_data_to_get_observations() called')
    
    template = """index=ktb_csoc_default sourcetype=\"cisco:stealthwatchcloud:alert\"| spath id | search id={0} | spath \"observations{{}}\" | table text, \"observations{{}}\" | rename \"observations{{}}\" as observations"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Filter_SW_Alert:condition_1:artifact:*.cef.alert_id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_data_to_get_observations", separator=", ")

    Run_Query_to_get_observations(container=container)

    return

def Run_Query_to_get_observations(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Run_Query_to_get_observations() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Run_Query_to_get_observations' call
    formatted_data_1 = phantom.get_format_data(name='Format_data_to_get_observations')

    parameters = []
    
    # build parameters list for 'Run_Query_to_get_observations' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=Prepare_a_list_of_observation_id_in_str, name="Run_Query_to_get_observations")

    return

def Prepare_a_list_of_observation_id_in_str(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Prepare_a_list_of_observation_id_in_str() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['Run_Query_to_get_observations:action_result.data.*.observations'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    Prepare_a_list_of_observation_id_in_str__observation_list_str = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    if results_item_1_0 != []:
        Prepare_a_list_of_observation_id_in_str__observation_list_str = ", ".join(results_item_1_0[0])
        phantom.debug(Prepare_a_list_of_observation_id_in_str__observation_list_str)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Prepare_a_list_of_observation_id_in_str:observation_list_str', value=json.dumps(Prepare_a_list_of_observation_id_in_str__observation_list_str))
    Format_data_to_get_observation_detail(container=container)

    return

def Format_data_to_get_observation_detail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_data_to_get_observation_detail() called')
    
    template = """index=ktb_csoc_default sourcetype=\"cisco:stealthwatchcloud:observation\"| spath id | search id IN ({0}) | table id, external_ip, external_ip_country_code"""

    # parameter list for template variable replacement
    parameters = [
        "Prepare_a_list_of_observation_id_in_str:custom_function:observation_list_str",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_data_to_get_observation_detail", separator=", ")

    Run_query_to_get_observation_detail(container=container)

    return

def Run_query_to_get_observation_detail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Run_query_to_get_observation_detail() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Run_query_to_get_observation_detail' call
    formatted_data_1 = phantom.get_format_data(name='Format_data_to_get_observation_detail')

    parameters = []
    
    # build parameters list for 'Run_query_to_get_observation_detail' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=Add_artifact_of_observations, name="Run_query_to_get_observation_detail")

    return

def Add_artifact_of_observations(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_artifact_of_observations() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Add_artifact_of_observations' call
    results_data_1 = phantom.collect2(container=container, datapath=['Run_query_to_get_observation_detail:action_result.data.*.id', 'Run_query_to_get_observation_detail:action_result.data.*.external_ip'], action_results=results)

    parameters = []
    
    # build parameters list for 'Add_artifact_of_observations' call
    i = 0
    for results_item_1 in results_data_1:
        if i > 6:
            break
        parameters.append({
            'name': "Observation artifact",
            'label': "event",
            'cef_name': "test",
            'contains': "",
            'cef_value': "",
            'container_id': "",
            'cef_dictionary': "{\"observation_id\": " + results_item_1[0] + "," + "\"external_ip\": \"" + results_item_1[1] + "\"}",
            'run_automation': "false",
            'source_data_identifier': f"sw-cloud-observation-id-{results_item_1[0]}",
            # context (artifact id) is added to associate results with the artifact
            #'context': {'artifact_id': results_item_1[0]},
        })
        i += 1

    phantom.act(action="add artifact", parameters=parameters, assets=['phantom asset'], name="Add_artifact_of_observations", parent_action=action, callback=playbook_local_KTB_ENRICH_EXTERNAL_IP_1)

    return

def set_status_set_severity_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_set_severity_6() called')

    phantom.set_status(container=container, status="Open")

    phantom.set_severity(container=container, severity="Low")

    return

def join_set_status_set_severity_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_set_status_set_severity_6() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(playbook_names=['playbook_local_KTB_ENRICH_EXTERNAL_IP_1'], action_names=['Persistent_External_Attack_Detected']):
        
        # call connected block "set_status_set_severity_6"
        set_status_set_severity_6(container=container, handle=handle)
    
    return

def decision_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_6() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.tags", "in", ["indicator_malicious",]],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        filter_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    join_set_status_set_severity_6(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def decision_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_7() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Run_query_to_get_observation_detail:action_result.data.*.external_ip_country_code", "in", ["TH","KH"]],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        filter_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    decision_6(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.external_ip", "!=", ""],
            ["artifact:*.cef.external_ip_malicious", "==", True],
        ],
        logical_operator='and',
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Public_IP_in_white_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def decision_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_8() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Public_IP_in_white_list:custom_function:NonWhitellist", "!=", []],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Prepare_for_showing_attacker_IP(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    join_set_status_set_severity_6(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def Prepare_for_showing_attacker_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Prepare_for_showing_attacker_IP() called')
    
    template = """Attackers IP address(es):
%%
  - {0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "Public_IP_in_white_list:custom_function:NonWhitellist",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Prepare_for_showing_attacker_IP", separator=", ")

    Add_note_for_showing_attackers_IP(container=container)

    return

def Add_note_for_showing_attackers_IP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_note_for_showing_attackers_IP() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Add_note_for_showing_attackers_IP' call
    formatted_data_1 = phantom.get_format_data(name='Prepare_for_showing_attacker_IP')

    parameters = []
    
    # build parameters list for 'Add_note_for_showing_attackers_IP' call
    parameters.append({
        'title': "Attackers IP address",
        'content': formatted_data_1,
        'phase_id': "",
        'container_id': "",
    })

    phantom.act(action="add note", parameters=parameters, assets=['phantom asset'], callback=Update_the_attackers_IP_address, name="Add_note_for_showing_attackers_IP")

    return

def promote_to_case_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('promote_to_case_7() called')

    phantom.promote(container=container, template="KTB Workbook")

    return

"""
Update the attackers IP address 
"""
def Update_the_attackers_IP_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Update_the_attackers_IP_address() called')
    
    Public_IP_in_white_list__NonWhitellist = json.loads(phantom.get_run_data(key='Public_IP_in_white_list:NonWhitellist'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    for ip in Public_IP_in_white_list__NonWhitellist:
        success, message, num_of_matching_row = phantom.check_list(list_name="Attacker IP address", value=ip, case_sensitive=True, substring=False)
        #phantom.debug(num_of_matching_row)
        if num_of_matching_row == 0:
            phantom.add_list(list_name="Attacker IP address", values=[ip])

    ################################################################################
    ## Custom Code End
    ################################################################################
    promote_to_case_7(container=container)

    return

def filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_4() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Run_query_to_get_observation_detail:action_result.data.*.external_ip_country_code", "in", ["TH","KH"]],
        ],
        name="filter_4:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Prepare_for_the_prompt(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Prepare_for_the_prompt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Prepare_for_the_prompt() called')
    
    template = """Here is the list of  suspected IP address(es) in Thailand / Cambodia Found:

%%
  - {0}
%%

Event link for more detail: https://phantom.csoc.krungthai.local/mission/{1}/analyst/timeline"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_4:condition_1:Run_query_to_get_observation_detail:action_result.data.*.external_ip",
        "container:id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Prepare_for_the_prompt", separator=", ")

    Persistent_External_Attack_Detected(container=container)

    return

def Persistent_External_Attack_Detected(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Persistent_External_Attack_Detected() called')
    
    # set user and message variables for phantom.prompt call
    user = "Tier2 Analyst"
    message = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "Prepare_for_the_prompt:formatted_data",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="Persistent_External_Attack_Detected", separator=", ", parameters=parameters, response_types=response_types, callback=join_set_status_set_severity_6)

    return

def decision_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_10() called')
    
    status_param = container.get('status', None)

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            [status_param, "!=", "closed"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Filter_Existing_Observations(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        Filter_SW_Alert(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
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