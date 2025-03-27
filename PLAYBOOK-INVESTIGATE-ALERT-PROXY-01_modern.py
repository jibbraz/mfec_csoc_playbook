"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'decision_5' block
    decision_5(container=container)

    return

@phantom.playbook_block()
def playbook_local_PLAYBOOK_ENRICH_INDICATOR_ALL_01_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PLAYBOOK_ENRICH_INDICATOR_ALL_01_1() called')
    
    # call playbook "local/playbook-enrich-indicator-all-01", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/playbook-enrich-indicator-all-01", container=container, name="playbook_local_PLAYBOOK_ENRICH_INDICATOR_ALL_01_1", callback=join_set_status_1)

    return

@phantom.playbook_block()
def playbook_local_ktb_triage_playbook_for_generic_label_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_ktb_triage_playbook_for_generic_label_1() called')
    
    # call playbook "local/KTB Triage Playbook for Generic Label", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/KTB Triage Playbook for Generic Label", container=container, name="playbook_local_ktb_triage_playbook_for_generic_label_1", callback=decision_7)

    return

@phantom.playbook_block()
def set_status_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_1() called')

    phantom.set_status(container=container, status="Open")
    filter_1(container=container)

    return

@phantom.playbook_block()
def join_set_status_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_set_status_1() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(playbook_names=['playbook_local_PLAYBOOK_ENRICH_INDICATOR_ALL_01_1', 'playbook_local_PLAYBOOK_ENRICH_INDICATOR_VIRUSTOTAL_THREATSTREAM_01_2']):
        
        # call connected block "set_status_1"
        set_status_1(container=container, handle=handle)
    
    return

@phantom.playbook_block()
def update_proxy_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_proxy_url() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.cef.requestURL', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]
    container_item_1 = [item[1] for item in container_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    test_url = container_item_1[0]
    #
    if test_url.split(":")[0] != "http" and test_url.split(":",1)[0] != "https":
        test_url = "http:" + test_url.split(":",1)[1]
    
        parameters = []
        cef_json = {"requestURL" : test_url }
                    
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
        
        phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_proxy_url")

    #####################################

    test_url = container_item_0[0]

    ################################################################################
    ## Custom Code End
    ################################################################################
    playbook_local_ktb_triage_playbook_for_generic_label_1(container=container)

    return

@phantom.playbook_block()
def join_update_proxy_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_update_proxy_url() called')

    # no callbacks to check, call connected block "update_proxy_url"
    phantom.save_run_data(key='join_update_proxy_url_called', value='update_proxy_url', auto=True)

    update_proxy_url(container=container, handle=handle)
    
    return

@phantom.playbook_block()
def extract_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('extract_domain() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.cef.requestURL', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]
    container_item_1 = [item[1] for item in container_data]

    extract_domain__destinationDomain = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    requestDomain = []
    destinationDomain = []
    #phantom.debug(container_data)
    #phantom.debug(container_item_0)
    #phantom.debug(container_item_1)
    for artifact in container_data:
        artifact_id = artifact[0]
        requestURL = artifact[1]
        phantom.debug(requestURL)
        requestDomain.append([artifact_id,requestURL.split("//")[1].split("/")[0]])
    
    phantom.debug(requestDomain)
    parameters = []
    
    for item in requestDomain:
        parameters.append({
        'artifact_id': item[0],
        'cef_json': {"destinationDnsDomain" : item[1]},
        })
        destinationDomain.append(item[1])
    
    phantom.debug(destinationDomain)
    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_destinationDnsDomain")
    extract_domain__destinationDomain = destinationDomain
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='extract_domain:destinationDomain', value=json.dumps(extract_domain__destinationDomain))
    join_update_proxy_url(container=container)

    return

@phantom.playbook_block()
def playbook_local_PLAYBOOK_ENRICH_INDICATOR_VIRUSTOTAL_THREATSTREAM_01_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PLAYBOOK_ENRICH_INDICATOR_VIRUSTOTAL_THREATSTREAM_01_2() called')
    
    # call playbook "local/playbook-enrich-indicator-virustotal-threatstream-01", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/playbook-enrich-indicator-virustotal-threatstream-01", container=container, name="playbook_local_PLAYBOOK_ENRICH_INDICATOR_VIRUSTOTAL_THREATSTREAM_01_2", callback=join_set_status_1)

    return

@phantom.playbook_block()
def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_5() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""],
            ["artifact:*.cef.destinationDnsDomain", "==", ""],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        extract_domain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        join_update_proxy_url(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.requestURL_malicious", "==", True],
            ["artifact:*.cef.requestURL", "not in", "custom_list:noContainUrl"],
        ],
        logical_operator='and',
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        transform_url_to_send_email(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.requestURL_malicious", "==", True],
            ["artifact:*.cef.requestURL", "in", "custom_list:noContainUrl"],
        ],
        logical_operator='and',
        name="filter_1:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        format_url_in_no_contain_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

@phantom.playbook_block()
def format_contain_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_contain_url() called')
    
    template = """Dear Approver,
   This is an automated message to inform you of the containment approval request in phantom.
   According to the case and details below, please attend Phantom to approve the containment accordingly.

====================
[Case ID]: {0}
[Case Name]: {1}
[IOC to contain]: {2}
[Security device to contain]: Fortigate URL
[Link to Phantom Event]: https://phantom.csoc.krungthai.local/mission/{0}
[Case details]: {3}
====================

Please do not respond to this message."""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
        "container:name",
        "transform_url_to_send_email:custom_function:transformURL",
        "filtered-data:filter_1:condition_1:artifact:*.name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_contain_url", separator=", ")

    send_email_2(container=container)

    return

@phantom.playbook_block()
def send_email_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_email_2() called')

    # collect data for 'send_email_2' call
    formatted_data_1 = phantom.get_format_data(name='format_contain_url')

    parameters = []
    
    # build parameters list for 'send_email_2' call
    parameters.append({
        'cc': "",
        'to': "security-infra@ktbcs.co.th",
        'bcc': "",
        'body': formatted_data_1,
        'from': "no-reply-phantom@ktbcs.co.th",
        'headers': "",
        'subject': "SOAR - Containment Approval Needed - Notification",
        'attachments': "",
    })

    phantom.act(action="send email", parameters=parameters, assets=['smtp asset'], callback=contain_url_confirmation, name="send_email_2")

    return

@phantom.playbook_block()
def contain_url_confirmation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('contain_url_confirmation() called')
    
    # set user and message variables for phantom.prompt call
    user = "Tier2 Analyst"
    message = """***WARNING*** 
Do you want to proceed with containment for Request URL = {0}?

Event Info:
Case ID: {1}
Case Name: {2}

Send from playbook: PLAYBOOK-INVESTIGATE-ALERT-PROXY-01"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:artifact:*.cef.requestURL",
        "container:id",
        "container:name",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="contain_url_confirmation", separator=", ", parameters=parameters, response_types=response_types, callback=decision_6)

    return

@phantom.playbook_block()
def decision_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_6() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["contain_url_confirmation:action_result.status", "==", "success"],
            ["contain_url_confirmation:action_result.summary.responses.0", "==", "Yes"],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEKTBCS_URL_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["contain_url_confirmation:action_result.status", "==", "success"],
            ["contain_url_confirmation:action_result.summary.responses.0", "==", "No"],
        ],
        logical_operator='and')

    # call connected blocks if condition 2 matched
    if matched:
        format_prompt_decline(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 3
    format_prompt_timeout(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

@phantom.playbook_block()
def format_prompt_decline(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_prompt_decline() called')
    
    template = """The Request URL {0} is malicious, but approver decide to not contain."""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:artifact:*.cef.requestURL",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_prompt_decline", separator=", ")

    set_status_add_note_3(container=container)

    return

@phantom.playbook_block()
def format_prompt_timeout(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_prompt_timeout() called')
    
    template = """The Request URL {0} is malicious, but no response from approver.

Please further analyse."""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:artifact:*.cef.requestURL",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_prompt_timeout", separator=", ")

    set_status_add_note_2(container=container)

    return

@phantom.playbook_block()
def set_status_add_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_add_note_2() called')

    formatted_data_1 = phantom.get_format_data(name='format_prompt_timeout')

    phantom.set_status(container=container, status="In progress")

    note_title = ""
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    cf_local_set_last_automated_action_2(container=container)

    return

@phantom.playbook_block()
def set_status_add_note_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_add_note_3() called')

    formatted_data_1 = phantom.get_format_data(name='format_prompt_decline')

    phantom.set_status(container=container, status="In progress")

    note_title = ""
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    cf_local_set_last_automated_action_1(container=container)

    return

@phantom.playbook_block()
def cf_local_set_last_automated_action_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_set_last_automated_action_1() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "Containment Approval Rejected",
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

    # call custom function "local/set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_last_automated_action', parameters=parameters, name='cf_local_set_last_automated_action_1')

    return

@phantom.playbook_block()
def cf_local_set_last_automated_action_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_set_last_automated_action_2() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "Request for Containment",
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

    # call custom function "local/set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_last_automated_action', parameters=parameters, name='cf_local_set_last_automated_action_2')

    return

@phantom.playbook_block()
def format_url_in_no_contain_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_url_in_no_contain_list() called')
    
    template = """Follow URL found malicious and in 'NO CONTAIL URL' list

%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_2:artifact:*.cef.requestURL",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_url_in_no_contain_list", separator=", ")

    note_url_in_no_contain_list(container=container)

    return

@phantom.playbook_block()
def note_url_in_no_contain_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('note_url_in_no_contain_list() called')

    formatted_data_1 = phantom.get_format_data(name='format_url_in_no_contain_list')

    note_title = ""
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

@phantom.playbook_block()
def transform_url_to_send_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('transform_url_to_send_email() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.requestURL'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    transform_url_to_send_email__transformURL = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    transformURL = []
    for url in filtered_artifacts_item_1_0:
        transformURL.append(url.replace(".","[dot]"))
    phantom.debug("transformURL = ")
    phantom.debug(transformURL)
    transform_url_to_send_email__transformURL = transformURL[0]

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='transform_url_to_send_email:transformURL', value=json.dumps(transform_url_to_send_email__transformURL))
    format_14(container=container)

    return

@phantom.playbook_block()
def format_14(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_14() called')
    
    template = """This is an automated message to inform you the IOC detected in incident. (No automatic containment is executed by the playbook). 

====================
[Case ID]: {0}
[Case Name]: {1}
[IOC to contain]: {2}
===================="""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
        "container:name",
        "transform_url_to_send_email:custom_function:transformURL",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_14", separator=", ")

    add_note_5(container=container)
    cf_local_add_ioc_containment_list_1(container=container)

    return

@phantom.playbook_block()
def add_note_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_5() called')

    formatted_data_1 = phantom.get_format_data(name='format_14')

    note_title = ""
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    join_cf_local_set_last_automated_action_3(container=container)

    return

@phantom.playbook_block()
def cf_local_set_last_automated_action_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_set_last_automated_action_3() called')
    
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

    # call custom function "local/set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_last_automated_action', parameters=parameters, name='cf_local_set_last_automated_action_3')

    return

@phantom.playbook_block()
def join_cf_local_set_last_automated_action_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_cf_local_set_last_automated_action_3() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(playbook_names=['playbook_local_PLAYBOOK_ENRICH_INDICATOR_ALL_01_1', 'playbook_local_PLAYBOOK_ENRICH_INDICATOR_VIRUSTOTAL_THREATSTREAM_01_2'], custom_function_names=['cf_local_add_ioc_containment_list_1']):
        
        # call connected block "cf_local_set_last_automated_action_3"
        cf_local_set_last_automated_action_3(container=container, handle=handle)
    
    return

@phantom.playbook_block()
def cf_local_add_ioc_containment_list_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_add_ioc_containment_list_1() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    legacy_custom_function_result_0 = [
        [
            json.loads(phantom.get_run_data(key="transform_url_to_send_email:transformURL")),
        ],
    ]
    literal_values_0 = [
        [
            "url",
        ],
    ]

    parameters = []

    for item0 in literal_values_0:
        for item1 in legacy_custom_function_result_0:
            for item2 in container_property_0:
                parameters.append({
                    'IOC_Type': item0[0],
                    'input_IOC': item1[0],
                    'Container_id': item2[0],
                })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/add_ioc_containment_list", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/add_ioc_containment_list', parameters=parameters, name='cf_local_add_ioc_containment_list_1', callback=join_cf_local_set_last_automated_action_3)

    return

@phantom.playbook_block()
def decision_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_7() called')
    
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
        playbook_local_PLAYBOOK_ENRICH_INDICATOR_ALL_01_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        playbook_local_PLAYBOOK_ENRICH_INDICATOR_VIRUSTOTAL_THREATSTREAM_01_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2

    return

@phantom.playbook_block()
def playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEKTBCS_URL_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEKTBCS_URL_1() called')
    
    # call playbook "local/playbook-contain-indicator-fortigatektbcs-url", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/playbook-contain-indicator-fortigatektbcs-url", container=container, name="playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEKTBCS_URL_1", callback=fmt_block_url_successful)

    return

@phantom.playbook_block()
def fmt_block_url_successful(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('fmt_block_url_successful() called')
    
    template = """This is an automated message to inform you of the containment is success.

Case Name: {0}
Contained URL: {1}
Contain Status: {2}

Please do not respond to this message."""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "artifact:*.cef.requestURL",
        "artifact:*.cef.requestURL_ContainResult",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="fmt_block_url_successful", separator=", ")

    add_note_set_status_promote_to_case_6(container=container)

    return

@phantom.playbook_block()
def add_note_set_status_promote_to_case_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_set_status_promote_to_case_6() called')

    formatted_data_1 = phantom.get_format_data(name='fmt_block_url_successful')

    note_title = ""
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    phantom.set_status(container=container, status="Resolved")

    phantom.promote(container=container, template="KTB Workbook")
    cf_local_set_last_automated_action_4(container=container)

    return

@phantom.playbook_block()
def cf_local_set_last_automated_action_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_set_last_automated_action_4() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "Resolved",
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

    # call custom function "local/set_last_automated_action", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/set_last_automated_action', parameters=parameters, name='cf_local_set_last_automated_action_4')

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