"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'prepareauthenbody' block
    prepareauthenbody(container=container)

    return

@phantom.playbook_block()
def prepareobjectbody(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prepareobjectbody() called')
    
    template = """api/v2/cmdb/firewall/address/Phantom {0}_32?vdom=KCS_VDOM_Ex"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="prepareobjectbody", separator=", ")

    sleep_4(container=container)

    return

@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["deleteobjectingroup:action_result.status", "!=", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        deleteobjectfromgrpfail(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    sleep_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

@phantom.playbook_block()
def preparedeleteingroupurl(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('preparedeleteingroupurl() called')
    
    template = """api/v2/cmdb/firewall/addrgrp/phantom-blacklist/member/Phantom {0}_32?vdom=KCS_VDOM_Ex"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="preparedeleteingroupurl", separator=", ")

    sleep(container=container)

    return

@phantom.playbook_block()
def deleteobjectfromgrpfail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('deleteobjectfromgrpfail() called')
    
    template = """%%
| **Source IP** | **Delete from Object Group** | **Delete Object** |    
|-----------|-----------|----------|
| {0}| {1}:{2}  |  HOLD | 
Execution Time : {3}
```
Object Name : Phantom {0}_32
Group Name : phantom-blacklist
%%"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
        "deleteobjectingroup:action_result.status",
        "deleteobjectingroup:action_result.summary.status_code",
        "cf_community_datetime_modify_1:custom_function_result.data.datetime_string",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="deleteobjectfromgrpfail", separator=", ")

    add_note_7(container=container)

    return

@phantom.playbook_block()
def add_note_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_7() called')

    formatted_data_1 = phantom.get_format_data(name='deleteobjectfromgrpfail')

    note_title = "Playbook Summary: Unblock Source IP"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    join_update_artifact_fail(container=container)

    return

@phantom.playbook_block()
def authen(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('authen() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'authen' call
    formatted_data_1 = phantom.get_format_data(name='prepareauthenbody')

    parameters = []
    
    # build parameters list for 'authen' call
    parameters.append({
        'body': formatted_data_1,
        'headers': "",
        'location': "logincheck",
        'verify_certificate': False,
    })

    phantom.act(action="post data", parameters=parameters, assets=['fortigate-aci (session-based)'], callback=cf_local_prepare_fortigate_cookie_header_1, name="authen", parent_action=action)

    return

@phantom.playbook_block()
def prepareauthenbody(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prepareauthenbody() called')
    
    template = """"""

    # parameter list for template variable replacement
    parameters = [
        "",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="prepareauthenbody", separator=", ")

    authen_2(container=container)

    return

@phantom.playbook_block()
def cf_local_prepare_fortigate_cookie_header_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_prepare_fortigate_cookie_header_1() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['authen:action_result.data.*.response_headers.Set-Cookie', 'authen:action_result.parameter.context.artifact_id'], action_results=results )

    parameters = []

    action_results_data_0_0 = [item[0] for item in action_results_data_0]

    parameters.append({
        'Cookies': action_results_data_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/prepare_fortigate_cookie_header", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/prepare_fortigate_cookie_header', parameters=parameters, name='cf_local_prepare_fortigate_cookie_header_1', callback=prepareobjectbody)

    return

@phantom.playbook_block()
def authen_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('authen_2() called')

    # collect data for 'authen_2' call
    formatted_data_1 = phantom.get_format_data(name='prepareauthenbody')

    parameters = []
    
    # build parameters list for 'authen_2' call
    parameters.append({
        'body': formatted_data_1,
        'headers': "",
        'location': "logincheck",
        'verify_certificate': False,
    })

    phantom.act(action="post data", parameters=parameters, assets=['fortigate-aci (session-based)'], callback=cf_local_prepare_fortigate_cookie_header_2, name="authen_2")

    return

@phantom.playbook_block()
def cf_local_prepare_fortigate_cookie_header_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_prepare_fortigate_cookie_header_2() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['authen_2:action_result.data.*.response_headers.Set-Cookie', 'authen_2:action_result.parameter.context.artifact_id'], action_results=results )

    parameters = []

    action_results_data_0_0 = [item[0] for item in action_results_data_0]

    parameters.append({
        'Cookies': action_results_data_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/prepare_fortigate_cookie_header", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/prepare_fortigate_cookie_header', parameters=parameters, name='cf_local_prepare_fortigate_cookie_header_2', callback=preparedeleteingroupurl)

    return

@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["deleteobject:action_result.status", "!=", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        deleteobject2grpfail(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    deleteobjectsuccess(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

@phantom.playbook_block()
def deleteobject2grpfail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('deleteobject2grpfail() called')
    
    template = """%%
| **Source IP** | **Delete from Object Group** | **Delete Object** |    
|-----------|-----------|----------|
| {0}| {1}:{2}  |  {3}:{4} | 
Execution Time : {5}
```
Object Name : Phantom {0}_32
Group Name : phantom-blacklist
%%"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
        "deleteobjectingroup:action_result.status",
        "deleteobjectingroup:action_result.summary.status_code",
        "deleteobject:action_result.status",
        "deleteobject:action_result.summary.status_code",
        "cf_community_datetime_modify_1:custom_function_result.data.datetime_string",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="deleteobject2grpfail", separator=", ")

    add_note_9(container=container)

    return

@phantom.playbook_block()
def add_note_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_9() called')

    formatted_data_1 = phantom.get_format_data(name='deleteobject2grpfail')

    note_title = "Playbook Summary: Unblock Source IP"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    join_update_artifact_fail(container=container)

    return

@phantom.playbook_block()
def deleteobjectsuccess(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('deleteobjectsuccess() called')
    
    template = """%%
| **Source IP** | **Delete from Object Group** | **Delete Object** |    
|-----------|-----------|----------|
| {0} | {1}:{2} | {3}:{4} | 
Execution Time : {5}
```
Object Name : Phantom {0}_32
Group Name : phantom-blacklist
%%"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
        "deleteobjectingroup:action_result.status",
        "deleteobjectingroup:action_result.summary.status_code",
        "deleteobjectingroup:action_result.status",
        "deleteobjectingroup:action_result.summary.status_code",
        "cf_community_datetime_modify_1:custom_function_result.data.datetime_string",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="deleteobjectsuccess", separator=", ")

    add_note_10(container=container)

    return

@phantom.playbook_block()
def add_note_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_10() called')

    formatted_data_1 = phantom.get_format_data(name='deleteobjectsuccess')

    note_title = "Playbook Summary: Unblock Source IP"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    update_artifact_success(container=container)

    return

@phantom.playbook_block()
def deleteobjectingroup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('deleteobjectingroup() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'deleteobjectingroup' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_prepare_fortigate_cookie_header_2:custom_function_result.data.header'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='preparedeleteingroupurl')

    parameters = []
    
    # build parameters list for 'deleteobjectingroup' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        parameters.append({
            'body': "",
            'headers': custom_function_results_item_1[0],
            'location': formatted_data_1,
            'verify_certificate': False,
        })

    phantom.act(action="delete data", parameters=parameters, assets=['fortigate-aci (session-based)'], callback=sleep_2, name="deleteobjectingroup", parent_action=action)

    return

@phantom.playbook_block()
def deleteobject(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('deleteobject() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'deleteobject' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_prepare_fortigate_cookie_header_1:custom_function_result.data.header'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='prepareobjectbody')

    parameters = []
    
    # build parameters list for 'deleteobject' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        parameters.append({
            'body': "",
            'headers': custom_function_results_item_1[0],
            'location': formatted_data_1,
            'verify_certificate': False,
        })

    phantom.act(action="delete data", parameters=parameters, assets=['fortigate-aci (session-based)'], callback=sleep_5, name="deleteobject", parent_action=action)

    return

@phantom.playbook_block()
def update_artifact_fail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_artifact_fail() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'update_artifact_fail' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'update_artifact_fail' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'name': "",
                'tags': "",
                'label': "",
                'cef_json': "{\"sourceAddress_UncontainResult\" : \"False\"}",
                'severity': "",
                'overwrite': False,
                'artifact_id': container_item[0],
                'artifact_json': "",
                'cef_types_json': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_fail")

    return

@phantom.playbook_block()
def join_update_artifact_fail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_update_artifact_fail() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['logout_2'], custom_function_names=['cf_community_datetime_modify_1']):
        
        # call connected block "update_artifact_fail"
        update_artifact_fail(container=container, handle=handle)
    
    return

@phantom.playbook_block()
def update_artifact_success(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_artifact_success() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'update_artifact_success' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'update_artifact_success' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'name': "",
                'tags': "",
                'label': "",
                'cef_json': "{\"sourceAddress_UncontainResult\" : \"True\"}",
                'severity': "",
                'overwrite': False,
                'artifact_id': container_item[0],
                'artifact_json': "",
                'cef_types_json': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_success")

    return

@phantom.playbook_block()
def cf_community_datetime_modify_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_datetime_modify_1() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['deleteobjectingroup:action_result.data.*.response_headers.Date', 'deleteobjectingroup:action_result.parameter.context.artifact_id'], action_results=results )
    literal_values_0 = [
        [
            7,
            "hours",
            "%a, %d %b %Y %H:%M:%S %Z",
            "%b %d,  %Y %H:%M",
        ],
    ]

    parameters = []

    for item0 in action_results_data_0:
        for item1 in literal_values_0:
            parameters.append({
                'input_datetime': item0[0],
                'amount_to_modify': item1[0],
                'modification_unit': item1[1],
                'input_format_string': item1[2],
                'output_format_string': item1[3],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/datetime_modify", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/datetime_modify', parameters=parameters, name='cf_community_datetime_modify_1', callback=decision_1)

    return

@phantom.playbook_block()
def sleep(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('sleep() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'sleep' call

    parameters = []
    
    # build parameters list for 'sleep' call
    parameters.append({
        'sleep_seconds': 5,
    })

    phantom.act(action="no op", parameters=parameters, assets=['phantom asset'], callback=deleteobjectingroup, name="sleep")

    return

@phantom.playbook_block()
def sleep_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('sleep_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'sleep_2' call

    parameters = []
    
    # build parameters list for 'sleep_2' call
    parameters.append({
        'sleep_seconds': 5,
    })

    phantom.act(action="no op", parameters=parameters, assets=['phantom asset'], callback=logout, name="sleep_2", parent_action=action)

    return

@phantom.playbook_block()
def logout(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('logout() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'logout' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_prepare_fortigate_cookie_header_2:custom_function_result.data.header'], action_results=results)

    parameters = []
    
    # build parameters list for 'logout' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        parameters.append({
            'body': "empty",
            'headers': custom_function_results_item_1[0],
            'location': "logout",
            'verify_certificate': False,
        })

    phantom.act(action="post data", parameters=parameters, assets=['fortigate-aci (session-based)'], callback=cf_community_datetime_modify_1, name="logout", parent_action=action)

    return

@phantom.playbook_block()
def sleep_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('sleep_3() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'sleep_3' call

    parameters = []
    
    # build parameters list for 'sleep_3' call
    parameters.append({
        'sleep_seconds': 5,
    })

    phantom.act(action="no op", parameters=parameters, assets=['phantom asset'], callback=authen, name="sleep_3")

    return

@phantom.playbook_block()
def sleep_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('sleep_4() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'sleep_4' call

    parameters = []
    
    # build parameters list for 'sleep_4' call
    parameters.append({
        'sleep_seconds': 5,
    })

    phantom.act(action="no op", parameters=parameters, assets=['phantom asset'], callback=deleteobject, name="sleep_4")

    return

@phantom.playbook_block()
def sleep_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('sleep_5() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'sleep_5' call

    parameters = []
    
    # build parameters list for 'sleep_5' call
    parameters.append({
        'sleep_seconds': 5,
    })

    phantom.act(action="no op", parameters=parameters, assets=['phantom asset'], callback=logout_2, name="sleep_5", parent_action=action)

    return

@phantom.playbook_block()
def logout_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('logout_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'logout_2' call

    parameters = []
    
    # build parameters list for 'logout_2' call
    parameters.append({
        'body': "empty",
        'headers': "",
        'location': "logout",
        'verify_certificate': False,
    })

    phantom.act(action="post data", parameters=parameters, assets=['fortigate-aci (session-based)'], callback=decision_2, name="logout_2", parent_action=action)

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