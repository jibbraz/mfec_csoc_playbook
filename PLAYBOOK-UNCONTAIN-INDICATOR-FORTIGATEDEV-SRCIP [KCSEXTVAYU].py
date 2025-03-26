"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'prepareAuthenBody' block
    prepareAuthenBody(container=container)

    return

def prepareObjectBody(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prepareObjectBody() called')
    
    template = """api/v2/cmdb/firewall/address/Phantom {0}_32?vdom=KCSEXTVAYU"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="prepareObjectBody", separator=", ")

    deleteObject(container=container)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["deleteObjectInGroup:action_result.status", "!=", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        logout(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    sleep_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def prepareDeleteInGroupURL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prepareDeleteInGroupURL() called')
    
    template = """api/v2/cmdb/firewall/addrgrp/phantom-blacklist/member/Phantom {0}_32?vdom=KCSEXTVAYU"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="prepareDeleteInGroupURL", separator=", ")

    deleteObjectInGroup(container=container)

    return

def deleteObjectFromGrpFail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('deleteObjectFromGrpFail() called')
    
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
        "deleteObjectInGroup:action_result.status",
        "deleteObjectInGroup:action_result.summary.status_code",
        "cf_community_datetime_modify_1:custom_function_result.data.datetime_string",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="deleteObjectFromGrpFail", separator=", ")

    add_note_7(container=container)

    return

def add_note_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_7() called')

    formatted_data_1 = phantom.get_format_data(name='deleteObjectFromGrpFail')

    note_title = "Playbook Summary: Unblock Source IP"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    container = phantom.get_container(container.get('id', None))
    update_artifact_fail(container=container)

    return

def prepareAuthenBody(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prepareAuthenBody() called')
    
    template = """username=phantomcsocfw&secretkey=Ktbcs@123&ajax=1"""

    # parameter list for template variable replacement
    parameters = [
        "",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="prepareAuthenBody", separator=", ")

    authen_2(container=container)

    return

def authen_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('authen_2() called')

    # collect data for 'authen_2' call
    formatted_data_1 = phantom.get_format_data(name='prepareAuthenBody')

    parameters = []
    
    # build parameters list for 'authen_2' call
    parameters.append({
        'body': formatted_data_1,
        'headers': "",
        'location': "logincheck",
        'verify_certificate': False,
    })

    phantom.act(action="post data", parameters=parameters, assets=['fortigate-dev (session-based)'], callback=cf_local_prepare_Fortigate_Cookie_Header_v7210_1, name="authen_2")

    return

def cf_local_prepare_Fortigate_Cookie_Header_v7210_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_prepare_Fortigate_Cookie_Header_v7210_1() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['authen_2:action_result.data.*.response_headers.set-cookie', 'authen_2:action_result.parameter.context.artifact_id'], action_results=results )

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

    # call custom function "local/prepare_Fortigate_Cookie_Header_v7210", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/prepare_Fortigate_Cookie_Header_v7210', parameters=parameters, name='cf_local_prepare_Fortigate_Cookie_Header_v7210_1', callback=cf_community_datetime_modify_1)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["deleteObject:action_result.status", "!=", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        deleteObject2GrpFail(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    deleteObjectSuccess(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def deleteObject2GrpFail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('deleteObject2GrpFail() called')
    
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
        "deleteObjectInGroup:action_result.status",
        "deleteObjectInGroup:action_result.summary.status_code",
        "deleteObject:action_result.status",
        "deleteObject:action_result.summary.status_code",
        "cf_community_datetime_modify_1:custom_function_result.data.datetime_string",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="deleteObject2GrpFail", separator=", ")

    add_note_9(container=container)

    return

def add_note_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_9() called')

    formatted_data_1 = phantom.get_format_data(name='deleteObject2GrpFail')

    note_title = "Playbook Summary: Unblock Source IP"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    container = phantom.get_container(container.get('id', None))
    update_artifact_fail_2(container=container)

    return

def deleteObjectSuccess(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('deleteObjectSuccess() called')
    
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
        "deleteObjectInGroup:action_result.status",
        "deleteObjectInGroup:action_result.summary.status_code",
        "deleteObjectInGroup:action_result.status",
        "deleteObjectInGroup:action_result.summary.status_code",
        "cf_community_datetime_modify_1:custom_function_result.data.datetime_string",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="deleteObjectSuccess", separator=", ")

    add_note_10(container=container)

    return

def add_note_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_10() called')

    formatted_data_1 = phantom.get_format_data(name='deleteObjectSuccess')

    note_title = "Playbook Summary: Unblock Source IP"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    container = phantom.get_container(container.get('id', None))
    update_artifact_success(container=container)

    return

def deleteObjectInGroup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('deleteObjectInGroup() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'deleteObjectInGroup' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_prepare_Fortigate_Cookie_Header_v7210_1:custom_function_result.data.header'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='prepareDeleteInGroupURL')

    parameters = []
    
    # build parameters list for 'deleteObjectInGroup' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        parameters.append({
            'body': "",
            'headers': custom_function_results_item_1[0],
            'location': formatted_data_1,
            'verify_certificate': False,
        })

    phantom.act(action="delete data", parameters=parameters, assets=['fortigate-dev (session-based)'], callback=decision_1, name="deleteObjectInGroup")

    return

def deleteObject(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('deleteObject() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'deleteObject' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_prepare_Fortigate_Cookie_Header_v7210_1:custom_function_result.data.header'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='prepareObjectBody')

    parameters = []
    
    # build parameters list for 'deleteObject' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        parameters.append({
            'body': "",
            'headers': custom_function_results_item_1[0],
            'location': formatted_data_1,
            'verify_certificate': False,
        })

    phantom.act(action="delete data", parameters=parameters, assets=['fortigate-dev (session-based)'], callback=sleep_5, name="deleteObject")

    return

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

def cf_community_datetime_modify_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_datetime_modify_1() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['authen_2:action_result.data.*.response_headers.Date', 'authen_2:action_result.parameter.context.artifact_id'], action_results=results )
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
    phantom.custom_function(custom_function='community/datetime_modify', parameters=parameters, name='cf_community_datetime_modify_1', callback=sleep)

    return

def sleep(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('sleep() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'sleep' call

    parameters = []
    
    # build parameters list for 'sleep' call
    parameters.append({
        'sleep_seconds': 5,
    })

    phantom.act(action="no op", parameters=parameters, assets=['phantom asset'], callback=prepareDeleteInGroupURL, name="sleep")

    return

def sleep_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('sleep_3() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'sleep_3' call

    parameters = []
    
    # build parameters list for 'sleep_3' call
    parameters.append({
        'sleep_seconds': 5,
    })

    phantom.act(action="no op", parameters=parameters, assets=['phantom asset'], callback=prepareObjectBody, name="sleep_3")

    return

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

    phantom.act(action="post data", parameters=parameters, assets=['fortigate-dev (session-based)'], callback=decision_2, name="logout_2", parent_action=action)

    return

def logout(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('logout() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'logout' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_prepare_Fortigate_Cookie_Header_v7210_1:custom_function_result.data.header'], action_results=results)

    parameters = []
    
    # build parameters list for 'logout' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        parameters.append({
            'body': "empty",
            'headers': custom_function_results_item_1[0],
            'location': "logout",
            'verify_certificate': False,
        })

    phantom.act(action="post data", parameters=parameters, assets=['fortigate-dev (session-based)'], callback=deleteObjectFromGrpFail, name="logout")

    return

def update_artifact_fail_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_artifact_fail_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'update_artifact_fail_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='deleteObject2GrpFail')

    parameters = []
    
    # build parameters list for 'update_artifact_fail_2' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'name': "",
                'tags': "",
                'label': "",
                'cef_json': formatted_data_1,
                'severity': "",
                'overwrite': False,
                'artifact_id': container_item[0],
                'artifact_json': "",
                'cef_types_json': "{\"sourceAddress_UncontainResult\" : \"False\"}",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_artifact_fail_2")

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