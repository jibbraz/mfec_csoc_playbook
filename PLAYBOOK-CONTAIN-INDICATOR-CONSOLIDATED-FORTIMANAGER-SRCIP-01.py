"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'BodyAuthReqToFortiManager' block
    BodyAuthReqToFortiManager(container=container)

    return

"""
HTTP method: POST
API execute method: exec
URL: /sys/login/user
"""
def AuthReqToFortiManager(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('AuthReqToFortiManager() called')

    # collect data for 'AuthReqToFortiManager' call
    formatted_data_1 = phantom.get_format_data(name='BodyAuthReqToFortiManager')

    parameters = []
    
    # build parameters list for 'AuthReqToFortiManager' call
    parameters.append({
        'body': formatted_data_1,
        'headers': "{\"Content-Type\":\"application/json\"}",
        'location': "/jsonrpc",
        'verify_certificate': False,
    })

    phantom.act(action="post data", parameters=parameters, assets=['fortimanager vayu'], callback=GetAuthSessionID, name="AuthReqToFortiManager")

    return

def GetAuthSessionID(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('GetAuthSessionID() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "AuthReqToFortiManager:action_result.data.*.parsed_response_body.session",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="GetAuthSessionID", scope="new", separator=", ")

    IPAddrData(container=container)

    return

def ReqCreateAddrObj(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ReqCreateAddrObj() called')
    
    template = """%%
{{
    \"session\": \"{0}\",
    \"id\": 1,
    \"method\": \"set\",
    \"params\": [
        {{
            \"url\": \"/pm/config/adom/root/obj/firewall/address\",
            \"data\": [
{1}
]
        }}
    ]
}}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "GetAuthSessionID:formatted_data",
        "BodyReqCreateAddrObj:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="ReqCreateAddrObj", separator=", ")

    CreateAddrObj(container=container)

    return

def CreateAddrObj(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('CreateAddrObj() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'CreateAddrObj' call
    formatted_data_1 = phantom.get_format_data(name='ReqCreateAddrObj')

    parameters = []
    
    # build parameters list for 'CreateAddrObj' call
    parameters.append({
        'body': formatted_data_1,
        'headers': "{\"Content-Type\":\"apllication/json\"}",
        'location': "/jsonrpc",
        'verify_certificate': False,
    })

    phantom.act(action="post data", parameters=parameters, assets=['fortimanager vayu'], callback=BodyReqAddAddrObjToAddrGrp, name="CreateAddrObj")

    return

def ReqAddAddrObjToAddrGrp(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ReqAddAddrObjToAddrGrp() called')
    
    template = """%%
{{
	\"session\": \"{0}\",
	\"id\": 1,
	\"method\": \"add\" ,
    \"params\": [
        {{
            \"url\": \"/pm/config/adom/root/obj/firewall/addrgrp/phantom-blacklist/member\",
            \"data\": [      
                        {1}
            ]
        }}
    ]			
}}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "GetAuthSessionID:formatted_data",
        "BodyReqAddAddrObjToAddrGrp:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="ReqAddAddrObjToAddrGrp", separator=", ")

    AddAddrObjToAddrGrp(container=container)

    return

def AddAddrObjToAddrGrp(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('AddAddrObjToAddrGrp() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'AddAddrObjToAddrGrp' call
    formatted_data_1 = phantom.get_format_data(name='ReqAddAddrObjToAddrGrp')

    parameters = []
    
    # build parameters list for 'AddAddrObjToAddrGrp' call
    parameters.append({
        'body': formatted_data_1,
        'headers': "{\"Content-Type\":\"application/json\"}",
        'location': "/jsonrpc",
        'verify_certificate': False,
    })

    phantom.act(action="post data", parameters=parameters, assets=['fortimanager vayu'], callback=ReqInstallPolicyPackage, name="AddAddrObjToAddrGrp")

    return

def ReqInstallPolicyPackage(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ReqInstallPolicyPackage() called')
    
    template = """%%
{{
	\"session\": \"{0}\",
	\"id\": 1,
	\"method\": \"exec\" ,
	\"params\": [
		{{
			\"url\": \"/securityconsole/install/package\",
            \"data\": [
                {{
                    \"adom\": \"root\",
                    \"pkg\": \"Policy-Internet\",
                    \"scope member\": [
                        {{
                            \"name\": \"BBT-DC2_DH2_R903_U33-34-3301E-FW-01\",
                            \"vdom\": \"root\"
                        }}
                    ],
                    \"flags\": \"none\"
                }}
            ]
		}}
	],
	\"verbose\": 1				
}}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "GetAuthSessionID:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="ReqInstallPolicyPackage", separator=", ")

    InstallPolicyPackage(container=container)

    return

def InstallPolicyPackage(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('InstallPolicyPackage() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'InstallPolicyPackage' call
    formatted_data_1 = phantom.get_format_data(name='ReqInstallPolicyPackage')

    parameters = []
    
    # build parameters list for 'InstallPolicyPackage' call
    parameters.append({
        'body': formatted_data_1,
        'headers': "{\"Content-Type\":\"application/json\"}",
        'location': "/jsonrpc",
        'verify_certificate': False,
    })

    phantom.act(action="post data", parameters=parameters, assets=['fortimanager vayu'], callback=cf_local_waittime_1, name="InstallPolicyPackage")

    return

def BodyReqCreateAddrObj(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('BodyReqCreateAddrObj() called')
    
    template = """%%
                {{
                    \"name\": \"Phantom {0}_32\",
                    \"subnet\": [
                        \"{0}\",\"255.255.255.255\"
                    ],
                    \"comment\": \"Create by Phantom\",
                    \"type\": 0,
                    \"associated-interface\": \"any\",
                    \"color\": 22
                }},
%%"""

    # parameter list for template variable replacement
    parameters = [
        "IPAddrData:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="BodyReqCreateAddrObj", separator=", ")

    ReqCreateAddrObj(container=container)

    return

def BodyReqAddAddrObjToAddrGrp(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('BodyReqAddAddrObjToAddrGrp() called')
    
    template = """%%
\"Phantom {0}_32\",
%%"""

    # parameter list for template variable replacement
    parameters = [
        "IPAddrData:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="BodyReqAddAddrObjToAddrGrp", separator=", ")

    ReqAddAddrObjToAddrGrp(container=container)

    return

def IPAddrData(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('IPAddrData() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="IPAddrData", separator=", ")

    BodyReqCreateAddrObj(container=container)

    return

def BodyAuthReqToFortiManager(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('BodyAuthReqToFortiManager() called')
    
    template = """%%
{{
	\"id\": {0},
	\"method\": \"exec\",
	\"params\": [
	  {{
	    \"data\": [
                    {{
		\"user\": \"phantomcsocfw\",
        \"passwd\": \"Ktbcs@123\"
	        }}
	    ],
	    \"url\": \"sys/login/user\"
      	  }}
	],
	\"session\": null,
	\"verbose\": 1
}}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="BodyAuthReqToFortiManager", separator=", ")

    AuthReqToFortiManager(container=container)

    return

def FormatOutputForNoteDone(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('FormatOutputForNoteDone() called')
    
    template = """<b>Containment result</b>

<b>Containment Source IP Address:</b> {0}
<b>Execute Time:</b> {1}

{2}"""

    # parameter list for template variable replacement
    parameters = [
        "IPAddrData:formatted_data",
        "cf_community_datetime_modify_1:custom_function_result.data.datetime_string",
        "TaskResultDone:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="FormatOutputForNoteDone", separator=", ")

    AddSummaryToNoteDone(container=container)

    return

def AddSummaryToNoteDone(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('AddSummaryToNoteDone() called')

    formatted_data_1 = phantom.get_format_data(name='FormatOutputForNoteDone')

    note_title = "Containment result by Phantom"
    note_content = formatted_data_1
    note_format = "html"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def BodyReqCheckTaskResult(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('BodyReqCheckTaskResult() called')
    
    template = """%%
{{
	\"session\": \"{0}\",
	\"id\": 1,
	\"method\": \"get\" ,
	\"params\": [
		{{
			\"url\": \"task/task/{1}\"
		}}
	],
	\"verbose\": 1				
}}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "GetAuthSessionID:formatted_data",
        "InstallPolicyPackage:action_result.data.*.parsed_response_body.result.*.data.task",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="BodyReqCheckTaskResult", separator=", ")

    VerityTaskStatus(container=container)

    return

def VerityTaskStatus(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('VerityTaskStatus() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'VerityTaskStatus' call
    formatted_data_1 = phantom.get_format_data(name='BodyReqCheckTaskResult')

    parameters = []
    
    # build parameters list for 'VerityTaskStatus' call
    parameters.append({
        'body': formatted_data_1,
        'headers': "{\"Content-Type\":\"application/json\"}",
        'location': "/jsonrpc",
        'verify_certificate': False,
    })

    phantom.act(action="post data", parameters=parameters, assets=['fortimanager vayu'], callback=cf_community_datetime_modify_1, name="VerityTaskStatus")

    return

def cf_local_waittime_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_waittime_1() called')
    
    parameters = [{}]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/waittime", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/waittime', parameters=parameters, name='cf_local_waittime_1', callback=BodyReqCheckTaskResult)

    return

def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["VerityTaskStatus:action_result.data.*.parsed_response_body.result.*.data.state", "==", "done"],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pass

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["VerityTaskStatus:action_result.data.*.parsed_response_body.result.*.data.state", "==", "error"],
        ],
        name="filter_2:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        pass

    return

def TaskResultDone(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('TaskResultDone() called')
    
    template = """Policy installation by Phantom to FortiManager has \"{0}\" with task id \"{1}\""""

    # parameter list for template variable replacement
    parameters = [
        "VerityTaskStatus:action_result.data.*.parsed_response_body.result.*.data.state",
        "InstallPolicyPackage:action_result.data.*.parsed_response_body.result.*.data.task",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="TaskResultDone", separator=", ")

    update_artifact_success(container=container)

    return

def TaskResultError(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('TaskResultError() called')
    
    template = """Policy installation by Phantom to FortiManager has \"{0}\" with task id \"{1}\".

Please contact FortiManager owner (firewall.support@ktbcs.co.th) directly to further verify failure reason."""

    # parameter list for template variable replacement
    parameters = [
        "VerityTaskStatus:action_result.data.*.parsed_response_body.result.*.data.state",
        "InstallPolicyPackage:action_result.data.*.parsed_response_body.result.*.data.task",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="TaskResultError", separator=", ")

    update_artifact_fail(container=container)

    return

def cf_community_passthrough_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_passthrough_2() called')
    
    formatted_data_0 = [
        [
            phantom.get_format_data(name="TaskResultDone"),
            phantom.get_format_data(name="TaskResultError"),
        ],
    ]

    parameters = []

    formatted_data_0_0 = [item[0] for item in formatted_data_0]
    formatted_data_0_1 = [item[1] for item in formatted_data_0]

    parameters.append({
        'input_1': formatted_data_0_0,
        'input_2': formatted_data_0_1,
        'input_3': None,
        'input_4': None,
        'input_5': None,
        'input_6': None,
        'input_7': None,
        'input_8': None,
        'input_9': None,
        'input_10': None,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/passthrough", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/passthrough', parameters=parameters, name='cf_community_passthrough_2')

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
                'cef_json': "{\"sourceAddress_ContainResult\":\"True\"}",
                'severity': "",
                'overwrite': False,
                'artifact_id': container_item[0],
                'artifact_json': "",
                'cef_types_json': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], callback=FormatOutputForNoteDone, name="update_artifact_success")

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
                'cef_json': "{\"sourceAddress_ContainResult\":\"False\"}",
                'severity': "",
                'overwrite': False,
                'artifact_id': container_item[0],
                'artifact_json': "",
                'cef_types_json': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], callback=FormatOutputForNoteError, name="update_artifact_fail")

    return

def FormatOutputForNoteError(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('FormatOutputForNoteError() called')
    
    template = """<b>Containment result</b>

<b>Containment Source IP Address:</b> {0}
<b>Execute Time:</b> {1}

{2}"""

    # parameter list for template variable replacement
    parameters = [
        "IPAddrData:formatted_data",
        "cf_community_datetime_modify_1:custom_function_result.data.datetime_string",
        "TaskResultError:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="FormatOutputForNoteError", separator=", ")

    AddSummaryToNoteError(container=container)

    return

def AddSummaryToNoteError(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('AddSummaryToNoteError() called')

    formatted_data_1 = phantom.get_format_data(name='TaskResultError')

    note_title = "Containment result by Phantom"
    note_content = formatted_data_1
    note_format = "html"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["VerityTaskStatus:action_result.data.*.parsed_response_body.result.*.data.state", "==", "done"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        TaskResultDone(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    TaskResultError(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def cf_community_datetime_modify_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_datetime_modify_1() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['VerityTaskStatus:action_result.data.*.response_headers.Date', 'VerityTaskStatus:action_result.parameter.context.artifact_id'], action_results=results )
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