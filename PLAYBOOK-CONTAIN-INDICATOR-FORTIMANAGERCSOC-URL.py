"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'FilterMaliciousURL' block
    FilterMaliciousURL(container=container)

    return

"""
HTTP method: POST
API execute method: exec
URL: /sys/login/user
"""
def AuthReqToFortiManager(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('AuthReqToFortiManager() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
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

    phantom.act(action="post data", parameters=parameters, assets=['csoc-fortimanager'], callback=GetAuthSessionID, name="AuthReqToFortiManager")

    return

def GetAuthSessionID(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('GetAuthSessionID() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "AuthReqToFortiManager:action_result.data.*.parsed_response_body.session",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="GetAuthSessionID", scope="new", separator=", ")

    ReqCreateBlockURL(container=container)

    return

def ReqCreateBlockURL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ReqCreateBlockURL() called')
    
    template = """%%
{{
    \"session\": \"{0}\",
    \"method\": \"add\",
    \"params\": [
        {{
            \"url\": \"/pm/config/adom/root/obj/webfilter/urlfilter/2/entries/\",
            \"data\":  {1}
        }}
    ]
}}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "GetAuthSessionID:formatted_data",
        "cf_local_strip_url_prefix_1:custom_function_result.data.processedURL.*",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="ReqCreateBlockURL", separator=", ")

    CreateBlockURLEntry(container=container)

    return

def CreateBlockURLEntry(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('CreateBlockURLEntry() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'CreateBlockURLEntry' call
    formatted_data_1 = phantom.get_format_data(name='ReqCreateBlockURL')

    parameters = []
    
    # build parameters list for 'CreateBlockURLEntry' call
    parameters.append({
        'body': formatted_data_1,
        'headers': "{\"Content-Type\":\"application/json\"}",
        'location': "/jsonrpc",
        'verify_certificate': False,
    })

    phantom.act(action="post data", parameters=parameters, assets=['csoc-fortimanager'], callback=decision_2, name="CreateBlockURLEntry")

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
                            \"name\": \"BBT-DC2_DH1_R903_U33-34-3301E-FW-01
\",
                            \"vdom\": \"Internet\"
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

    phantom.act(action="post data", parameters=parameters, assets=['csoc-fortimanager'], callback=no_op_1, name="InstallPolicyPackage")

    return

def BodyAuthReqToFortiManager(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('BodyAuthReqToFortiManager() called')
    
    template = """%%
{{
	\"method\": \"exec\",
	\"params\": [
	  {{
	    \"data\": [
                    {{
		\"user\": \"soar\",
        \"passwd\": \"csoc@2022\"
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

def FormatOutputForNote(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('FormatOutputForNote() called')
    
    template = """<b>Block URL result</b>

<b>Blocked URL Data </b>
{0}

URL from artifact : 
{1}

<b>Execute Time:</b> {2}
{3}"""

    # parameter list for template variable replacement
    parameters = [
        "cf_local_strip_url_prefix_1:custom_function_result.data.processedURL",
        "FormatFilteredURL:formatted_data",
        "VerityTaskStatus:action_result.data.*.response_headers.Date",
        "cf_community_passthrough_2:custom_function_result.data.*.item",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="FormatOutputForNote", separator=", ")

    cf_local_debug_variable_1(container=container)

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

    phantom.act(action="post data", parameters=parameters, assets=['csoc-fortimanager'], callback=decisionPolicyInstallation, name="VerityTaskStatus")

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

    addCEFContainResultTrue(container=container)

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

    addCEFContainResultFalse(container=container)

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
    phantom.custom_function(custom_function='community/passthrough', parameters=parameters, name='cf_community_passthrough_2', callback=FormatOutputForNote)

    return

def join_cf_community_passthrough_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_cf_community_passthrough_2() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['updateArtifactTrue', 'updateArtifactFalse']):
        
        # call connected block "cf_community_passthrough_2"
        cf_community_passthrough_2(container=container, handle=handle)
    
    return

def cf_local_strip_url_prefix_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_strip_url_prefix_1() called')
    
    formatted_data_0 = [
        [
            phantom.get_format_data(name="FormatFilteredURL"),
        ],
    ]

    parameters = []

    for item0 in formatted_data_0:
        parameters.append({
            'requestURLs': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/strip_url_prefix", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/strip_url_prefix', parameters=parameters, name='cf_local_strip_url_prefix_1', callback=BodyAuthReqToFortiManager)

    return

def FilterMaliciousURL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('FilterMaliciousURL() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL_malicious", "==", True],
        ],
        name="FilterMaliciousURL:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        FormatFilteredURL(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def FormatFilteredURL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('FormatFilteredURL() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:FilterMaliciousURL:condition_1:artifact:*.cef.requestURL",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="FormatFilteredURL", separator=", ")

    cf_local_strip_url_prefix_1(container=container)

    return

def updateArtifactTrue(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('updateArtifactTrue() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'updateArtifactTrue' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:FilterMaliciousURL:condition_1:artifact:*.id', 'filtered-data:FilterMaliciousURL:condition_1:artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='addCEFContainResultTrue')

    parameters = []
    
    # build parameters list for 'updateArtifactTrue' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'name': "",
                'tags': "",
                'label': "",
                'cef_json': formatted_data_1,
                'severity': "",
                'overwrite': False,
                'artifact_id': filtered_artifacts_item_1[0],
                'artifact_json': "",
                'cef_types_json': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], callback=join_cf_community_passthrough_2, name="updateArtifactTrue")

    return

def addCEFContainResultTrue(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('addCEFContainResultTrue() called')
    
    template = """%%
{{
	\"requestURL_ContainResult\": \"True\"
}}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:FilterMaliciousURL:condition_1:artifact:*.id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="addCEFContainResultTrue", separator=", ")

    updateArtifactTrue(container=container)

    return

def no_op_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('no_op_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'no_op_1' call

    parameters = []
    
    # build parameters list for 'no_op_1' call
    parameters.append({
        'sleep_seconds': 30,
    })

    phantom.act(action="no op", parameters=parameters, assets=['phantom asset'], callback=BodyReqCheckTaskResult, name="no_op_1", parent_action=action)

    return

def decisionPolicyInstallation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decisionPolicyInstallation() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["VerityTaskStatus:action_result.data.*.parsed_response_body.result.*.data.state", "==", "error"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        TaskResultError(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    TaskResultDone(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def addCEFContainResultFalse(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('addCEFContainResultFalse() called')
    
    template = """%%
{{
	\"requestURL_ContainResult\": \"False\"
}}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:FilterMaliciousURL:condition_1:artifact:*.id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="addCEFContainResultFalse", separator=", ")

    updateArtifactFalse(container=container)

    return

def updateArtifactFalse(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('updateArtifactFalse() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'updateArtifactFalse' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:FilterMaliciousURL:condition_1:artifact:*.id', 'filtered-data:FilterMaliciousURL:condition_1:artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='addCEFContainResultFalse')

    parameters = []
    
    # build parameters list for 'updateArtifactFalse' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'name': "",
                'tags': "",
                'label': "",
                'cef_json': formatted_data_1,
                'severity': "",
                'overwrite': "",
                'artifact_id': filtered_artifacts_item_1[0],
                'artifact_json': "",
                'cef_types_json': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], callback=join_cf_community_passthrough_2, name="updateArtifactFalse")

    return

def cf_local_debug_variable_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_debug_variable_1() called')
    
    formatted_data_0 = [
        [
            phantom.get_format_data(name="FormatOutputForNote"),
        ],
    ]

    parameters = []

    for item0 in formatted_data_0:
        parameters.append({
            'var1': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/debug_variable", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/debug_variable', parameters=parameters, name='cf_local_debug_variable_1', callback=add_note_4)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["CreateBlockURLEntry:action_result.data.*.parsed_response_body.result.*.status.message", "==", "OK"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        ReqInstallPolicyPackage(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    addURLEntryError(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def addURLEntryError(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('addURLEntryError() called')
    
    template = """%%
{{
	\"requestURL_ContainResult\": \"False\"
}}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:FilterMaliciousURL:condition_1:artifact:*.id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="addURLEntryError", separator=", ")

    addCEFContainResultFalse2(container=container)

    return

def addCEFContainResultFalse2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('addCEFContainResultFalse2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'addCEFContainResultFalse2' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:FilterMaliciousURL:condition_1:artifact:*.id', 'filtered-data:FilterMaliciousURL:condition_1:artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='addURLEntryError')

    parameters = []
    
    # build parameters list for 'addCEFContainResultFalse2' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'name': "",
                'tags': "",
                'label': "",
                'cef_json': formatted_data_1,
                'severity': "",
                'overwrite': "",
                'artifact_id': filtered_artifacts_item_1[0],
                'artifact_json': "",
                'cef_types_json': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], callback=formatAddURLFail, name="addCEFContainResultFalse2")

    return

def formatAddURLFail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('formatAddURLFail() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:FilterMaliciousURL:condition_1:artifact:*.cef.requestURL",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="formatAddURLFail", separator=", ")

    formatAddURLFailNote(container=container)

    return

def formatAddURLFailNote(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('formatAddURLFailNote() called')
    
    template = """<b>Block URL result</b>
Fail to block URL :
{0}

Messages :
{1}

<b>Execute Time:</b> {2}"""

    # parameter list for template variable replacement
    parameters = [
        "formatAddURLFail:formatted_data",
        "CreateBlockURLEntry:action_result.data.*.parsed_response_body.result.*.status.message",
        "CreateBlockURLEntry:action_result.data.*.response_headers.Date",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="formatAddURLFailNote", separator=", ")

    add_note_3(container=container)

    return

def add_note_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_3() called')

    formatted_data_1 = phantom.get_format_data(name='formatAddURLFailNote')

    note_title = "Playbook Summary: Block URL Result"
    note_content = formatted_data_1
    note_format = "html"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def add_note_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_4() called')

    formatted_data_1 = phantom.get_format_data(name='FormatOutputForNote')

    note_title = "Playbook Summary: Block URL Result"
    note_content = formatted_data_1
    note_format = "html"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

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