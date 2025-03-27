"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filtermaliciousurl' block
    filtermaliciousurl(container=container)

    return

"""
HTTP method: POST
API execute method: exec
URL: /sys/login/user
"""
@phantom.playbook_block()
def authreqtofortimanager(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('authreqtofortimanager() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'authreqtofortimanager' call
    formatted_data_1 = phantom.get_format_data(name='Bodyauthreqtofortimanager')

    parameters = []
    
    # build parameters list for 'authreqtofortimanager' call
    parameters.append({
        'body': formatted_data_1,
        'headers': "{\"Content-Type\":\"application/json\"}",
        'location': "/jsonrpc",
        'verify_certificate': False,
    })

    phantom.act(action="post data", parameters=parameters, assets=['csoc-fortimanager'], callback=getauthsessionid, name="authreqtofortimanager")

    return

@phantom.playbook_block()
def getauthsessionid(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('getauthsessionid() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "authreqtofortimanager:action_result.data.*.parsed_response_body.session",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="getauthsessionid", scope="new", separator=", ")

    reqcreateblockurl(container=container)

    return

@phantom.playbook_block()
def reqcreateblockurl(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('reqcreateblockurl() called')
    
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
        "getauthsessionid:formatted_data",
        "cf_local_strip_url_prefix_1:custom_function_result.data.processedURL.*",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="reqcreateblockurl", separator=", ")

    createblockurlentry(container=container)

    return

@phantom.playbook_block()
def createblockurlentry(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('createblockurlentry() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'createblockurlentry' call
    formatted_data_1 = phantom.get_format_data(name='reqcreateblockurl')

    parameters = []
    
    # build parameters list for 'createblockurlentry' call
    parameters.append({
        'body': formatted_data_1,
        'headers': "{\"Content-Type\":\"application/json\"}",
        'location': "/jsonrpc",
        'verify_certificate': False,
    })

    phantom.act(action="post data", parameters=parameters, assets=['csoc-fortimanager'], callback=decision_2, name="createblockurlentry")

    return

@phantom.playbook_block()
def reqinstallpolicypackage(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('reqinstallpolicypackage() called')
    
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
        "getauthsessionid:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="reqinstallpolicypackage", separator=", ")

    installpolicypackage(container=container)

    return

@phantom.playbook_block()
def installpolicypackage(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('installpolicypackage() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'installpolicypackage' call
    formatted_data_1 = phantom.get_format_data(name='reqinstallpolicypackage')

    parameters = []
    
    # build parameters list for 'installpolicypackage' call
    parameters.append({
        'body': formatted_data_1,
        'headers': "{\"Content-Type\":\"application/json\"}",
        'location': "/jsonrpc",
        'verify_certificate': False,
    })

    phantom.act(action="post data", parameters=parameters, assets=['csoc-fortimanager'], callback=no_op_1, name="installpolicypackage")

    return

@phantom.playbook_block()
def Bodyauthreqtofortimanager(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Bodyauthreqtofortimanager() called')
    
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

    phantom.format(container=container, template=template, parameters=parameters, name="Bodyauthreqtofortimanager", separator=", ")

    authreqtofortimanager(container=container)

    return

@phantom.playbook_block()
def formatoutputfornote(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('formatoutputfornote() called')
    
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
        "formatfilteredurl:formatted_data",
        "veritytaskstatus:action_result.data.*.response_headers.Date",
        "cf_community_passthrough_2:custom_function_result.data.*.item",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="formatoutputfornote", separator=", ")

    cf_local_debug_variable_1(container=container)

    return

@phantom.playbook_block()
def bodyreqchecktaskresult(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('bodyreqchecktaskresult() called')
    
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
        "getauthsessionid:formatted_data",
        "installpolicypackage:action_result.data.*.parsed_response_body.result.*.data.task",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="bodyreqchecktaskresult", separator=", ")

    veritytaskstatus(container=container)

    return

@phantom.playbook_block()
def veritytaskstatus(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('veritytaskstatus() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'veritytaskstatus' call
    formatted_data_1 = phantom.get_format_data(name='bodyreqchecktaskresult')

    parameters = []
    
    # build parameters list for 'veritytaskstatus' call
    parameters.append({
        'body': formatted_data_1,
        'headers': "{\"Content-Type\":\"application/json\"}",
        'location': "/jsonrpc",
        'verify_certificate': False,
    })

    phantom.act(action="post data", parameters=parameters, assets=['csoc-fortimanager'], callback=decisionpolicyinstallation, name="veritytaskstatus")

    return

@phantom.playbook_block()
def taskresultdone(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('taskresultdone() called')
    
    template = """Policy installation by Phantom to FortiManager has \"{0}\" with task id \"{1}\""""

    # parameter list for template variable replacement
    parameters = [
        "veritytaskstatus:action_result.data.*.parsed_response_body.result.*.data.state",
        "installpolicypackage:action_result.data.*.parsed_response_body.result.*.data.task",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="taskresultdone", separator=", ")

    addcefcontainresulttrue(container=container)

    return

@phantom.playbook_block()
def taskresulterror(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('taskresulterror() called')
    
    template = """Policy installation by Phantom to FortiManager has \"{0}\" with task id \"{1}\".

Please contact FortiManager owner (firewall.support@ktbcs.co.th) directly to further verify failure reason."""

    # parameter list for template variable replacement
    parameters = [
        "veritytaskstatus:action_result.data.*.parsed_response_body.result.*.data.state",
        "installpolicypackage:action_result.data.*.parsed_response_body.result.*.data.task",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="taskresulterror", separator=", ")

    addcefcontainresultfalse(container=container)

    return

@phantom.playbook_block()
def cf_community_passthrough_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_passthrough_2() called')
    
    formatted_data_0 = [
        [
            phantom.get_format_data(name="taskresultdone"),
            phantom.get_format_data(name="taskresulterror"),
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
    phantom.custom_function(custom_function='community/passthrough', parameters=parameters, name='cf_community_passthrough_2', callback=formatoutputfornote)

    return

@phantom.playbook_block()
def join_cf_community_passthrough_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('join_cf_community_passthrough_2() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['updateartifacttrue', 'updateartifactfalse']):
        
        # call connected block "cf_community_passthrough_2"
        cf_community_passthrough_2(container=container, handle=handle)
    
    return

@phantom.playbook_block()
def cf_local_strip_url_prefix_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_strip_url_prefix_1() called')
    
    formatted_data_0 = [
        [
            phantom.get_format_data(name="formatfilteredurl"),
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
    phantom.custom_function(custom_function='local/strip_url_prefix', parameters=parameters, name='cf_local_strip_url_prefix_1', callback=Bodyauthreqtofortimanager)

    return

@phantom.playbook_block()
def filtermaliciousurl(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filtermaliciousurl() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL_malicious", "==", True],
        ],
        name="filtermaliciousurl:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        formatfilteredurl(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def formatfilteredurl(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('formatfilteredurl() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filtermaliciousurl:condition_1:artifact:*.cef.requestURL",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="formatfilteredurl", separator=", ")

    cf_local_strip_url_prefix_1(container=container)

    return

@phantom.playbook_block()
def updateartifacttrue(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('updateartifacttrue() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'updateartifacttrue' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filtermaliciousurl:condition_1:artifact:*.id', 'filtered-data:filtermaliciousurl:condition_1:artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='addcefcontainresulttrue')

    parameters = []
    
    # build parameters list for 'updateartifacttrue' call
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

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], callback=join_cf_community_passthrough_2, name="updateartifacttrue")

    return

@phantom.playbook_block()
def addcefcontainresulttrue(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('addcefcontainresulttrue() called')
    
    template = """%%
{{
	\"requestURL_ContainResult\": \"True\"
}}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filtermaliciousurl:condition_1:artifact:*.id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="addcefcontainresulttrue", separator=", ")

    updateartifacttrue(container=container)

    return

@phantom.playbook_block()
def no_op_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('no_op_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'no_op_1' call

    parameters = []
    
    # build parameters list for 'no_op_1' call
    parameters.append({
        'sleep_seconds': 30,
    })

    phantom.act(action="no op", parameters=parameters, assets=['phantom asset'], callback=bodyreqchecktaskresult, name="no_op_1", parent_action=action)

    return

@phantom.playbook_block()
def decisionpolicyinstallation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decisionpolicyinstallation() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["veritytaskstatus:action_result.data.*.parsed_response_body.result.*.data.state", "==", "error"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        taskresulterror(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    taskresultdone(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

@phantom.playbook_block()
def addcefcontainresultfalse(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('addcefcontainresultfalse() called')
    
    template = """%%
{{
	\"requestURL_ContainResult\": \"False\"
}}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filtermaliciousurl:condition_1:artifact:*.id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="addcefcontainresultfalse", separator=", ")

    updateartifactfalse(container=container)

    return

@phantom.playbook_block()
def updateartifactfalse(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('updateartifactfalse() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'updateartifactfalse' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filtermaliciousurl:condition_1:artifact:*.id', 'filtered-data:filtermaliciousurl:condition_1:artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='addcefcontainresultfalse')

    parameters = []
    
    # build parameters list for 'updateartifactfalse' call
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

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], callback=join_cf_community_passthrough_2, name="updateartifactfalse")

    return

@phantom.playbook_block()
def cf_local_debug_variable_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_debug_variable_1() called')
    
    formatted_data_0 = [
        [
            phantom.get_format_data(name="formatoutputfornote"),
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

@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["createblockurlentry:action_result.data.*.parsed_response_body.result.*.status.message", "==", "OK"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        reqinstallpolicypackage(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    addurlentryerror(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

@phantom.playbook_block()
def addurlentryerror(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('addurlentryerror() called')
    
    template = """%%
{{
	\"requestURL_ContainResult\": \"False\"
}}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filtermaliciousurl:condition_1:artifact:*.id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="addurlentryerror", separator=", ")

    addcefcontainresultfalse2(container=container)

    return

@phantom.playbook_block()
def addcefcontainresultfalse2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('addcefcontainresultfalse2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'addcefcontainresultfalse2' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filtermaliciousurl:condition_1:artifact:*.id', 'filtered-data:filtermaliciousurl:condition_1:artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='addurlentryerror')

    parameters = []
    
    # build parameters list for 'addcefcontainresultfalse2' call
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

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], callback=formataddurlfail, name="addcefcontainresultfalse2")

    return

@phantom.playbook_block()
def formataddurlfail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('formataddurlfail() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filtermaliciousurl:condition_1:artifact:*.cef.requestURL",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="formataddurlfail", separator=", ")

    formataddurlfailNote(container=container)

    return

@phantom.playbook_block()
def formataddurlfailNote(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('formataddurlfailNote() called')
    
    template = """<b>Block URL result</b>
Fail to block URL :
{0}

Messages :
{1}

<b>Execute Time:</b> {2}"""

    # parameter list for template variable replacement
    parameters = [
        "formataddurlfail:formatted_data",
        "createblockurlentry:action_result.data.*.parsed_response_body.result.*.status.message",
        "createblockurlentry:action_result.data.*.response_headers.Date",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="formataddurlfailNote", separator=", ")

    add_note_3(container=container)

    return

@phantom.playbook_block()
def add_note_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_3() called')

    formatted_data_1 = phantom.get_format_data(name='formataddurlfailNote')

    note_title = "Playbook Summary: Block URL Result"
    note_content = formatted_data_1
    note_format = "html"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

@phantom.playbook_block()
def add_note_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_4() called')

    formatted_data_1 = phantom.get_format_data(name='formatoutputfornote')

    note_title = "Playbook Summary: Block URL Result"
    note_content = formatted_data_1
    note_format = "html"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

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