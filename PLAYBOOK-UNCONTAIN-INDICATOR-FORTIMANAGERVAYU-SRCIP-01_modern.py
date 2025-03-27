"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Bodyauthreqtofortimanager' block
    Bodyauthreqtofortimanager(container=container)

    return

"""
HTTP method: POST
API execute method: exec
URL: /sys/login/user
"""
@phantom.playbook_block()
def authreqtofortimanager(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('authreqtofortimanager() called')

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

    phantom.act(action="post data", parameters=parameters, assets=['fortimanager vayu'], callback=getauthsessionid, name="authreqtofortimanager")

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

    ipaddrdata(container=container)

    return

@phantom.playbook_block()
def reqdeladdrobj(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('reqdeladdrobj() called')
    
    template = """%%
{{
    \"session\": \"{0}\",
    \"id\": 1,
    \"method\": \"delete\",
    \"params\": [
        {{
            \"url\": \"/pm/config/adom/root/obj/firewall/address/Phantom {1}_32\"
        }}
    ]
}}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "getauthsessionid:formatted_data",
        "ipaddrdata:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="reqdeladdrobj", separator=", ")

    deleteaddrobj(container=container)

    return

@phantom.playbook_block()
def deleteaddrobj(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('deleteaddrobj() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'deleteaddrobj' call
    formatted_data_1 = phantom.get_format_data(name='reqdeladdrobj')

    parameters = []
    
    # build parameters list for 'deleteaddrobj' call
    parameters.append({
        'body': formatted_data_1,
        'headers': "{\"Content-Type\":\"apllication/json\"}",
        'location': "/jsonrpc",
        'verify_certificate': False,
    })

    phantom.act(action="post data", parameters=parameters, assets=['fortimanager vayu'], callback=reqinstallpolicypackage, name="deleteaddrobj")

    return

@phantom.playbook_block()
def reqdeladdrobjfromaddrgrp(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('reqdeladdrobjfromaddrgrp() called')
    
    template = """%%
{{
	\"session\": \"{0}\",
	\"id\": 1,
	\"method\": \"delete\" ,
    \"params\": [
        {{
            \"url\": \"/pm/config/adom/root/obj/firewall/addrgrp/phantom-blacklist/member\",
            \"data\": [      
                        \"Phantom {1}_32\"
            ]
        }}
    ]			
}}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "getauthsessionid:formatted_data",
        "ipaddrdata:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="reqdeladdrobjfromaddrgrp", separator=", ")

    deladdrobjfromaddrgrp(container=container)

    return

@phantom.playbook_block()
def deladdrobjfromaddrgrp(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('deladdrobjfromaddrgrp() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'deladdrobjfromaddrgrp' call
    formatted_data_1 = phantom.get_format_data(name='reqdeladdrobjfromaddrgrp')

    parameters = []
    
    # build parameters list for 'deladdrobjfromaddrgrp' call
    parameters.append({
        'body': formatted_data_1,
        'headers': "{\"Content-Type\":\"application/json\"}",
        'location': "/jsonrpc",
        'verify_certificate': False,
    })

    phantom.act(action="post data", parameters=parameters, assets=['fortimanager vayu'], callback=reqdeladdrobj, name="deladdrobjfromaddrgrp")

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

    phantom.act(action="post data", parameters=parameters, assets=['fortimanager vayu'], callback=cf_local_waittime_1, name="installpolicypackage")

    return

@phantom.playbook_block()
def bodyreqdeladdrobjfromaddrgrp(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('bodyreqdeladdrobjfromaddrgrp() called')
    
    template = """%%
\"Phantom {0}_32\",
%%"""

    # parameter list for template variable replacement
    parameters = [
        "ipaddrdata:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="bodyreqdeladdrobjfromaddrgrp", separator=", ")

    reqdeladdrobjfromaddrgrp(container=container)

    return

@phantom.playbook_block()
def ipaddrdata(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ipaddrdata() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="ipaddrdata", separator=", ")

    bodyreqdeladdrobjfromaddrgrp(container=container)

    return

@phantom.playbook_block()
def Bodyauthreqtofortimanager(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Bodyauthreqtofortimanager() called')
    
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

    phantom.format(container=container, template=template, parameters=parameters, name="Bodyauthreqtofortimanager", separator=", ")

    authreqtofortimanager(container=container)

    return

@phantom.playbook_block()
def formatoutputfornotedone(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('formatoutputfornotedone() called')
    
    template = """<b>Uncontainment result</b>

<b>Uncontainment Source IP Address:</b> {0}
<b>Execute Time:</b> {1}

{2}"""

    # parameter list for template variable replacement
    parameters = [
        "ipaddrdata:formatted_data",
        "cf_community_datetime_modify_1:custom_function_result.data.datetime_string",
        "taskresultdone:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="formatoutputfornotedone", separator=", ")

    addsummarytonotedone(container=container)

    return

@phantom.playbook_block()
def addsummarytonotedone(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('addsummarytonotedone() called')

    formatted_data_1 = phantom.get_format_data(name='formatoutputfornotedone')

    note_title = "Uncontainment result by Phantom"
    note_content = formatted_data_1
    note_format = "html"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

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

    phantom.act(action="post data", parameters=parameters, assets=['fortimanager vayu'], callback=cf_community_datetime_modify_1, name="veritytaskstatus")

    return

@phantom.playbook_block()
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
    phantom.custom_function(custom_function='local/waittime', parameters=parameters, name='cf_local_waittime_1', callback=bodyreqchecktaskresult)

    return

@phantom.playbook_block()
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["veritytaskstatus:action_result.data.*.parsed_response_body.result.*.data.state", "==", "done"],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pass

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["veritytaskstatus:action_result.data.*.parsed_response_body.result.*.data.state", "==", "error"],
        ],
        name="filter_2:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        pass

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

    update_artifact_success(container=container)

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

    update_artifact_fail(container=container)

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
    phantom.custom_function(custom_function='community/passthrough', parameters=parameters, name='cf_community_passthrough_2')

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
                'cef_json': "{\"sourceAddress_UncontainResult\":\"True\"}",
                'severity': "",
                'overwrite': False,
                'artifact_id': container_item[0],
                'artifact_json': "",
                'cef_types_json': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], callback=formatoutputfornotedone, name="update_artifact_success")

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

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], callback=formatoutputfornoteerror, name="update_artifact_fail")

    return

@phantom.playbook_block()
def formatoutputfornoteerror(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('formatoutputfornoteerror() called')
    
    template = """<b>Uncontainment result</b>

<b>Uncontainment Source IP Address:</b> {0}
<b>Execute Time:</b> {1}

{2}"""

    # parameter list for template variable replacement
    parameters = [
        "ipaddrdata:formatted_data",
        "cf_community_datetime_modify_1:custom_function_result.data.datetime_string",
        "taskresulterror:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="formatoutputfornoteerror", separator=", ")

    addsummarytonoteerror(container=container)

    return

@phantom.playbook_block()
def addsummarytonoteerror(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('addsummarytonoteerror() called')

    formatted_data_1 = phantom.get_format_data(name='formatoutputfornoteerror')

    note_title = "Uncontainment result by Phantom"
    note_content = formatted_data_1
    note_format = "html"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["veritytaskstatus:action_result.data.*.parsed_response_body.result.*.data.state", "==", "done"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        taskresultdone(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    taskresulterror(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

@phantom.playbook_block()
def cf_community_datetime_modify_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_datetime_modify_1() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['veritytaskstatus:action_result.data.*.response_headers.Date', 'veritytaskstatus:action_result.parameter.context.artifact_id'], action_results=results )
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