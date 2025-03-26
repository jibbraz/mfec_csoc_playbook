"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'AuthReqToFortiManager' block
    AuthReqToFortiManager(container=container)

    return

"""
HTTP method: POST
API execute method: exec
URL: /sys/login/user
"""
def AuthReqToFortiManager(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('AuthReqToFortiManager() called')

    # collect data for 'AuthReqToFortiManager' call

    parameters = []
    
    # build parameters list for 'AuthReqToFortiManager' call
    parameters.append({
        'body': "{ 	\"id\": 1, 	\"method\": \"exec\", 	\"params\": [ 		{ 			\"data\": [ 			{ 				\"passwd\": \"soar\", 				\"user\": \"soar\" 			} 			], 			\"url\": \"sys/login/user\" 		} 	], 	\"session\": null, 	\"verbose\": 1 }",
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

    BodyReqDelAddrObjFromAddrGrp(container=container)

    return

def cf_community_debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_debug_1() called')
    
    container_data_0 = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []

    container_data_0_0 = [item[0] for item in container_data_0]

    parameters.append({
        'input_1': container_data_0_0,
        'input_2': None,
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

    # call custom function "community/debug", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/debug', parameters=parameters, name='cf_community_debug_1')

    return

def ReqDelAddrObjFromAddrGrp(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ReqDelAddrObjFromAddrGrp() called')
    
    template = """%%
{{
	\"session\": \"{0}\",
	\"id\": 1,
	\"method\": \"delete\" ,
    \"params\": [
        {{
            \"url\": \"/pm/config/adom/root/obj/firewall/addrgrp/Phantom-Blacklist/member/\",
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
        "BodyReqDelAddrObjFromAddrGrp:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="ReqDelAddrObjFromAddrGrp", separator=", ")

    DelAddrObjToAddrGrp(container=container)

    return

def DelAddrObjToAddrGrp(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('DelAddrObjToAddrGrp() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'DelAddrObjToAddrGrp' call
    formatted_data_1 = phantom.get_format_data(name='ReqDelAddrObjFromAddrGrp')

    parameters = []
    
    # build parameters list for 'DelAddrObjToAddrGrp' call
    parameters.append({
        'body': formatted_data_1,
        'headers': "{\"Content-Type\":\"application/json\"}",
        'location': "/jsonrpc",
        'verify_certificate': False,
    })

    phantom.act(action="post data", parameters=parameters, assets=['csoc-fortimanager'], callback=ReqInstallPolicyPackage, name="DelAddrObjToAddrGrp")

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
                    \"pkg\": \"FortiGate CSOC\",
                    \"scope member\": [
                        {{
                            \"name\": \"FGVM01TM22001286\",
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

    phantom.act(action="post data", parameters=parameters, assets=['csoc-fortimanager'], callback=cf_community_debug_1, name="InstallPolicyPackage")

    return

def BodyReqDelAddrObjFromAddrGrp(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('BodyReqDelAddrObjFromAddrGrp() called')
    
    template = """%%
\"Phantom {0}_32\",
%%"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="BodyReqDelAddrObjFromAddrGrp", separator=", ")

    ReqDelAddrObjFromAddrGrp(container=container)

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