"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'authreqtofortimanager' block
    authreqtofortimanager(container=container)

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

    parameters = []
    
    # build parameters list for 'authreqtofortimanager' call
    parameters.append({
        'body': "{ 	\"id\": 1, 	\"method\": \"exec\", 	\"params\": [ 		{ 			\"data\": [ 			{ 				\"passwd\": \"soar\", 				\"user\": \"soar\" 			} 			], 			\"url\": \"sys/login/user\" 		} 	], 	\"session\": null, 	\"verbose\": 1 }",
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

    bodyreqdeladdrobjfromaddrgrp(container=container)

    return

@phantom.playbook_block()
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
        "getauthsessionid:formatted_data",
        "bodyreqdeladdrobjfromaddrgrp:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="reqdeladdrobjfromaddrgrp", separator=", ")

    deladdrobjtoaddrgrp(container=container)

    return

@phantom.playbook_block()
def deladdrobjtoaddrgrp(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('deladdrobjtoaddrgrp() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'deladdrobjtoaddrgrp' call
    formatted_data_1 = phantom.get_format_data(name='reqdeladdrobjfromaddrgrp')

    parameters = []
    
    # build parameters list for 'deladdrobjtoaddrgrp' call
    parameters.append({
        'body': formatted_data_1,
        'headers': "{\"Content-Type\":\"application/json\"}",
        'location': "/jsonrpc",
        'verify_certificate': False,
    })

    phantom.act(action="post data", parameters=parameters, assets=['csoc-fortimanager'], callback=reqinstallpolicypackage, name="deladdrobjtoaddrgrp")

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

    phantom.act(action="post data", parameters=parameters, assets=['csoc-fortimanager'], callback=cf_community_debug_1, name="installpolicypackage")

    return

@phantom.playbook_block()
def bodyreqdeladdrobjfromaddrgrp(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('bodyreqdeladdrobjfromaddrgrp() called')
    
    template = """%%
\"Phantom {0}_32\",
%%"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="bodyreqdeladdrobjfromaddrgrp", separator=", ")

    reqdeladdrobjfromaddrgrp(container=container)

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