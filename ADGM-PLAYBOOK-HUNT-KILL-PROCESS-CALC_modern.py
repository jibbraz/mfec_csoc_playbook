"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'clienthostname' block
    clienthostname(container=container)

    return

@phantom.playbook_block()
def getcompguid(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('getcompguid() called')

    # collect data for 'getcompguid' call
    formatted_data_1 = phantom.get_format_data(name='GetclienthostnameURI')

    parameters = []
    
    # build parameters list for 'getcompguid' call
    parameters.append({
        'headers': "",
        'location': formatted_data_1,
        'verify_certificate': False,
    })

    phantom.act(action="get data", parameters=parameters, assets=['altiris uat'], callback=compguid, name="getcompguid")

    return

"""
Get client hostname and prepare URI to get computer guid
"""
@phantom.playbook_block()
def GetclienthostnameURI(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('GetclienthostnameURI() called')
    
    template = """/ASDK.NS/ItemManagementService.asmx/GetItemsByNameAndType?name={0}&type=ComputerResource"""

    # parameter list for template variable replacement
    parameters = [
        "clienthostname:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="GetclienthostnameURI", separator=", ")

    getcompguid(container=container)

    return

@phantom.playbook_block()
def compguid(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('compguid() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "getcompguid:action_result.data.*.parsed_response_body.*.guid",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="compguid", separator=", ")

    checkclientexist(container=container)

    return

@phantom.playbook_block()
def checkclientexist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('checkclientexist() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["getcompguid:action_result.data.*.parsed_response_body.*.guid", "==", None],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        notifyclientnotexist(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    executetaskkillprocesscalcuri(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

@phantom.playbook_block()
def notifyclientnotexist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('notifyclientnotexist() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """This client {0} not managed by Symantec Altiris. The playbook will be stop."""

    # parameter list for template variable replacement
    parameters = [
        "clienthostname:formatted_data",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="notifyclientnotexist", separator=", ", parameters=parameters, response_types=response_types)

    return

@phantom.playbook_block()
def executetaskkillprocesscalcuri(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('executetaskkillprocesscalcuri() called')
    
    template = """/ASDK.Task/TaskManagementService.asmx/ExecuteTask?taskGuid=5b8a765c-b3dd-40c2-b5ff-c91684ce2139&executionName=CSOC-ThreatHunter-Response&inputParameters=<inputParameters><parameter><name>@AssignedResources</name><value>{0}</value></parameter></inputParameters>"""

    # parameter list for template variable replacement
    parameters = [
        "compguid:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="executetaskkillprocesscalcuri", separator=", ")

    executetaskkillcalc(container=container)

    return

@phantom.playbook_block()
def executetaskkillcalc(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('executetaskkillcalc() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'executetaskkillcalc' call
    formatted_data_1 = phantom.get_format_data(name='executetaskkillprocesscalcuri')

    parameters = []
    
    # build parameters list for 'executetaskkillcalc' call
    parameters.append({
        'headers': "",
        'location': formatted_data_1,
        'verify_certificate': False,
    })

    phantom.act(action="get data", parameters=parameters, assets=['altiris uat'], callback=executedtaskguid, name="executetaskkillcalc")

    return

@phantom.playbook_block()
def executedtaskguid(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('executedtaskguid() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "executetaskkillcalc:action_result.data.*.parsed_response_body.guid.#text",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="executedtaskguid", separator=", ")

    cf_local_waittime_1(container=container)

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
    phantom.custom_function(custom_function='local/waittime', parameters=parameters, name='cf_local_waittime_1', callback=gettaskstatusuri)

    return

@phantom.playbook_block()
def taskresourcestatusURI(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('taskresourcestatusURI() called')
    
    template = """/ASDK.Task/TaskManagementService.asmx/Gettaskresourcestatus?taskInstanceGuid={0}&resourceGuid={1}"""

    # parameter list for template variable replacement
    parameters = [
        "executedtaskguid:formatted_data",
        "compguid:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="taskresourcestatusURI", separator=", ")

    GettaskresourcestatusResult(container=container)

    return

@phantom.playbook_block()
def GettaskresourcestatusResult(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('GettaskresourcestatusResult() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'GettaskresourcestatusResult' call
    formatted_data_1 = phantom.get_format_data(name='taskresourcestatusURI')

    parameters = []
    
    # build parameters list for 'GettaskresourcestatusResult' call
    parameters.append({
        'headers': "",
        'location': formatted_data_1,
        'verify_certificate': False,
    })

    phantom.act(action="get data", parameters=parameters, assets=['altiris uat'], callback=taskresourcestatus, name="GettaskresourcestatusResult")

    return

@phantom.playbook_block()
def gettaskstatusuri(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('gettaskstatusuri() called')
    
    template = """/ASDK.Task/TaskManagementService.asmx/gettaskstatus?taskGuid={0}"""

    # parameter list for template variable replacement
    parameters = [
        "executedtaskguid:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="gettaskstatusuri", separator=", ")

    gettaskstatus(container=container)

    return

@phantom.playbook_block()
def gettaskstatus(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('gettaskstatus() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'gettaskstatus' call
    formatted_data_1 = phantom.get_format_data(name='gettaskstatusuri')

    parameters = []
    
    # build parameters list for 'gettaskstatus' call
    parameters.append({
        'headers': "",
        'location': formatted_data_1,
        'verify_certificate': False,
    })

    phantom.act(action="get data", parameters=parameters, assets=['altiris uat'], callback=taskstatus, name="gettaskstatus")

    return

@phantom.playbook_block()
def taskstatus(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('taskstatus() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "gettaskstatus:action_result.data.*.parsed_response_body.*.taskstatusDetails.Status",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="taskstatus", separator=", ")

    decision_4(container=container)

    return

@phantom.playbook_block()
def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["gettaskstatus:action_result.data.*.parsed_response_body.*.taskstatusDetails.Status", "!=", "Completed"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        prompt_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    taskresourcestatusURI(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

@phantom.playbook_block()
def prompt_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_4() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """Task execution on target {0} has failure. Please contact CSOC-Platform for working with Symantec Altiris Administrator."""

    # parameter list for template variable replacement
    parameters = [
        "compguid:formatted_data",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_4", separator=", ", parameters=parameters, response_types=response_types)

    return

@phantom.playbook_block()
def taskresourcestatus(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('taskresourcestatus() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "GettaskresourcestatusResult:action_result.data.*.parsed_response_body.taskresourcestatusDetails.OutputProperties.*.Value",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="taskresourcestatus", separator=", ")

    addnotetoevent(container=container)

    return

@phantom.playbook_block()
def addnotetoevent(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('addnotetoevent() called')

    formatted_data_1 = phantom.get_format_data(name='taskresourcestatus')

    note_title = "Result of kill process"
    note_content = formatted_data_1
    note_format = "html"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

@phantom.playbook_block()
def clienthostname(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('clienthostname() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationHostName",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="clienthostname", separator=", ")

    GetclienthostnameURI(container=container)

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