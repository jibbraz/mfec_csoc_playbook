"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'ClientHostname' block
    ClientHostname(container=container)

    return

def GetCompGuid(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('GetCompGuid() called')

    # collect data for 'GetCompGuid' call
    formatted_data_1 = phantom.get_format_data(name='GetClientHostnameURI')

    parameters = []
    
    # build parameters list for 'GetCompGuid' call
    parameters.append({
        'headers': "",
        'location': formatted_data_1,
        'verify_certificate': False,
    })

    phantom.act(action="get data", parameters=parameters, assets=['altiris uat'], callback=CompGuid, name="GetCompGuid")

    return

"""
Get client hostname and prepare URI to get computer guid
"""
def GetClientHostnameURI(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('GetClientHostnameURI() called')
    
    template = """/ASDK.NS/ItemManagementService.asmx/GetItemsByNameAndType?name={0}&type=ComputerResource"""

    # parameter list for template variable replacement
    parameters = [
        "ClientHostname:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="GetClientHostnameURI", separator=", ")

    GetCompGuid(container=container)

    return

def CompGuid(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('CompGuid() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "GetCompGuid:action_result.data.*.parsed_response_body.*.guid",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="CompGuid", separator=", ")

    CheckClientExist(container=container)

    return

def CheckClientExist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('CheckClientExist() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["GetCompGuid:action_result.data.*.parsed_response_body.*.guid", "==", None],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        NotifyClientNotExist(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    ExecuteTaskGetInstalledProgramURI(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def NotifyClientNotExist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('NotifyClientNotExist() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """This client {0} not managed by Symantec Altiris. The playbook will be stop."""

    # parameter list for template variable replacement
    parameters = [
        "ClientHostname:formatted_data",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="NotifyClientNotExist", separator=", ", parameters=parameters, response_types=response_types)

    return

def ExecuteTaskGetInstalledProgramURI(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ExecuteTaskGetInstalledProgramURI() called')
    
    template = """/ASDK.Task/TaskManagementService.asmx/ExecuteTask?taskGuid=5afa05b8-a400-4d66-a7e9-4492dcdf9b6a&executionName=CSOC-ThreatHunter-Response&inputParameters=<inputParameters><parameter><name>@AssignedResources</name><value>{0}</value></parameter></inputParameters>"""

    # parameter list for template variable replacement
    parameters = [
        "CompGuid:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="ExecuteTaskGetInstalledProgramURI", separator=", ")

    ExecuteTask(container=container)

    return

def ExecuteTask(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ExecuteTask() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ExecuteTask' call
    formatted_data_1 = phantom.get_format_data(name='ExecuteTaskGetInstalledProgramURI')

    parameters = []
    
    # build parameters list for 'ExecuteTask' call
    parameters.append({
        'headers': "",
        'location': formatted_data_1,
        'verify_certificate': False,
    })

    phantom.act(action="get data", parameters=parameters, assets=['altiris uat'], callback=ExecutedTaskGuid, name="ExecuteTask")

    return

def ExecutedTaskGuid(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ExecutedTaskGuid() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "ExecuteTask:action_result.data.*.parsed_response_body.guid.#text",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="ExecutedTaskGuid", separator=", ")

    cf_local_waittime_1(container=container)

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
    phantom.custom_function(custom_function='local/waittime', parameters=parameters, name='cf_local_waittime_1', callback=GetTaskStatusURI)

    return

def TaskResourceStatusURI(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('TaskResourceStatusURI() called')
    
    template = """/ASDK.Task/TaskManagementService.asmx/GetTaskResourceStatus?taskInstanceGuid={0}&resourceGuid={1}"""

    # parameter list for template variable replacement
    parameters = [
        "ExecutedTaskGuid:formatted_data",
        "CompGuid:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="TaskResourceStatusURI", separator=", ")

    GetTaskResourceStatusResult(container=container)

    return

def GetTaskResourceStatusResult(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('GetTaskResourceStatusResult() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'GetTaskResourceStatusResult' call
    formatted_data_1 = phantom.get_format_data(name='TaskResourceStatusURI')

    parameters = []
    
    # build parameters list for 'GetTaskResourceStatusResult' call
    parameters.append({
        'headers': "",
        'location': formatted_data_1,
        'verify_certificate': False,
    })

    phantom.act(action="get data", parameters=parameters, assets=['altiris uat'], callback=TaskResourceStatus, name="GetTaskResourceStatusResult")

    return

def GetTaskStatusURI(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('GetTaskStatusURI() called')
    
    template = """/ASDK.Task/TaskManagementService.asmx/GetTaskStatus?taskGuid={0}"""

    # parameter list for template variable replacement
    parameters = [
        "ExecutedTaskGuid:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="GetTaskStatusURI", separator=", ")

    GetTaskStatus(container=container)

    return

def GetTaskStatus(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('GetTaskStatus() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'GetTaskStatus' call
    formatted_data_1 = phantom.get_format_data(name='GetTaskStatusURI')

    parameters = []
    
    # build parameters list for 'GetTaskStatus' call
    parameters.append({
        'headers': "",
        'location': formatted_data_1,
        'verify_certificate': False,
    })

    phantom.act(action="get data", parameters=parameters, assets=['altiris uat'], callback=TaskStatus, name="GetTaskStatus")

    return

def TaskStatus(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('TaskStatus() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "GetTaskStatus:action_result.data.*.parsed_response_body.*.TaskStatusDetails.Status",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="TaskStatus", separator=", ")

    decision_4(container=container)

    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["GetTaskStatus:action_result.data.*.parsed_response_body.*.TaskStatusDetails.Status", "!=", "Completed"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        prompt_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    TaskResourceStatusURI(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def prompt_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_4() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """Task execution on target {0} has failure. Please contact CSOC-Platform for working with Symantec Altiris Administrator."""

    # parameter list for template variable replacement
    parameters = [
        "CompGuid:formatted_data",
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

def TaskResourceStatus(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('TaskResourceStatus() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "GetTaskResourceStatusResult:action_result.data.*.parsed_response_body.TaskResourceStatusDetails.OutputProperties.*.Value",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="TaskResourceStatus", separator=", ")

    AddNoteToEvent(container=container)

    return

def AddNoteToEvent(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('AddNoteToEvent() called')

    formatted_data_1 = phantom.get_format_data(name='TaskResourceStatus')

    note_title = "List of installed program"
    note_content = formatted_data_1
    note_format = "html"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def ClientHostname(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ClientHostname() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationHostName",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="ClientHostname", separator=", ")

    GetClientHostnameURI(container=container)

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