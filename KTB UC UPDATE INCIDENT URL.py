"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'join_filter_1' block
    join_filter_1(container=container)

    return

def format_search_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_search_url() called')
    
    id_value = container.get('id', None)
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.event_id', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]

    format_search_url__note_search_url = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    # create dynamic url from static splunk url and event_id in container
    
    static_url = "https://splunk-es.csoc.krungthai.local/en-GB/app/SplunkEnterpriseSecuritySuite/incident_review?earliest=-7d%40h&latest=now&search=event_id%3D"
    dynamic_url = static_url + container_item_0[0]
    
    # update artifact
    artifactid = ""
    parameters = []
    cef_json = { '_incident_url': dynamic_url }
    
    url = phantom.build_phantom_rest_url('container' , id_value , 'artifacts')
    #url = url + '?_filter_cef__username="' + filtered_artifacts_item_1_0[0] +'"'
    #phantom.debug(url)
    response = phantom.requests.get(url, verify=False)
    for key in response.json()['data']:
        for item in key:
            if item == 'id':
                artifactid = key[item]
                parameters.append({
                    'artifact_id': artifactid,
                   	'name': "",
                	'label': "",
		            'severity': "",
		            'cef_json': cef_json,
		            'cef_types_json': { '_incident_url' : ['url'] },
    	            'tags': "",
		            'overwrite': "",
                    'artifact_json': "",
                })
                phantom.act(action="update artifact", parameters=parameters, assets=['phantom asset'], name="update_incident_url")
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='format_search_url:note_search_url', value=json.dumps(format_search_url__note_search_url))
    join_decision_2(container=container)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.event_id", "!=", ""],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_search_url(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        delete_original_search(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def join_filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_filter_1() called')

    # no callbacks to check, call connected block "filter_1"
    phantom.save_run_data(key='join_filter_1_called', value='filter_1', auto=True)

    filter_1(container=container, handle=handle)
    
    return

"""
compare event_id and delete one artifact if found identical
"""
def delete_duplicate_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('delete_duplicate_artifact() called')
    
    id_value = container.get('id', None)
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.event_id', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]

    delete_duplicate_artifact__artifactid = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    artifactid = []
    artifactcount = 0
    
    url = phantom.build_phantom_rest_url('container' , id_value , 'artifacts')
    response = phantom.requests.get(url, verify=False)
    for key in response.json()['data']:
        for item in key:
            if item == 'id':
                artifactid.append(key[item])
                artifactcount += 1
    
    phantom.debug(container_item_0)
    if (container_item_0[0] == container_item_0[1]):
        success = phantom.delete_artifact(artifact_id=artifactid[1])
        phantom.debug('phantom.delete_artifact results: success: {} '.format(success))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='delete_duplicate_artifact:artifactid', value=json.dumps(delete_duplicate_artifact__artifactid))
    join_filter_1(container=container)

    return

def delete_original_search(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('delete_original_search() called')
    
    input_parameter_0 = ""

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    updated_artifact = {}
    artifacts = phantom.collect(container, 'artifacts:*', scope='all')
    #phantom.debug(len(artifacts))
    key = '_originating_search'    
    for artifact in artifacts:
        updated_artifact['cef'] = artifact['cef']
        updated_artifact['cef_types'] = artifact['cef_types']
        
        if key in updated_artifact['cef']:
            del updated_artifact['cef']['_originating_search']
        if key in updated_artifact['cef']:
            del updated_artifact['cef_types']['_originating_search']

        artifact_id = artifact["id"]
        phantom.debug('updating artifact {} with the following attributes:\n{}'.format(artifact_id, updated_artifact))
        url = phantom.build_phantom_rest_url('artifact', artifact_id)
        phantom.debug(url)
        response = phantom.requests.post(url, json=updated_artifact, verify=False).json()

        phantom.debug('POST /rest/artifact returned the following response:\n{}'.format(response))
        if 'success' not in response or response['success'] != True:
            raise RuntimeError("POST /rest/artifact failed") 

    ################################################################################
    ## Custom Code End
    ################################################################################
    join_decision_2(container=container)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')
    
    label_param = container.get('label', None)

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            [label_param, "==", "account"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        return

    # call connected blocks for 'else' condition 2

    return

def join_decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_decision_2() called')

    # no callbacks to check, call connected block "decision_2"
    phantom.save_run_data(key='join_decision_2_called', value='decision_2', auto=True)

    decision_2(container=container, handle=handle)
    
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