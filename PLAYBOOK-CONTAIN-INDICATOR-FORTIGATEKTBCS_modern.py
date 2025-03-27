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
        cf_local_strip_url_prefix_n_generate_body_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

@phantom.playbook_block()
def mergeresultformat(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('mergeresultformat() called')
    
    template = """[
%%
{{\"result_body\" : {5}, \"status\" : \"{0}\"}},
{{\"result_body\" : {6}, \"status\" : \"{1}\"}},
{{\"result_body\" : {7}, \"status\" : \"{2}\"}},
{{\"result_body\" : {8}, \"status\" : \"{3}\"}},
{{\"result_body\" : {9}, \"status\" : \"{4}\"}},
%%
]"""

    # parameter list for template variable replacement
    parameters = [
        "postdc1_atp_seg_1:action_result.status",
        "postdc2_atp_seg_1:action_result.status",
        "postdr1_atp_seg_1:action_result.status",
        "postdr2_atp_seg_1:action_result.status",
        "postdr2_atp_seg_2:action_result.status",
        "postdc1_atp_seg_1:action_result.parameter.body",
        "postdc2_atp_seg_1:action_result.parameter.body",
        "postdr1_atp_seg_1:action_result.parameter.body",
        "postdr2_atp_seg_1:action_result.parameter.body",
        "postdr2_atp_seg_2:action_result.parameter.body",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="mergeresultformat", separator=", ")

    artifactupdateformat(container=container)

    return

@phantom.playbook_block()
def cf_local_debug_variable_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_debug_variable_1() called')
    
    formatted_data_as_list_0 = phantom.get_format_data(name="mergeresultformat__as_list")
    formatted_data_0 = [
        [
            phantom.get_format_data(name="mergeresultformat"),
        ],
    ]

    parameters = []

    formatted_data_as_list_0_0 = [item[0] for item in formatted_data_as_list_0]

    for item0 in formatted_data_0:
        parameters.append({
            'var1': item0[0],
            'var2_list': formatted_data_as_list_0_0,
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/debug_variable", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/debug_variable', parameters=parameters, name='cf_local_debug_variable_1')

    return

@phantom.playbook_block()
def add_note_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_4() called')

    formatted_data_1 = phantom.get_format_data(name='addnoteformat')

    note_title = "Playbook Summary: Block URL Result"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    mergeresultformat(container=container)

    return

@phantom.playbook_block()
def postdc1_atp_seg_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('postdc1_atp_seg_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'postdc1_atp_seg_1' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_strip_url_prefix_n_generate_body_1:custom_function_result.data.bodyFormat.*'], action_results=results)

    parameters = []
    
    # build parameters list for 'postdc1_atp_seg_1' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'body': custom_function_results_item_1[0],
                'headers': "",
                'location': "webfilter/ftgd-local-rating?vdom=ATP-Seg-1&access_token=Gx706wf7wfxgr8Nhb530w9HsHdH93Q",
                'verify_certificate': False,
            })

    phantom.act(action="post data", parameters=parameters, assets=['fortigate-pbs-01'], callback=postdc2_atp_seg_1, name="postdc1_atp_seg_1")

    return

@phantom.playbook_block()
def addnoteformat(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('addnoteformat() called')
    
    template = """{0}
Execution Time : {1}"""

    # parameter list for template variable replacement
    parameters = [
        "cf_local_sort_and_gen_markdown_1:custom_function_result.data.markdown",
        "postdc1_atp_seg_1:action_result.data.*.response_headers.Date",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="addnoteformat", separator=", ")

    add_note_4(container=container)

    return

@phantom.playbook_block()
def cf_local_strip_url_prefix_n_generate_body_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_strip_url_prefix_n_generate_body_1() called')
    
    filtered_artifacts_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filtermaliciousurl:condition_1:artifact:*.cef.requestURL'])

    parameters = []

    for item0 in filtered_artifacts_data_0:
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

    # call custom function "local/strip_url_prefix_n_generate_body", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/strip_url_prefix_n_generate_body', parameters=parameters, name='cf_local_strip_url_prefix_n_generate_body_1', callback=postdc1_atp_seg_1)

    return

@phantom.playbook_block()
def postdc2_atp_seg_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('postdc2_atp_seg_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'postdc2_atp_seg_1' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_strip_url_prefix_n_generate_body_1:custom_function_result.data.bodyFormat.*'], action_results=results)

    parameters = []
    
    # build parameters list for 'postdc2_atp_seg_1' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'body': custom_function_results_item_1[0],
                'headers': "",
                'location': "webfilter/ftgd-local-rating?vdom=ATP-Seg-1&access_token=rd89bs6667cq6dcdhnrjhj7rkrNqnG",
                'verify_certificate': False,
            })

    phantom.act(action="post data", parameters=parameters, assets=['fortigate-pbs-02'], callback=postdr1_atp_seg_1, name="postdc2_atp_seg_1", parent_action=action)

    return

@phantom.playbook_block()
def postdr1_atp_seg_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('postdr1_atp_seg_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'postdr1_atp_seg_1' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_strip_url_prefix_n_generate_body_1:custom_function_result.data.bodyFormat.*'], action_results=results)

    parameters = []
    
    # build parameters list for 'postdr1_atp_seg_1' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'body': custom_function_results_item_1[0],
                'headers': "",
                'location': "webfilter/ftgd-local-rating?vdom=ATP-Seg-1&access_token=sj6g8dQNmgpxj6k7bcd74gd8j535rq",
                'verify_certificate': False,
            })

    phantom.act(action="post data", parameters=parameters, assets=['fortigate-bbt-01'], callback=postdr2_atp_seg_1, name="postdr1_atp_seg_1", parent_action=action)

    return

@phantom.playbook_block()
def postdr2_atp_seg_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('postdr2_atp_seg_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'postdr2_atp_seg_1' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_strip_url_prefix_n_generate_body_1:custom_function_result.data.bodyFormat.*'], action_results=results)

    parameters = []
    
    # build parameters list for 'postdr2_atp_seg_1' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'body': custom_function_results_item_1[0],
                'headers': "",
                'location': "webfilter/ftgd-local-rating?vdom=ATP-Seg-1&access_token=3xd3n91w6kthqw7xGhbxjmnt6hrrmj",
                'verify_certificate': False,
            })

    phantom.act(action="post data", parameters=parameters, assets=['fortigate-bbt-02'], callback=postdr2_atp_seg_2, name="postdr2_atp_seg_1", parent_action=action)

    return

@phantom.playbook_block()
def cf_local_merge_url_result_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_merge_url_result_1() called')
    
    formatted_data_0 = [
        [
            phantom.get_format_data(name="mergeresultformat"),
            phantom.get_format_data(name="artifactupdateformat"),
        ],
    ]

    parameters = []

    for item0 in formatted_data_0:
        parameters.append({
            'resultList': item0[0],
            'artifactInfo': item0[1],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/merge_url_result", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/merge_url_result', parameters=parameters, name='cf_local_merge_url_result_1')

    return

@phantom.playbook_block()
def artifactupdateformat(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('artifactupdateformat() called')
    
    template = """[
%%
{{
      \"artifact_id\" : {0} ,
      \"cef\" : [{1}]
}},
%%
]"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filtermaliciousurl:condition_1:artifact:*.id",
        "filtered-data:filtermaliciousurl:condition_1:artifact:*.cef",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="artifactupdateformat", separator=", ")

    cf_local_merge_url_result_1(container=container)

    return

@phantom.playbook_block()
def preparenoteformat(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('preparenoteformat() called')
    
    template = """[
%%
{{\"device\" : \"DC1-ATP-Seg-1\", \"body\" : {0}, \"status\" : \"{1}\", \"code\" : \"{10}\",\"reason\" : \"{11}\"}},
{{\"device\" : \"DC2-ATP-Seg-1\", \"body\" : {2}, \"status\" : \"{3}\", \"code\" : \"{12}\",\"reason\" : \"{13}\"}},
{{\"device\" : \"DR1-ATP-Seg-1\", \"body\" : {4}, \"status\" : \"{5}\", \"code\" : \"{14}\",\"reason\" : \"{15}\"}},
{{\"device\" : \"DR2-ATP-Seg-1\", \"body\" : {6}, \"status\" : \"{7}\", \"code\" : \"{16}\",\"reason\" : \"{17}\"}},
{{\"device\" : \"DR2-ATP-Seg-2\", \"body\" : {8}, \"status\" : \"{9}\", \"code\" : \"{18}\",\"reason\" : \"{19}\"}},
%%
]"""

    # parameter list for template variable replacement
    parameters = [
        "postdc1_atp_seg_1:action_result.parameter.body",
        "postdc1_atp_seg_1:action_result.status",
        "postdc2_atp_seg_1:action_result.parameter.body",
        "postdc2_atp_seg_1:action_result.status",
        "postdr1_atp_seg_1:action_result.parameter.body",
        "postdr1_atp_seg_1:action_result.status",
        "postdr2_atp_seg_1:action_result.parameter.body",
        "postdr2_atp_seg_1:action_result.status",
        "postdr2_atp_seg_2:action_result.parameter.body",
        "postdr2_atp_seg_2:action_result.status",
        "postdc1_atp_seg_1:action_result.summary.status_code",
        "postdc1_atp_seg_1:action_result.summary.reason",
        "postdc2_atp_seg_1:action_result.summary.status_code",
        "postdc2_atp_seg_1:action_result.summary.reason",
        "postdr1_atp_seg_1:action_result.summary.status_code",
        "postdr1_atp_seg_1:action_result.summary.reason",
        "postdr2_atp_seg_1:action_result.summary.status_code",
        "postdr2_atp_seg_1:action_result.summary.reason",
        "postdr2_atp_seg_2:action_result.summary.status_code",
        "postdr2_atp_seg_2:action_result.summary.reason",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="preparenoteformat", separator=", ")

    cf_local_sort_and_gen_markdown_1(container=container)

    return

@phantom.playbook_block()
def cf_local_sort_and_gen_markdown_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_sort_and_gen_markdown_1() called')
    
    formatted_data_0 = [
        [
            phantom.get_format_data(name="preparenoteformat"),
        ],
    ]

    parameters = []

    for item0 in formatted_data_0:
        parameters.append({
            'resultList': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/sort_and_gen_markdown", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/sort_and_gen_markdown', parameters=parameters, name='cf_local_sort_and_gen_markdown_1', callback=addnoteformat)

    return

@phantom.playbook_block()
def postdr2_atp_seg_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('postdr2_atp_seg_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'postdr2_atp_seg_2' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_strip_url_prefix_n_generate_body_1:custom_function_result.data.bodyFormat.*'], action_results=results)

    parameters = []
    
    # build parameters list for 'postdr2_atp_seg_2' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'body': custom_function_results_item_1[0],
                'headers': "",
                'location': "webfilter/ftgd-local-rating?vdom=ATP-Seg-2&access_token=3xd3n91w6kthqw7xGhbxjmnt6hrrmj",
                'verify_certificate': False,
            })

    phantom.act(action="post data", parameters=parameters, assets=['fortigate-bbt-02'], callback=preparenoteformat, name="postdr2_atp_seg_2", parent_action=action)

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