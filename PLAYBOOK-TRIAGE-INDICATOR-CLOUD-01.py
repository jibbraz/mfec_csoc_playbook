"""
An inactive user is defined as a user who had no activity in the last 30 days.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Format_query_to_splunk' block
    Format_query_to_splunk(container=container)

    return

"""
Compare the PasswordLastUsed field to the calculated start time to find unused accounts. Ignore accounts with no value for PasswordLastUsed. This will ignore all accounts with no passwords, such as accounts that only use API access keys.
"""
def filter_inactive(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_inactive() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Query_on_Splunk_to_get_active_user:action_result.status", "==", "SUCCESS"],
        ],
        name="filter_inactive:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        update_custom_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
List all AWS IAM accounts, which will include the PasswordLastUsed field for us to filter on.
"""
def Query_on_Splunk_to_get_active_user(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Query_on_Splunk_to_get_active_user() called')

    # collect data for 'Query_on_Splunk_to_get_active_user' call
    formatted_data_1 = phantom.get_format_data(name='Format_query_to_splunk')

    parameters = []
    
    # build parameters list for 'Query_on_Splunk_to_get_active_user' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk es asset'], callback=filter_inactive, name="Query_on_Splunk_to_get_active_user")

    return

def update_custom_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_custom_list() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['Query_on_Splunk_to_get_active_user:action_result.data.*._raw'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    update_custom_list__inactive_users = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    active_users =['from splunk result']
    clist_full_users = [row[0] for row in phantom.get_list(list_name='GCP_Full_User_List')]
    clist_inact_users = phantom.get_list(list_name='GCP_Inactive_User_List')    
    inact_user_times_current={}
    inact_user_index={row[0]:clist_inact_users.index(row) for row in clist_inact_users}
    inact_users =[user for user in clist_full_users if user not in active_users]

    for user in inact_users:
        if user in inact_user_index.keys():
            index_num = int(inact_user_index[user])
            row_info = clist_inact_users[index_num]
            times=int(row_info[1])+1
            phantom.delete_from_list(list_name='GCP_Inactive_User_List',value=[row_info], remove_row=True)
            phantom.add_list(list_name='GCP_Inactive_User_List',value=[[user,times]])
            inact_user_times_current[user]=times
        else :
            phantom.add_list(list_name='GCP_Inactive_User_List',value=[[user,1]])
            inact_user_times_current[user]=1

    update_custom_list__inactive_users =  inact_user_times_current
    ##################################################
    ##################################################
    ##################################################
    ##################################################
    ##################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='update_custom_list:inactive_users', value=json.dumps(update_custom_list__inactive_users))
    Add_email_body(container=container)

    return

def Add_email_body(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_email_body() called')
    
    template = """Hello,

This is an automated message to inform you of the following investigation.

Inactive Users lists: {0}  

Please do not respond to this message."""

    # parameter list for template variable replacement
    parameters = [
        "",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Add_email_body", separator=", ")

    Send_Email(container=container)

    return

def Send_Email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Send_Email() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Send_Email' call
    formatted_data_1 = phantom.get_format_data(name='Add_email_body')

    parameters = []
    
    # build parameters list for 'Send_Email' call
    parameters.append({
        'cc': "",
        'to': "incidentmanagerxx@gmail.com",
        'bcc': "",
        'body': formatted_data_1,
        'from': "no-reply-phantom@ktbcs.co.th",
        'headers': "",
        'subject': "SOAR-Inactive users notifications",
        'attachments': "",
    })

    phantom.act(action="send email", parameters=parameters, assets=['smtp asset'], name="Send_Email")

    return

def Format_query_to_splunk(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_query_to_splunk() called')
    
    template = """index=GCPxxx earliest=-30d@d latest=now | dedup  username |  stats values(username) as active_users"""

    # parameter list for template variable replacement
    parameters = [
        "test",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_query_to_splunk", separator=", ")

    Query_on_Splunk_to_get_active_user(container=container)

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