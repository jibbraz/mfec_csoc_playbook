"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_1' block
    filter_1(container=container)

    return

@phantom.playbook_block()
def playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEACI_BLOCKSRCIP_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEACI_BLOCKSRCIP_1() called')
    
    # call playbook "local/playbook-contain-indicator-fortigateaci-blocksrcip", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/playbook-contain-indicator-fortigateaci-blocksrcip", container=container)
    playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIMANAGER_SRC_VAYUX_SRCIP_01_1(container=container)

    return

@phantom.playbook_block()
def playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIMANAGERVAYU_SRCIP_01_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIMANAGERVAYU_SRCIP_01_1() called')
    
    # call playbook "local/playbook-contain-indicator-fortimanagervayu-srcip-01", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/playbook-contain-indicator-fortimanagervayu-srcip-01", container=container)

    return

@phantom.playbook_block()
def playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIMANAGER_SRC_VAYUX_SRCIP_01_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIMANAGER_SRC_VAYUX_SRCIP_01_1() called')
    
    # call playbook "local/playbook-contain-indicator-fortimanager-src-vayux-srcip-01", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/playbook-contain-indicator-fortimanager-src-vayux-srcip-01", container=container)
    playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIMANAGER_BBT_VAYUX_SRCIP_01_1(container=container)

    return

@phantom.playbook_block()
def playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIMANAGER_BBT_VAYUX_SRCIP_01_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIMANAGER_BBT_VAYUX_SRCIP_01_1() called')
    
    # call playbook "local/playbook-contain-indicator-fortimanager-bbt-vayux-srcip-01", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/playbook-contain-indicator-fortimanager-bbt-vayux-srcip-01", container=container)
    playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEINTERNET_BLOCKSRCIP_1(container=container)

    return

@phantom.playbook_block()
def playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEINTERNET_BLOCKSRCIP_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEINTERNET_BLOCKSRCIP_1() called')
    
    # call playbook "local/playbook-contain-indicator-fortigateinternet-blocksrcip", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/playbook-contain-indicator-fortigateinternet-blocksrcip", container=container)
    playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEINTERNET_DR_BLOCKSRCIP_1(container=container)

    return

@phantom.playbook_block()
def playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEINTERNET_DR_BLOCKSRCIP_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEINTERNET_DR_BLOCKSRCIP_1() called')
    
    # call playbook "local/playbook-contain-indicator-fortigateinternet-dr-blocksrcip", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/playbook-contain-indicator-fortigateinternet-dr-blocksrcip", container=container)
    playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEDEV_BLOCKSRCIP_1(container=container)

    return

@phantom.playbook_block()
def playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEDEV_BLOCKSRCIP_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEDEV_BLOCKSRCIP_1() called')
    
    # call playbook "local/playbook-contain-indicator-fortigatedev-blocksrcip", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/playbook-contain-indicator-fortigatedev-blocksrcip", container=container)

    return

@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "not in", "custom_list:KTB Public IP"],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEACI_BLOCKSRCIP_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "in", "custom_list:KTB Public IP"],
        ],
        name="filter_1:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        ip_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

@phantom.playbook_block()
def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_reputation_1() called')

    # collect data for 'ip_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'ip_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="ip reputation", parameters=parameters, assets=['virustotal v3 asset'], callback=add_note_1, name="ip_reputation_1")

    return

@phantom.playbook_block()
def add_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_1() called')

    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    container_item_0 = [item[0] for item in container_data]

    note_title = "[ALERT] : Please check ip address."
    note_content = container_item_0
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    container = phantom.get_container(container.get('id', None))

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