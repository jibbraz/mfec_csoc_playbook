"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEDEV_BLOCKSRCIP_KCSEXTDEVL2_1' block
    playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEDEV_BLOCKSRCIP_KCSEXTDEVL2_1(container=container)

    return

@phantom.playbook_block()
def playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEDEV_BLOCKSRCIP_KCSEXTDEVL2_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEDEV_BLOCKSRCIP_KCSEXTDEVL2_1() called')
    
    # call playbook "local/playbook-contain-indicator-fortigatedev-blocksrcip[kcsextdevl2]", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/playbook-contain-indicator-fortigatedev-blocksrcip[kcsextdevl2]", container=container)
    playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEDEV_BLOCKSRCIP_KCSEXTDEVL3_1(container=container)

    return

@phantom.playbook_block()
def playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEDEV_BLOCKSRCIP_KCSEXTDEVL3_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEDEV_BLOCKSRCIP_KCSEXTDEVL3_1() called')
    
    # call playbook "local/playbook-contain-indicator-fortigatedev-blocksrcip[kcsextdevl3]", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/playbook-contain-indicator-fortigatedev-blocksrcip[kcsextdevl3]", container=container)
    playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEDEV_BLOCKSRCIP_KCSEXTVAYU_1(container=container)

    return

@phantom.playbook_block()
def playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEDEV_BLOCKSRCIP_KCSEXTVAYU_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PLAYBOOK_CONTAIN_INDICATOR_FORTIGATEDEV_BLOCKSRCIP_KCSEXTVAYU_1() called')
    
    # call playbook "local/playbook-contain-indicator-fortigatedev-blocksrcip[kcsextvayu]", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/playbook-contain-indicator-fortigatedev-blocksrcip[kcsextvayu]", container=container)

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