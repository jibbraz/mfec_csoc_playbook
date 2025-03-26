"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'playbook_local_PLAYBOOK_UNCONTAIN_INDICATOR_FORTIGATEACI_DSTIP_1' block
    playbook_local_PLAYBOOK_UNCONTAIN_INDICATOR_FORTIGATEACI_DSTIP_1(container=container)

    return

def playbook_local_PLAYBOOK_UNCONTAIN_INDICATOR_FORTIGATEACI_DSTIP_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PLAYBOOK_UNCONTAIN_INDICATOR_FORTIGATEACI_DSTIP_1() called')
    
    # call playbook "local/PLAYBOOK-UNCONTAIN-INDICATOR-FORTIGATEACI-DSTIP", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/PLAYBOOK-UNCONTAIN-INDICATOR-FORTIGATEACI-DSTIP", container=container)
    playbook_local_PLAYBOOK_UNCONTAIN_INDICATOR_FORTIMANAGER_SRC_VAYUX_DSTIP_01_1(container=container)

    return

def playbook_local_PLAYBOOK_UNCONTAIN_INDICATOR_FORTIMANAGERVAYU_DSTIP_01_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PLAYBOOK_UNCONTAIN_INDICATOR_FORTIMANAGERVAYU_DSTIP_01_1() called')
    
    # call playbook "local/PLAYBOOK-UNCONTAIN-INDICATOR-FORTIMANAGERVAYU-DSTIP-01", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/PLAYBOOK-UNCONTAIN-INDICATOR-FORTIMANAGERVAYU-DSTIP-01", container=container)

    return

def playbook_local_PLAYBOOK_UNCONTAIN_INDICATOR_FORTIMANAGER_SRC_VAYUX_DSTIP_01_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PLAYBOOK_UNCONTAIN_INDICATOR_FORTIMANAGER_SRC_VAYUX_DSTIP_01_1() called')
    
    # call playbook "local/PLAYBOOK-UNCONTAIN-INDICATOR-FORTIMANAGER-SRC-VAYUX-DSTIP-01", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/PLAYBOOK-UNCONTAIN-INDICATOR-FORTIMANAGER-SRC-VAYUX-DSTIP-01", container=container)
    playbook_local_PLAYBOOK_UNCONTAIN_INDICATOR_FORTIMANAGER_BBT_VAYUX_DSTIP_01_1(container=container)

    return

def playbook_local_PLAYBOOK_UNCONTAIN_INDICATOR_FORTIMANAGER_BBT_VAYUX_DSTIP_01_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PLAYBOOK_UNCONTAIN_INDICATOR_FORTIMANAGER_BBT_VAYUX_DSTIP_01_1() called')
    
    # call playbook "local/PLAYBOOK-UNCONTAIN-INDICATOR-FORTIMANAGER-BBT-VAYUX-DSTIP-01", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/PLAYBOOK-UNCONTAIN-INDICATOR-FORTIMANAGER-BBT-VAYUX-DSTIP-01", container=container)
    playbook_local_PLAYBOOK_UNCONTAIN_INDICATOR_FORTIGATEINTERNET_DSTIP_1(container=container)

    return

def playbook_local_PLAYBOOK_UNCONTAIN_INDICATOR_FORTIGATEINTERNET_DSTIP_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PLAYBOOK_UNCONTAIN_INDICATOR_FORTIGATEINTERNET_DSTIP_1() called')
    
    # call playbook "local/PLAYBOOK-UNCONTAIN-INDICATOR-FORTIGATEINTERNET-DSTIP", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/PLAYBOOK-UNCONTAIN-INDICATOR-FORTIGATEINTERNET-DSTIP", container=container)
    playbook_local_PLAYBOOK_UNCONTAIN_INDICATOR_FORTIGATEINTERNET_DR_DSTIP_1(container=container)

    return

def playbook_local_PLAYBOOK_UNCONTAIN_INDICATOR_FORTIGATEINTERNET_DR_DSTIP_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PLAYBOOK_UNCONTAIN_INDICATOR_FORTIGATEINTERNET_DR_DSTIP_1() called')
    
    # call playbook "local/PLAYBOOK-UNCONTAIN-INDICATOR-FORTIGATEINTERNET-DR-DSTIP", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/PLAYBOOK-UNCONTAIN-INDICATOR-FORTIGATEINTERNET-DR-DSTIP", container=container)
    playbook_local_PLAYBOOK_UNCONTAIN_INDICATOR_FORTIGATEDEV_DSTIP_1(container=container)

    return

def playbook_local_PLAYBOOK_UNCONTAIN_INDICATOR_FORTIGATEDEV_DSTIP_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_PLAYBOOK_UNCONTAIN_INDICATOR_FORTIGATEDEV_DSTIP_1() called')
    
    # call playbook "local/PLAYBOOK-UNCONTAIN-INDICATOR-FORTIGATEDEV-DSTIP", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/PLAYBOOK-UNCONTAIN-INDICATOR-FORTIGATEDEV-DSTIP", container=container)

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