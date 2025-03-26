def filter_new_worknote(note_list=None, filter_from=None, settings=None, **kwargs):
    """
    Filter out the old worknote and worknote from servicenow from worknote list
    
    Args:
        note_list
        filter_from: get new work note from phantom or servicenow
        settings: settings dict
    
    Returns a JSON-serializable object that implements the configured data paths:
        success
        data
        error_msg
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    from datetime import datetime

    result = {}
    success = True
    data = []
    error_msg = ""
    
    try:
        filter_from = str(filter_from)
        if filter_from.lower() == "phantom":
            source_timestamp = "last_update_to_servicenow"
            filter_text_key = "note_title_from_servicenow"
        elif filter_from.lower() == "servicenow":
            source_timestamp = "last_update_from_servicenow"
            filter_text_key = "note_message_from_phantom"
        else:
            raise Exception("filter_from is neither phantom or servicenow")
        
        if not isinstance(settings, dict):
            raise Exception("Settings is not a dictionary")

        filter_text = settings.get(filter_text_key, "")
        if (filter_text == "") or (filter_text == None):
            raise Exception(f"{filter_text_key} not found in settings list")

        for note in note_list:
            note_info = note["note_info"]
            phantom_case_id = note_info["phantom_case_id"]
            container = phantom.get_container(phantom_case_id)
            timestamp = container.get("custom_fields", {}).get(source_timestamp, "")
            if (timestamp == None) or (timestamp == ""):
                timestamp = ""
            else:
                timestamp = datetime.strptime(timestamp, '%d/%m/%Y %H:%M:%S')
            
            # get only new Phantom note, filter out note from servicenow
            if (filter_from == "phantom") and (note_info["title"] == filter_text):
                continue

            # get only new Servicenow note, filter out note from phantom
            if (filter_from == "servicenow") and (f"\n{filter_text}" in note_info["content"]):
                continue

            datetime_str = note_info["creation_date"]
            creation_date = datetime.strptime(datetime_str, "%d/%m/%Y %H:%M:%S")
            creation_date = creation_date.replace(tzinfo=None)

            # timestamp update to servicenow blank if the case just created from ServiceNow and no any update from Phantom send to ServiceNow.
            # That's why we have to sync work note to ServiceNow even the timestamp is blank
            if (timestamp == "") or (creation_date > timestamp):
                data.append(note)

    except Exception as e:
        success = False
        error_msg = f"Exception: {str(e)}"

    result["success"] = success
    result["data"] = data
    result["error_msg"] = error_msg

    # Return a JSON-serializable object
    assert json.dumps(result)  # Will raise an exception if the :outputs: object is not JSON-serializable
    phantom.debug(result)
    return result