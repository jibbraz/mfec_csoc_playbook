def process_servicenow_note(raw_servicenow_response=None, note_title=None, **kwargs):
    """
    Extract and process ServiceNow work notes from ServiceNow incident API response
    
    Args:
        raw_servicenow_response
        note_title: Note title to indicate this note is from ServiceNow
    
    Returns a JSON-serializable object that implements the configured data paths:
        success
        data
        error_msg
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    from datetime import datetime
    
    success = True
    data = []
    error_msg = ""
    
    result = {}

    try:
        servicenow_case_id = raw_servicenow_response.get("sys_id", "")
        phantom_case_id = raw_servicenow_response.get("u_phantom_case_id", "")
        worknote = raw_work_note = raw_servicenow_response.get("work_notes", "")
        if (worknote == None):
            worknote = ""
        
        worknote = worknote.replace("\r\n", "NEWLINE").split("\n")
        worknote = [i for i in worknote if i != ""]

        worknote_list = []
        created_date_list = worknote[0:][::2]
        text_list = worknote[1:][::2]

        if len(created_date_list) != len(text_list):
            raise Exception(f"Fail to extract work notes for ServiceNow case ID: {servicenow_case_id}. Wrong ServiceNow work note format")

        for i in range(len(created_date_list)-1, -1, -1):
            formatted_note = {}
            date_string = created_date_list[i]
            text = text_list[i].replace("NEWLINE", "\n")
            if " - " in date_string:
                creationDate, author = date_string.split(" - ")
                creationDate = datetime.strptime(creationDate, "%d-%m-%Y %H:%M:%S")
                creationDate = creationDate.strftime("%d/%m/%Y %H:%M:%S")
            else:
                continue
            
            content = f"{author} at {creationDate}\n{text}"
            
            formatted_note["title"] = note_title
            formatted_note["creation_date"] = creationDate
            formatted_note["phantom_case_id"] = phantom_case_id
            formatted_note["servicenow_case_id"] = servicenow_case_id
            formatted_note["author"] = author
            formatted_note["content"] = content
            formatted_note["raw_version"] = raw_work_note
            worknote_list.append({"note_info": formatted_note})
        data = worknote_list
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
