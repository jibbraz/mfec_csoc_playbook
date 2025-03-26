def generate_phantom_and_servicenow_diff_report(comparison_result=None, **kwargs):
    """
    Return a summarization of mismatched field from both Phantom and ServiceNow
    (string)
    
    Args:
        comparison_result
    
    Returns a JSON-serializable object that implements the configured data paths:
        success
        data
        error_msg
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    result = {}
    success = True
    data = ""
    error_msg = ""

    try:
        # Get case ID
        phantom_case_id = comparison_result.get("phantom_case_id", None)
        servicenow_case_id = comparison_result.get("servicenow_case_id", None)
        servicenow_case_number = comparison_result.get("servicenow_case_number", None)
        phantom_case_name = comparison_result.get("phantom_case_name", None)
        
        originate = comparison_result.get("originate", None)
        
        # Check if any diff
        phantom_based_diff = comparison_result.get("phantom_based_diff", False)
        servicenow_based_diff = comparison_result.get("servicenow_based_diff", False)
        has_diff = "No"
        if phantom_based_diff or servicenow_based_diff:
            has_diff = "Yes"
        
        # Get diff field and value
        phantom_based_field = comparison_result.get("phantom_override_field", [])
        phantom_based_field_count = len(phantom_based_field)
        servicenow_based_field = comparison_result.get("servicenow_override_field", [])
        servicenow_based_field_count = len(servicenow_based_field)
        
        # Generate diff report
        field_info_template = "- {field_name}\n  Phantom is \"{phantom_value}\" and ServiceNow is \"{servicenow_value}\". Updated value on {destination} to \"{edited_value}\".\n"
        all_field = comparison_result.get("field", {})
        
        phantom_diff_report = ""
        for field_name in phantom_based_field:
            field_info = all_field.get(field_name, {})
            phantom_value = field_info.get("phantom", None)
            servicenow_value = field_info.get("servicenow", None)
            field_info_string = field_info_template.format(field_name=field_name, phantom_value=phantom_value, servicenow_value=servicenow_value, destination="ServiceNow", edited_value=phantom_value)
            phantom_diff_report += field_info_string
        
        servicenow_diff_report = ""
        for field_name in servicenow_based_field:
            field_info = all_field.get(field_name, {})
            phantom_value = field_info.get("phantom", None)
            servicenow_value = field_info.get("servicenow", None)
            field_info_string = field_info_template.format(field_name=field_name, phantom_value=phantom_value, servicenow_value=servicenow_value, destination="Phantom", edited_value=servicenow_value)
            servicenow_diff_report += field_info_string
        
        # summarize data
        data = f"""Phantom case ID: {phantom_case_id}
Case name: {phantom_case_name}
Linked with ServiceNow case number: {servicenow_case_number} (ID: {servicenow_case_id})
Created by: {originate}
Has a diff?: {has_diff}
Diff on Phantom based field
{phantom_based_field_count} field(s)
{phantom_diff_report}
Diff on ServiceNow based field
{servicenow_based_field_count} field(s)
{servicenow_diff_report}"""

    except Exception as e:
        success = False
        error_msg = f"Exception: {str(e)}"

    result["success"] = success
    result["data"] = data
    result["error_msg"] = error_msg
    
    assert json.dumps(result)
    phantom.debug(result)
    return result