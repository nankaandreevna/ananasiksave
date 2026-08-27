import re

error_message = "400 The request has violated one or more Org Policies. Please refer to the respective violations for more information. [violations {\n"\
                "type: \"constraints/cloudfunctions.allowed/pcConnectorEgressSettings\"\n"\
                "subject: \"orgpolicy:projects/pri-iam-denytest\"\n"\
                "description: *Constraint constraints/cloudfunctions. allowed/pcConnectorEgresssettings violated for projects/prj-iam-denytest attempting CreateFunctionActionV with vpc_connector _egress _detting\n"\
                "5 set to VPC CONNECTOR EGRESS SETTINGS UNSPECIFIED. See https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints for more information.\"\n"\
                "description: *Another description field\n"\
                "}] ** message-> The request has violated one or more Org Policies. Please refer to the respective violations for more information."

# Using regular expression to find all description fields
description_pattern = r"description: \"(.*?)\""
description_matches = re.findall(description_pattern, error_message)
if description_matches:
    for index, description_value in enumerate(description_matches, start=1):
        print(f"Description {index}: {description_value}")
else:
    print("No description fields found.")




##########


import re

error_message = "400 The request has violated one or more Org Policies. Please refer to the respective violations for more information. [violations {\n"\
                "type: \"constraints/cloudfunctions.allowed/pcConnectorEgressSettings\"\n"\
                "subject: \"orgpolicy:projects/pri-iam-denytest\"\n"\
                "description: *Constraint constraints/cloudfunctions. allowed/pcConnectorEgresssettings violated for projects/prj-iam-denytest attempting CreateFunctionActionV with vpc_connector _egress _detting\n"\
                "5 set to VPC CONNECTOR EGRESS SETTINGS UNSPECIFIED. See https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints for more information.\"\n"\
                "description: *Another description field\n"\
                "}] ** message-> The request has violated one or more Org Policies. Please refer to the respective violations for more information."

description_matches = re.findall(r"description: \"(.*?)\"", error_message)
description_list = []

for index, description_value in enumerate(description_matches, start=1):
    variable_name = f"description_{index}"
    description_list.append({variable_name: description_value})

# Print the created variables
for item in description_list:
    for key, value in item.items():
        print(f"{key}: {value}")


###########


import re
from behave import given

# Sample error message
error_message = "400 The request has violated one or more Org Policies. Please refer to the respective violations for more information. [violations {\n"\
                "type: \"constraints/cloudfunctions.allowed/pcConnectorEgressSettings\"\n"\
                "subject: \"orgpolicy:projects/pri-iam-denytest\"\n"\
                "description: *Constraint constraints/cloudfunctions. allowed/pcConnectorEgresssettings violated for projects/prj-iam-denytest attempting CreateFunctionActionV with vpc_connector _egress _detting\n"\
                "5 set to VPC CONNECTOR EGRESS SETTINGS UNSPECIFIED. See https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints for more information.\"\n"\
                "description: *Another description field\n"\
                "}] ** message-> The request has violated one or more Org Policies. Please refer to the respective violations for more information."

description_matches = re.findall(r"description: \"(.*?)\"", error_message)
context.error_message = []

for index, description_value in enumerate(description_matches, start=1):
    context.error_message.append(description_value)

# Print context.error_message (optional)
print(context.error_message)



#--------------------------

from google.api_core.exceptions import GoogleAPIError
import json

try:
    # Your API call that might raise a GoogleAPIError
    # For example:
    # response = make_api_call()
    # (where make_api_call() might raise a GoogleAPIError)

    pass  # Placeholder for your API call

except GoogleAPIError as err:
    # Extract the error details
    error_message = str(err)
    error_details = err.error_details if hasattr(err, 'error_details') else None

    # Accessing the description from the error_details
    if error_details:
        for detail in error_details:
            if 'description' in detail:
                description = detail['description']
                print("Description:", description)

    # Logging the error message and description
    LOGGER.info(f"Exception happened with GoogleAPIError {error_message} ** message-> {description if 'description' in locals() else None}")
