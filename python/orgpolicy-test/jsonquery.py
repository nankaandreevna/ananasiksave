from google.api_core.exceptions import GoogleAPIError
import re

try:
    # Your API call that might raise a GoogleAPIError
    # For example:
    # response = make_api_call()
    # (where make_api_call() might raise a GoogleAPIError)

    pass  # Placeholder for your API call

except GoogleAPIError as err:
    error_message = str(err)
    LOGGER.info(f"Exception happened with GoogleAPIError {error_message} ** message-> {str(err.message)}")

    # Extract description using regex
    description_matches = re.findall(r"description: \"(.*?)\"", error_message)
    if description_matches:
        context.error_message = []  # Initializing error_message in context
        for index, description_value in enumerate(description_matches, start=1):
            context.error_message.append(description_value)

            # Remove 'In' from description if it exists
            context.error_message = [desc.replace('In', '') for desc in context.error_message]

            # You might want to handle further processing or logging here
