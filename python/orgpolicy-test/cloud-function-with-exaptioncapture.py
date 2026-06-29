from google.api_core.exceptions import GoogleAPIError
from google.cloud import functions_v1

def create_cloud_function_with_vpc(project_id, location, function_name, vpc_connector):
    # Create a Cloud Functions client
    client = functions_v1.CloudFunctionsServiceClient()

    # Construct the Cloud Function name
    function_full_name = f"projects/{project_id}/locations/{location}/functions/{function_name}"

    # Define the Cloud Function details including VPC settings
    function = {
        "name": function_full_name,
        "entry_point": "hello_http",  # Replace with your Python function entry point
        "runtime": "python38",  # Python runtime version
        "https_trigger": {},  # HTTP-triggered function
        "vpc_connector": vpc_connector,  # Replace with your VPC connector name
        "vpc_connector_egress_settings": "PRIVATE_RANGES_ONLY",  # VPC Connector egress settings
        # Replace with your function's source code ZIP in a GCS bucket
        "source_archive_url": "gs://cloud-functions-source-code/function_source.zip",
    }

    try:
        # Create the Cloud Function
        response = client.create_function(location=f"projects/{project_id}/locations/{location}", function=function)
        print(f"Cloud Function '{function_name}' created: {response}")

    except GoogleAPIError as e:
        # Handle Google API errors
        for error in e.errors:
            if error.get("violations"):
                for violation in error["violations"]:
                    if violation.get("type") == "constraints/cloudfunctions.requireVPCConnector":
                        print(f"Violation detected: {violation.get('description')}")
            else:
                print(f"Error: {e}")
                print(f"Failed to create the '{function_name}' Cloud Function.")
