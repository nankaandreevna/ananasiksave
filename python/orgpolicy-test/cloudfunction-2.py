from google.cloud import functions_v1

def create_cloud_function(project_id, location, function_name):
    # Create a Cloud Functions client
    client = functions_v1.CloudFunctionsServiceClient()

    # Define the Cloud Function details
    function = {
        "name": f"projects/{project_id}/locations/{location}/functions/{function_name}",
        "entry_point": "hello_http",  # Python function entry point
        "runtime": "python38",  # Python runtime version
        "trigger": {
            "httpsTrigger": {}  # HTTP-triggered function
        },
        "source_archive_url": "gs://cloud-functions-source-code/function_source.zip",  # Replace with your function's source code ZIP
    }

    try:
        # Create the Cloud Function
        response = client.create_function(location=f"projects/{project_id}/locations/{location}", function=function)
        print(f"Cloud Function '{function_name}' created: {response}")

    except Exception as e:
        print(f"Error: {e}")
        print(f"Failed to create the '{function_name}' Cloud Function.")

# Replace with your GCP project details and Cloud Function name
project_id = 'YOUR_PROJECT_ID'
location = 'us-central1'
function_name = 'YOUR_FUNCTION_NAME'

# Run the function to create a Cloud Function
create_cloud_function(project_id, location, function_name)
