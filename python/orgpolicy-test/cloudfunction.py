from google.cloud import functions_v1

def create_function_with_ingress_settings():
    client = functions_v1.CloudFunctionsServiceClient()

    # Replace these with your function details
    project_id = "your-project-id"
    location = "us-central1"
    function_id = "your-function-id"
    entry_point = "your_entry_point_function"  # Replace with your function's entry point
    runtime = "python38"  # Change according to your function's runtime
    source_dir = "path_to_your_function_code_directory"  # Replace with your function's source code directory

    # Define the ingress settings
    ingress_setting = functions_v1.AllowedIngressSettings(
        all_ingress_settings=True
    )  # Set the allowed ingress settings

    # Create the function with ingress settings
    response = client.create_function(
        location=location,
        function={"name": function_id, "entryPoint": entry_point, "runtime": runtime},
        source_archive_url=source_dir,
        allowed_ingress=ingress_setting  # Set the allowed ingress settings
    )

    print("Created function:", response)

# Call the function to create Cloud Function with specified ingress settings
create_function_with_ingress_settings()
