# This snippet has been automatically generated and should be regarded as a
# code template only.
# It will require modifications to work:
# - It may require correct/in-range values for request initialization.
# - It may require specifying regional endpoints when creating the service
#   client as shown in:
#   https://googleapis.dev/python/google-api-core/latest/client_options.html
from google.cloud import functions_v1

def sample_generate_download_url():
    # Create a client
    client = functions_v1.CloudFunctionsServiceClient()

    # Initialize request argument(s)
    request = functions_v1.GenerateDownloadUrlRequest(
    )

    # Make the request
    response = client.generate_download_url(request=request)

    # Handle the response
    print(response)