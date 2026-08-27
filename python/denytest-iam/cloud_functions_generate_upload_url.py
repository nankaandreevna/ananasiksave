def sample_generate_upload_url():
    # Create a client
    client = functions_v1.CloudFunctionsServiceClient()

    # Initialize request argument(s)
    request = functions_v1.GenerateUploadUrlRequest(
    )

    # Make the request
    response = client.generate_upload_url(request=request)

    # Handle the response
    print(response)