# note-commands for GCP IAM

## Deny supported permissions:
https://cloud.google.com/iam/docs/deny-permissions-support

## Cloud Functions 

Deny test for 
1. cloudfunctions.functions.sourceCodeGet
Method: projects.locations.functions.generateDownloadUrl   --->  cloudfunctions.functions.sourceCodeGet
Reference to method: https://cloud.google.com/functions/docs/reference/rest/v2beta/projects.locations.functions/generateDownloadUrl
Python reference: https://cloud.google.com/python/docs/reference/cloudfunctions/latest/google.cloud.functions_v1.services.cloud_functions_service.CloudFunctionsServiceClient#google_cloud_functions_v1_services_cloud_functions_service_CloudFunctionsServiceClient_generate_download_url
parent = string

The project and location in which the Google Cloud Storage signed URL should be generated, specified in the format projects/*/locations/*.
It takes the form projects/{project}/locations/{location}.

2. cloudfunctions.functions.sourceCodeSet
Method: projects.locations.functions.generateUploadUrl   ---> cloudfunctions.functions.sourceCodeSet
Reference to method:  https://cloud.google.com/functions/docs/reference/rest/v1/projects.locations.functions/generateUploadUrl
Python reference: https://cloud.google.com/python/docs/reference/cloudfunctions/latest/google.cloud.functions_v1.services.cloud_functions_service.CloudFunctionsServiceClient#google_cloud_functions_v1_services_cloud_functions_service_CloudFunctionsServiceClient_generate_upload_url

parent = string

The project and location in which the Google Cloud Storage signed URL should be generated, specified in the format projects/*/locations/*.
It takes the form projects/{project}/locations/{location}.