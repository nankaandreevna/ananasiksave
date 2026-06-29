from googleapiclient.discovery import build
from google.oauth2 import service_account

def enable_service(service_name, project_id):
    credentials = service_account.Credentials.from_service_account_file(
        'path/to/service_account.json'
    )

    service = build('servicemanagement', 'v1', credentials=credentials)

    service_name = f"projects/{project_id}/services/{service_name}"

    service_config = {
        'consumerConfig': {
            'minConcurrentRequests': 1,
            'maxConcurrentRequests': 1
        }
    }

    enable_request = service.services().enable(
        serviceName=service_name, body=service_config
    )

    response = enable_request.execute()

    print(f"Service '{service_name}' enabled for project '{project_id}'.")
