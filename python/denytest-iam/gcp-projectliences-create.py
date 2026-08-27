import google.auth
from googleapiclient.discovery import build

# Authenticate using your Google Cloud credentials
credentials, _ = google.auth.default()

# Specify the project ID and the resource ID (e.g., a project or folder) you want to attach the lien to
project_id = 'your-project-id'
resource_id = 'projects/your-project-id'  # You can use 'projects/PROJECT_ID' for projects

# Create the Resource Manager API client
service = build('cloudresourcemanager', 'v1', credentials=credentials)

# Define the lien body
lien_body = {
    "parent": resource_id,
    "reason": "Example Lien",
    "restrictions": [
        {
            "key": "example-key",
            "values": ["example-value"],
        },
    ],
}

try:
    # Create the lien using the liens.create method
    lien = service.liens().create(body=lien_body).execute()
    print(f"Lien created successfully: {lien['name']}")
except Exception as e:
    print(f"Error creating lien: {e}")
