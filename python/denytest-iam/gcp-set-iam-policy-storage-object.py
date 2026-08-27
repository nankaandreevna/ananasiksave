import google.auth
from googleapiclient import discovery

def set_iam_policy(bucket_name, object_name, policy):
    # Authenticate using your credentials
    credentials, project = google.auth.default()
    service = discovery.build('storage', 'v1', credentials=credentials)

    # Construct the resource URL
    resource = f"projects/{project}/buckets/{bucket_name}/objects/{object_name}"

    # Get the current IAM policy
    get_request = service.objects().getIamPolicy(resource=resource)
    current_policy = get_request.execute()

    # Set the desired IAM policy
    updated_policy = current_policy.copy()
    updated_policy['bindings'] = policy

    # Update the IAM policy on the object
    update_request = service.objects().setIamPolicy(resource=resource, body={'policy': updated_policy})
    update_request.execute()

    print(f"IAM policy set on object {object_name} in bucket {bucket_name}.")

# Usage
bucket_name = 'your-bucket-name'
object_name = 'your-object-name'
policy = [
    {
        "role": "roles/storage.objectViewer",
        "members": ["user:example@example.com"]
    },
    {
        "role": "roles/storage.objectAdmin",
        "members": ["user:admin@example.com"]
    }
]

set_iam_policy(bucket_name, object_name, policy)
