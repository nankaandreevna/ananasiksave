from google.cloud import storage
from google.cloud.iam import Policy

def update_iam_policy(bucket_name, object_name, policy):
    # Instantiate a client
    client = storage.Client()

    # Get the bucket
    bucket = client.get_bucket(bucket_name)

    # Get the blob object
    blob = bucket.blob(object_name)

    # Get the current IAM policy
    current_policy = blob.get_iam_policy(requested_policy_version=3)

    # Update the IAM policy bindings
    current_policy.bindings = policy

    # Set the updated IAM policy
    blob.set_iam_policy(current_policy)

    print(f"IAM policy updated for object {object_name} in bucket {bucket_name}.")

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

update_iam_policy(bucket_name, object_name, policy)
