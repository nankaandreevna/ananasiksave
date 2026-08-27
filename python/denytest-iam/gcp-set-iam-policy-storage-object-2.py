from google.cloud import storage

def set_iam_policy(bucket_name, object_name, policy):
    # Instantiate a client
    client = storage.Client()

    # Get the bucket
    bucket = client.get_bucket(bucket_name)

    # Get the blob object
    blob = bucket.blob(object_name)

    # Get the current IAM policy
    current_policy = blob.iam_policy

    # Set the desired IAM policy
    updated_policy = current_policy.copy()
    updated_policy.bindings = policy

    # Update the IAM policy on the object
    blob.patch()

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
