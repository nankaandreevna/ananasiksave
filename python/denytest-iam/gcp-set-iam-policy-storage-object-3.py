from google.cloud import storage

def update_iam_policy(bucket_name, object_name, policy):
    # Instantiate a client
    client = storage.Client()

    # Get the bucket
    bucket = client.get_bucket(bucket_name)

    # Get the blob object
    blob = bucket.blob(object_name)

    # Update the IAM policy for the object
    blob.acl.reload()
    current_policy = blob.acl
    current_policy.versioned_policy(policy)

    # Save the updated policy
    blob.acl.save()

    print(f"IAM policy updated for object {object_name} in bucket {bucket_name}.")

# Usage
bucket_name = 'your-bucket-name'
object_name = 'your-object-name'
policy = {
    "bindings": [
        {
            "role": "roles/storage.objectViewer",
            "members": ["user:example@example.com"]
        },
        {
            "role": "roles/storage.objectAdmin",
            "members": ["user:admin@example.com"]
        }
    ]
}

update_iam_policy(bucket_name, object_name, policy)
