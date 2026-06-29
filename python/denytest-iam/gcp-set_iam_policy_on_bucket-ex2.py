from google.cloud import storage

# Initialize the storage client
client = storage.Client()

# Get the bucket object
bucket = client.get_bucket('your-bucket-name')

# Define the IAM policy
policy = {
    "bindings": [
        {
            "role": "roles/storage.objectViewer",
            "members": [
                "user:example@gmail.com"
            ]
        }
    ]
}

# Set the IAM policy on the bucket
bucket.iam_configuration.policy = policy
bucket.iam_configuration.save()