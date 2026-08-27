from google.cloud import storage
from google.cloud.storage import Bucket
from google.cloud.iam import Policy

# Initialize the client
client = storage.Client()

# Get the bucket
bucket_name = 'your-bucket-name'
bucket: Bucket = client.bucket(bucket_name)

# Get the current IAM policy
policy = bucket.get_iam_policy()

# Add a new member to the policy
member = 'user:example@gmail.com'
role = 'roles/storage.objectViewer'
policy.bindings.append(Policy.Binding(member, [role]))

# Set the new IAM policy on the bucket
bucket.set_iam_policy(policy)

print(f"IAM policy set on bucket {bucket_name}")
