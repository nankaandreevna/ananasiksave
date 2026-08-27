from google.cloud import compute_v1
from google.protobuf import duration_pb2
from google.protobuf.json_format import ParseDict

def set_subnetwork_iam_policy(project_id, region, subnetwork_name, policy):
    # Create the subnetworks client
    subnetworks_client = compute_v1.SubnetworksClient()

    # Get the subnetwork resource URL
    subnetwork_url = f"projects/{project_id}/regions/{region}/subnetworks/{subnetwork_name}"

    # Create the policy protobuf object from the provided policy dictionary
    policy_pb = ParseDict(policy, compute_v1.Policy())

    # Create the request object
    request = compute_v1.SetIamPolicySubnetworkRequest(
        resource=subnetwork_url,
        region=region,
        region_set_policy_request=compute_v1.RegionSetPolicyRequest(policy=policy_pb),
        request_id=str(duration_pb2.Duration(seconds=0)),
    )

    # Send the API request to set the IAM policy
    response = subnetworks_client.set_iam_policy(request=request)

    print(f"IAM policy set for subnetwork '{subnetwork_name}'.")

# Example usage
project_id = "your-project-id"
region = "us-central1"
subnetwork_name = "your-subnetwork-name"
policy = {
    "bindings": [
        {
            "role": "roles/compute.networkUser",
            "members": [
                "user:example@example.com"
            ]
        }
    ]
}

set_subnetwork_iam_policy(project_id, region, subnetwork_name, policy)
