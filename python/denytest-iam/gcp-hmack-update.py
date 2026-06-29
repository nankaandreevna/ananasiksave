from google.cloud import iam

def update_hmac_key(project_id, access_id, state):
    client = iam.IAMClient()

    # Get the HMAC key metadata
    key_name = f'projects/{project_id}/serviceAccounts/{access_id}'
    key = client.get_service_account_key(name=key_name)

    # Update the state of the HMAC key
    key.state = state

    # Update the HMAC key
    updated_key = client.update_service_account_key(key)

    print(f'Updated HMAC key: {updated_key.name}')

# Usage example
project_id = 'your-project-id'
access_id = 'your-access-id'
state = 'DISABLED'  # New state for the HMAC key

update_hmac_key(project_id, access_id, state)
