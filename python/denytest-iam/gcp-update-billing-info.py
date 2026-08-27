from google.cloud import billing

def update_billing_info(project_id, account_id, billing_id):
    client = billing.CloudBillingClient()

    # Get the billing account
    billing_account_path = client.billing_account_path(project_id, billing_id)
    billing_account = client.get_billing_account(billing_account_path)

    # Update the account with new information
    billing_account.display_name = 'New Billing Account Name'
    billing_account.open = True
    billing_account.payment_account = '1234567890'  # Replace with your payment account ID

    # Update the billing account
    update_mask = {'paths': ['display_name', 'open', 'payment_account']}
    updated_account = client.update_billing_account(billing_account, update_mask)

    print(f'Updated billing account: {updated_account.name}')

# Usage example
project_id = 'your-project-id'
account_id = 'your-account-id'
billing_id = 'your-billing-account-id'

update_billing_info(project_id, account_id, billing_id)
