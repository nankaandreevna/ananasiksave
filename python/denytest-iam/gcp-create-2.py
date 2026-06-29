from google.cloud import dns

def create_resource_record_set(project_id, zone_name, rrset_name, rrset_type, rrset_ttl, rrset_data):
    # Instantiates a client
    client = dns.Client(project=project_id)

    # Creates a resource record set
    rrset = client.resource_record_sets(zone_name).create(
        rrset_name,
        rrset_type,
        rrset_ttl,
        rrset_data
    )

    print(f"Resource record set '{rrset_name}' created successfully.")
