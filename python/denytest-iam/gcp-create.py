from google.cloud import dns

def create_resource_record_set(project_id, zone_name, rrset_name, rrset_type, rrset_ttl, rrset_data):
    # Instantiates a client
    client = dns.Client(project=project_id)

    # Gets a zone object
    zone = client.zone(zone_name)

    # Creates a resource record set
    rrset = zone.resource_record_set(rrset_name, rrset_type, rrset_ttl, rrset_data)

    # Adds the resource record set to the zone
    changes = zone.changes()
    changes.add_additions(rrset)
    changes.create()

    # Waits for changes to complete
    while changes.status != 'done':
        changes.reload()
    
    print(f"Resource record set '{rrset_name}' created successfully.")
