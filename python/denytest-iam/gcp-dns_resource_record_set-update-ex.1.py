from google.cloud import dns

def update_resource_record_set(project_id, zone_name, rrset_name, rrset_type, rrset_ttl, rrset_data):
    # create a client object
    client = dns.Client(project=project_id)

    # retrieve the DNS zone
    zone = client.zone(zone_name)

    # retrieve the resource record set to update
    rrset = zone.resource_record_set(rrset_name, rrset_type)

    # update the TTL and data of the resource record set
    rrset.ttl = rrset_ttl
    rrset.clear_data()
    rrset.add_data(rrset_data)

    # commit the changes
    zone.update(rrset)

    print(f"Resource record set {rrset_name} ({rrset_type}) updated successfully!")
# Here's an explanation of the arguments for the function:

# project_id: The ID of the Google Cloud project that contains the DNS zone.
# zone_name: The name of the DNS zone to update.
# rrset_name: The name of the resource record set to update (e.g. "example.com.").
# rrset_type: The type of the resource record set (e.g. "A", "CNAME", "MX").
# rrset_ttl: The Time-To-Live value to set for the resource record set (in seconds).
# rrset_data: The data for the resource record set (e.g. an IP address for an "A" record, a domain name for a "CNAME" record).
# To use this function, you would call it with the appropriate arguments, like this:

# python
# Copy code
# project_id = "my-project-id"
# zone_name = "example-com"
# rrset_name = "www.example.com."
# rrset_type = "A"
# rrset_ttl = 300
# rrset_data = "192.0.2.1"

# update_resource_record_set(project_id, zone_name, rrset_name, rrset_type, rrset_ttl, rrset_data)
# This would update the "www.example.com" A record in


project_id = "my-project-id"
zone_name = "example-com"
rrset_name = "www.example.com."
rrset_type = "A"
rrset_ttl = 300
rrset_data = "192.0.2.1"

update_resource_record_set(project_id, zone_name, rrset_name, rrset_type, rrset_ttl, rrset_data)
