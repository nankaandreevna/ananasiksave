from google.cloud import dns

def update_dns_record_patch(project_id, zone_name, record_name, record_type, record_ttl, record_data):
    """
    Updates a DNS resource record set in GCP Cloud DNS using the patch method.

    Args:
        project_id (str): The GCP project ID.
        zone_name (str): The name of the DNS zone in which the record set is located.
        record_name (str): The name of the record set to update (e.g., www.example.com).
        record_type (str): The type of the record set to update (e.g., A, CNAME, MX, etc.).
        record_ttl (int): The time-to-live (TTL) value for the record set (in seconds).
        record_data (list): A list of strings representing the new data for the record set.

    Returns:
        str: The response from the API call.
    """
    # Initialize the Cloud DNS client
    client = dns.Client(project=project_id)

    # Get the zone object
    zone = client.zone(zone_name)

    # Build the request body
    request_body = {
        "ttl": record_ttl,
        "rrdatas": record_data
    }

    # Patch the resource record set
    response = zone.resource_record_set(record_name, record_type).patch(request_body)

    return response
