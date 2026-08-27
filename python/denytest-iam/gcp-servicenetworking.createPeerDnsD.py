from google.cloud import service_networking_v1

def create_peered_dns_domain(project_id, network_name, registration_domain, zone_name, description=None):
    client = service_networking_v1.ServiceNetworkingClient()

    parent = f"projects/{project_id}/global/networks/{network_name}"

    peered_dns_domain = {
        "dns_suffix": registration_domain,
        "description": description,
        "dns_peering_zone": zone_name
    }

    response = client.create_peered_dns_domain(parent=parent, peered_dns_domain=peered_dns_domain)

    print("Peered DNS Domain created:")
    print(f"DNS Suffix: {response.dns_suffix}")
    print(f"Description: {response.description}")
    print(f"DNS Peering Zone: {response.dns_peering_zone}")

# Usage example
project_id = "your-project-id"
network_name = "your-network-name"
registration_domain = "example.com"
zone_name = "us-central1-a"

create_peered_dns_domain(project_id, network_name, registration_domain, zone_name, description="Example DNS Domain")
