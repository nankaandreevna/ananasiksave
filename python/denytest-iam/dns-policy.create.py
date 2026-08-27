from google.cloud import dns

def create_dns_policy(project_id, policy_name, alternative_dns_servers):
    client = dns.Client(project=project_id)

    # Prepare the DNS zone request
    zone = client.zone(policy_name)

    # Create the DNS policy using the zone object
    policy = zone.policy()
    policy.alternative_name_server_configs = alternative_dns_servers

    # Create the DNS policy
    policy.create()

    print(f"DNS policy '{policy_name}' created successfully.")

# Provide your project ID, policy name, and alternative DNS servers
project_id = "your-project-id"
policy_name = "your-policy-name"
alternative_dns_servers = [
    dns.PolicyAlternativeNameServerConfig(
        target_name_server=dns.TargetNameServer(
            ipv4_address="8.8.8.8"
        ),
        forwarding_zone_name="example.com."
    ),
    dns.PolicyAlternativeNameServerConfig(
        target_name_server=dns.TargetNameServer(
            ipv4_address="8.8.4.4"
        ),
        forwarding_zone_name="example.net."
    )
]

create_dns_policy(project_id, policy_name, alternative_dns_servers)
