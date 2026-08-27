from google.cloud import compute_v1

def create_vpn_tunnel(project_id, region, tunnel_name, peer_ip, shared_secret):
    client = compute_v1.TunnelsClient()

    # Construct the VPN tunnel resource
    tunnel = compute_v1.VpnTunnel(
        name=tunnel_name,
        region=region,
        peer_ip=peer_ip,
        shared_secret=shared_secret,
        ike_version=2,
        target_vpn_gateway="projects/{0}/regions/{1}/targetVpnGateways/{2}".format(
            project_id, region, "your-target-vpn-gateway"
        ),
        # Add other properties as needed (e.g., IKE version, routing options, etc.)
    )

    # Create the VPN tunnel
    operation = client.insert(project=project_id, region=region, vpn_tunnel_resource=tunnel)

    # Wait for the operation to complete
    operation.result()

    print(f'VPN tunnel {tunnel_name} created successfully.')

# Usage example
project_id = 'your-project-id'
region = 'your-region'
tunnel_name = 'your-tunnel-name'
peer_ip = 'your-peer-ip-address'
shared_secret = 'your-shared-secret'

create_vpn_tunnel(project_id, region, tunnel_name, peer_ip, shared_secret)
