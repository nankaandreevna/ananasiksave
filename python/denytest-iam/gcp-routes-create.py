from google.cloud import compute_v1

def create_route(project_id, network_name, route_name, destination_range, next_hop_ip):
    compute_client = compute_v1.RoutesClient()

    # Construct the route resource
    route = compute_v1.Route(
        name=route_name,
        network=network_name,
        dest_range=destination_range,
        next_hop_ip=next_hop_ip
    )

    # Send the API request to create the route
    operation = compute_client.insert(project=project_id, route=route)
    operation.result()

    print(f"Route '{route_name}' created successfully.")

# Example usage
project_id = "your-project-id"
network_name = "your-network-name"
route_name = "your-route-name"
destination_range = "10.0.0.0/24"  # Destination IP range for the route
next_hop_ip = "10.0.0.1"  # Next hop IP address for the route

create_route(project_id, network_name, route_name, destination_range, next_hop_ip)
