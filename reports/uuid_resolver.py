import json, requests, os, base64
import re
import time

def decode_base64_url(data):
    # Decode base64url
    rem = len(data) % 4
    if rem > 0:
        data += '=' * (4 - rem)
    return base64.urlsafe_b64decode(data)

def decode_jwt(jwt):
    # Decode JWT without validating
    parts = jwt.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    # Decode the payload
    payload_enc = parts[1]
    payload_data = decode_base64_url(payload_enc)
    payload = json.loads(payload_data)

    return payload

def get_access_token(base_url, ws_token):
    username = 'apitoken'
    url = base_url + '/services/mtm/v1/oauth2/token'
    headers = {
        'User-Agent': 'TomGuttermann-UUIDResolver@LeanIX',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    data = {
        'grant_type': 'client_credentials'
    }

    auth = requests.auth.HTTPBasicAuth(username, ws_token)
    response = requests.post(url, headers=headers, data=data, auth=auth)
    
    if response.status_code == 200:
        return response.json().get('access_token')
    else:
        raise Exception(f"Could not get access_token. Status: {response.status_code} Message: {response.text}")

def count_uuids(data):
    count = 0
    if isinstance(data, dict):
        for value in data.values():
            if isinstance(value, (dict, list)):
                count += count_uuids(value)
            elif isinstance(value, str) and is_uuid(value):
                count += 1
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, (dict, list)):
                count += count_uuids(item)
            elif isinstance(item, str) and is_uuid(item):
                count += 1
    return count

def resolve_uuid(uuid, retries=10, wait=10):
    global resolution_count, error_count, total_uuids
    current_item = resolution_count + error_count + 1
    url = base_url + '/services/pathfinder/v1/graphql'
    query = f"""
            {{
                factSheet(id: "{uuid}") {{
                    name
                    type
                }}
            }}
            """

    headers = {
        "Authorization": "Bearer " + access_token,
        "Content-Type": "application/json",
        'User-Agent': 'TomGuttermann-UUIDResolver@LeanIX',
    }

    for attempt in range(retries):
        try:
            response = requests.post(url, json={'query': query}, headers=headers)
            response.raise_for_status()  # Raises HTTPError for 4xx and 5xx responses

            response_data = response.json()
            if response.status_code == 200:
                if 'errors' in response_data:
                    print(f"({current_item}/{total_uuids}) | Could not resolve UUID: {uuid}")
                    error_count += 1
                    return uuid  # Return UUID if there are errors in the response
                else:
                    resolvedString = f"{response_data['data']['factSheet']['type']}: {response_data['data']['factSheet']['name']}"
                    print(f"({current_item}/{total_uuids}) | UUID: {uuid} resolved to: {resolvedString}")
                    resolution_count += 1
                    return resolvedString

        except requests.exceptions.HTTPError:
            if response.status_code == 429:
                print(f"WARNING: Too many requests. Waiting {wait} seconds before retrying...")
                time.sleep(wait)
            else:
                # For other HTTP errors, exit the loop and proceed to raise an exception
                break
        except requests.exceptions.RequestException as req_err:
            print(f"Request error occurred: {req_err}. Waiting {wait} seconds before retrying...")
            time.sleep(wait)

    # If the function reaches this point, it means all retries have been exhausted
    error_count += 1
    raise Exception(f"Failed to resolve UUID {uuid} after {retries} attempts.")

def is_uuid(value):
    # A simple check to identify UUIDs. You might need to adjust the regex pattern based on your UUID format.
    return bool(re.match(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', value))

def contains_uuid(obj):
    obj_str = json.dumps(obj)  # Convert the object to a JSON string
    # Search for UUID patterns in the string
    return bool(re.search(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', obj_str))

def extract_and_resolve(data):
    if isinstance(data, dict):
        for key, value in list(data.items()):  # Use list to avoid dictionary size change during iteration
            if isinstance(value, (dict, list)):
                extract_and_resolve(value)
            elif isinstance(value, str) and is_uuid(value):
                resolved_value = resolve_uuid(value)
                if resolved_value != value:  # If resolution was successful
                    if key == "id":
                        # Replace the 'id' key with 'name'
                        data.pop("id")
                        data["name"] = resolved_value
                    else:
                        data[key] = resolved_value
    elif isinstance(data, list):
        for i, item in enumerate(data):
            if isinstance(item, (dict, list)):
                extract_and_resolve(item)
            elif isinstance(item, str) and is_uuid(item):
                data[i] = resolve_uuid(item)

def resolve_uuids_from_bookmark_objects(baseUrl, accessToken, bookmark_objects):
    global base_url, access_token
    global resolution_count, error_count, total_uuids
    resolution_count = 0
    error_count = 0
    base_url = baseUrl
    access_token = accessToken

    # Count total UUIDs before starting
    total_uuids = count_uuids(bookmark_objects)
    print(f"\nStarting UUID resolution process... (Total UUIDs to resolve: {total_uuids})")
    extract_and_resolve(bookmark_objects)
    print(f"\nUUID resolution completed:")
    print(f"- Successfully resolved: {resolution_count}/{total_uuids}")
    print(f"- Failed to resolve: {error_count}/{total_uuids}")

def initialize_workspace(instance, ws_token):
    """Initialize workspace and get access token"""
    base_url = f"https://{instance}.leanix.net"
    access_token = get_access_token(base_url, ws_token)
    decoded_payload = decode_jwt(access_token)
    base_url = decoded_payload['instanceUrl']
    workspace_name = decoded_payload['principal']['permission']['workspaceName']
    print(f"Initialized workspace: {workspace_name}")
    return base_url, access_token

def process_input_file(input_file, output_file, instance, ws_token):
    """Process input JSON file and resolve UUIDs"""
    # Initialize workspace
    base_url, access_token = initialize_workspace(instance, ws_token)
    
    # Read input file
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    # Resolve UUIDs
    resolve_uuids_from_bookmark_objects(base_url, access_token, [data])
    
    # Write output
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)

def main():
    instance = "demo-eu-1"
    print(f"Using LeanIX instance: {instance} (can be changed in the code if incorrect)")
    ws_token = input("Please enter your workspace token: ").strip()
    
    if not instance or not ws_token:
        print("Error: Instance and workspace token are required")
        return
    
    input_file = "input.json"
    output_file = "output.json"
    
    try:
        process_input_file(input_file, output_file, instance, ws_token)
        print(f"Successfully processed {input_file} and saved results to {output_file}")
    except Exception as e:
        print(f"Error processing file: {e}")

if __name__ == "__main__":
    main()