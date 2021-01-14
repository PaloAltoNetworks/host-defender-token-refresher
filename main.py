import googleapiclient.discovery
import json
import requests
import base64
import os
from googleapiclient import discovery
from google.cloud import secretmanager_v1

#establish the secret id
secret_id = 'host-defender-gcp-secure-deployment'

#Add the address of your console
console_address = 'https://us-west1.cloud.twistlock.com/us-3-159237196/api/v1/authenticate/renew'

def refresh_token(event, context):
    """
    helper function to refresh defender token and store in secrets manager
    runs on a cron job (Cloud Scheduler) which triggers via pub/sub
    """

    # build client and vars
    secret_client = secretmanager_v1.SecretManagerServiceClient()
    project_id = os.environ['GCP_PROJECT']
    secret_parent = f'projects/{project_id}'
    secret_name = secret_parent + f'/secrets/{secret_id}'
    secret_version = secret_name + '/versions/latest'
    # fetch secret with current token
    secret_data = secret_client.access_secret_version(request={'name': secret_version})
    #print("DEBUG: ", secret_data)
    # decode and format
    payload = secret_data.payload.data.decode('UTF-8')
    current_token = 'Bearer ' + str(payload)
    headers = {'authorization': current_token}
    # request to refresh the token
    refresh_token = requests.get(console_address, headers=headers, verify=False)
    print("DEBUG: ", refresh_token)
    # load new token as json and encode
    response_data = json.loads(refresh_token.content)
    new_token = response_data['token'].encode('utf-8')
    # create new secret version with upadated token value
    parent = secret_client.secret_path(project_id, secret_id)
    response = secret_client.add_secret_version(
        request={"parent": parent, "payload": {"data": new_token}}
    )
    print("DEBUG: ", response)
    new_version_name = response.name

    # destroy old version(s)
    for version in secret_client.list_secret_versions(request={"parent": parent}):
        # skip over newly created version with updated token
        if version.name == new_version_name:
            continue
        # destroy enabled versions
        if str(version.state) == "State.ENABLED":
            print("DELETING: ", version.name, version.state)
            delete_secret = secret_client.destroy_secret_version(request={'name': version.name})
            print("SECRET VERSION DESTROYED: ", delete_secret)
