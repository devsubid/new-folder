# hubspot.py

import json
import secrets
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
import httpx
import asyncio
import base64
import hashlib
import requests

from integrations.integration_item import IntegrationItem
from redis_client import add_key_value_redis, get_value_redis, delete_key_redis

# HubSpot OAuth credentials
# You need to create a HubSpot app and get these credentials
# https://developers.hubspot.com/docs/api/oauth-quickstart
CLIENT_ID = 'your-hubspot-client-id'
CLIENT_SECRET = 'your-hubspot-client-secret'
REDIRECT_URI = 'http://localhost:8000/integrations/hubspot/oauth2callback'
authorization_url = f'https://app.hubspot.com/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=contacts%20crm.objects.contacts.read%20crm.objects.companies.read'

async def authorize_hubspot(user_id, org_id):
    """
    Initiates the OAuth flow for HubSpot
    """
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode('utf-8')).decode('utf-8')
    
    auth_url = f'{authorization_url}&state={encoded_state}'
    await add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', json.dumps(state_data), expire=600)
    
    return auth_url

async def oauth2callback_hubspot(request: Request):
    """
    Handles the OAuth callback from HubSpot
    """
    if request.query_params.get('error'):
        raise HTTPException(status_code=400, detail=request.query_params.get('error_description'))
    
    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')
    state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode('utf-8'))
    
    original_state = state_data.get('state')
    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')
    
    saved_state = await get_value_redis(f'hubspot_state:{org_id}:{user_id}')
    
    if not saved_state:
        raise HTTPException(status_code=400, detail='State not found or expired')
    
    saved_state = json.loads(saved_state)
    if saved_state.get('state') != original_state:
        raise HTTPException(status_code=400, detail='State mismatch')
    
    # Exchange code for access token
    token_url = 'https://api.hubapi.com/oauth/v1/token'
    data = {
        'grant_type': 'authorization_code',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI,
        'code': code
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(token_url, data=data)
    
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail='Failed to get access token')
    
    token_data = response.json()
    
    # Store the credentials
    credentials = {
        'access_token': token_data.get('access_token'),
        'refresh_token': token_data.get('refresh_token'),
        'expires_in': token_data.get('expires_in'),
        'token_type': token_data.get('token_type')
    }
    
    await add_key_value_redis(f'hubspot_credentials:{org_id}:{user_id}', json.dumps(credentials), expire=600)
    
    # Return a success page
    html_content = """
    <html>
        <head>
            <title>HubSpot Integration Success</title>
            <script>
                window.onload = function() {
                    window.close();
                }
            </script>
        </head>
        <body>
            <h1>HubSpot Integration Successful!</h1>
            <p>You can close this window now.</p>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content)

async def get_hubspot_credentials(user_id, org_id):
    """
    Retrieves the stored HubSpot credentials
    """
    credentials = await get_value_redis(f'hubspot_credentials:{org_id}:{user_id}')
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found.')
    
    credentials = json.loads(credentials)
    await delete_key_redis(f'hubspot_credentials:{org_id}:{user_id}')
    
    return credentials

def create_integration_item_metadata_object(response_json, item_type, parent_id=None, parent_name=None) -> IntegrationItem:
    """
    Creates an integration metadata object from the response
    """
    parent_id = None if parent_id is None else parent_id
    integration_item_metadata = IntegrationItem(
        id=response_json.get('id', None),
        name=response_json.get('properties', {}).get('name', None) or response_json.get('name', None),
        type=item_type,
        parent_id=parent_id,
        parent_path_or_name=parent_name,
    )
    
    return integration_item_metadata

async def get_items_hubspot(credentials) -> list[IntegrationItem]:
    """
    Retrieves contacts and companies from HubSpot
    """
    credentials = json.loads(credentials)
    access_token = credentials.get('access_token')
    
    list_of_integration_item_metadata = []
    
    # Get contacts
    contacts_url = 'https://api.hubapi.com/crm/v3/objects/contacts'
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    contacts_response = requests.get(contacts_url, headers=headers)
    if contacts_response.status_code == 200:
        contacts_data = contacts_response.json()
        for contact in contacts_data.get('results', []):
            list_of_integration_item_metadata.append(
                create_integration_item_metadata_object(contact, 'Contact')
            )
    
    # Get companies
    companies_url = 'https://api.hubapi.com/crm/v3/objects/companies'
    companies_response = requests.get(companies_url, headers=headers)
    if companies_response.status_code == 200:
        companies_data = companies_response.json()
        for company in companies_data.get('results', []):
            list_of_integration_item_metadata.append(
                create_integration_item_metadata_object(company, 'Company')
            )
    
    return list_of_integration_item_metadata