#!/usr/bin/env python3

import os
import re
import sys

import requests


def get_jamf_token(instance_url, client_id, client_secret):

    response = requests.post(
        f'{instance_url}/api/oauth/token',
        data={
            'client_id': client_id,
            'client_secret': client_secret,
            'grant_type': 'client_credentials'
        },
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    
    if response.status_code != 200:
        raise Exception(f'Authentication failed: {response.status_code}')
    
    return response.json()['access_token']


def get_cloud_idps(instance_url, token):

    response = requests.get(
        f'{instance_url}/api/v1/cloud-idp',
        headers={'Authorization': f'Bearer {token}'}
    )
    
    if response.status_code != 200:
        raise Exception(f'Failed to fetch cloud IDPs: {response.status_code}')
    
    return response.json().get('results', [])


def clean_name(name):

    cleaned = name.lower()
    cleaned = re.sub(r'[^a-z0-9_]', '_', cleaned)
    cleaned = re.sub(r'_+', '_', cleaned)
    cleaned = cleaned.strip('_')
    
    if cleaned[0].isdigit():
        cleaned = f'idp_{cleaned}'
    
    return cleaned


def write_terraform_imports(idps, output_file='terraform_imports.tf'):

    if not idps:
        print('No cloud identity providers to export')
        return
    
    with open(output_file, 'w') as f:
        f.write('# Jamf Pro Cloud Identity Provider Import Blocks\n')
        f.write('# Run: terraform plan -generate-config-out=generated.tf\n\n')
        
        for idp in idps:
            idp_id = idp.get('id')
            idp_name = idp.get('displayName', f'idp_{idp_id}')
            resource_name = clean_name(idp_name)
            
            f.write(f'import {{\n')
            f.write(f'  to = jamfpro_cloud_identity_provider.{resource_name}\n')
            f.write(f'  id = "{idp_id}"\n')
            f.write(f'}}\n\n')
    
    print(f'Wrote {len(idps)} import blocks to {output_file}')


def main():
    instance_url = os.getenv('JAMF_INSTANCE_URL')
    client_id = os.getenv('JAMF_CLIENT_ID')
    client_secret = os.getenv('JAMF_CLIENT_SECRET')
    
    if not all([instance_url, client_id, client_secret]):
        print('Error: Missing environment variables')
        print('Required: JAMF_INSTANCE_URL, JAMF_CLIENT_ID, JAMF_CLIENT_SECRET - go and create a .env file!')
        sys.exit(1)
    
    instance_url = instance_url.rstrip('/')
    
    try:
        print(f'Connecting to {instance_url}...')
        token = get_jamf_token(instance_url, client_id, client_secret)
        
        print('Fetching cloud identity providers...')
        idps = get_cloud_idps(instance_url, token)
        
        if idps:
            print(f'Found {len(idps)} cloud identity provider(s):')
            for idp in idps:
                print(f"  - {idp.get('displayName')} (ID: {idp.get('id')})")
        
        write_terraform_imports(idps)
        
        print('\nNext steps:')
        print('1. terraform init')
        print('2. terraform plan -generate-config-out=generated.tf')

        
    except Exception as e:
        print(f'Error: {e}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()