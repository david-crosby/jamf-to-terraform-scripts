#!/usr/bin/env python3

import argparse
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


def get_static_computer_groups(instance_url, token):
    response = requests.get(
        f'{instance_url}/api/v2/computer-groups/static-groups',
        headers={'Authorization': f'Bearer {token}'}
    )

    if response.status_code != 200:
        raise Exception(f'Failed to fetch static computer groups: {response.status_code}')

    return response.json().get('results', [])


def get_smart_computer_groups(instance_url, token):
    response = requests.get(
        f'{instance_url}/api/v2/computer-groups/smart-groups',
        headers={'Authorization': f'Bearer {token}'}
    )

    if response.status_code != 200:
        raise Exception(f'Failed to fetch smart computer groups: {response.status_code}')

    return response.json().get('results', [])


def get_extension_attributes(instance_url, token):
    response = requests.get(
        f'{instance_url}/api/v1/computer-extension-attributes',
        headers={'Authorization': f'Bearer {token}'}
    )

    if response.status_code != 200:
        raise Exception(f'Failed to fetch extension attributes: {response.status_code}')

    return response.json().get('results', [])


def get_scripts(instance_url, token):
    response = requests.get(
        f'{instance_url}/api/v1/scripts',
        headers={'Authorization': f'Bearer {token}'}
    )

    if response.status_code != 200:
        raise Exception(f'Failed to fetch scripts: {response.status_code}')

    return response.json().get('results', [])


def get_extension_attribute_details(instance_url, token, ea_id):
    response = requests.get(
        f'{instance_url}/api/v1/computer-extension-attributes/{ea_id}',
        headers={'Authorization': f'Bearer {token}'}
    )

    if response.status_code != 200:
        return None

    return response.json()


def get_script_details(instance_url, token, script_id):
    response = requests.get(
        f'{instance_url}/api/v1/scripts/{script_id}',
        headers={'Authorization': f'Bearer {token}'}
    )

    if response.status_code != 200:
        return None

    return response.json()


def clean_name(name):
    cleaned = name.lower()
    cleaned = re.sub(r'[^a-z0-9_]', '_', cleaned)
    cleaned = re.sub(r'_+', '_', cleaned)
    cleaned = cleaned.strip('_')

    if cleaned and cleaned[0].isdigit():
        cleaned = f'resource_{cleaned}'

    return cleaned if cleaned else 'unnamed'


def build_group_map(static_groups, smart_groups):
    group_map = {}

    for group in static_groups:
        group_id = str(group.get('id'))
        group_name = group.get('name', f'group_{group_id}')
        group_map[group_id] = {
            'name': group_name,
            'type': 'static'
        }

    for group in smart_groups:
        group_id = str(group.get('id'))
        group_name = group.get('name', f'group_{group_id}')
        group_map[group_id] = {
            'name': group_name,
            'type': 'smart'
        }

    return group_map


def extract_scope_groups(scope_data):
    group_ids = []

    if not scope_data:
        return group_ids

    limitations = scope_data.get('limitations', {})
    computer_groups = limitations.get('computerGroups', [])

    for group in computer_groups:
        group_id = group.get('id')
        if group_id:
            group_ids.append(str(group_id))

    return group_ids


def write_idp_imports(idps, output_file='idp_imports.tf'):
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


def write_static_group_imports(groups, output_file='static_groups_imports.tf'):
    if not groups:
        print('No static computer groups to export')
        return

    with open(output_file, 'w') as f:
        f.write('# Jamf Pro Static Computer Group Import Blocks\n')
        f.write('# Run: terraform plan -generate-config-out=generated.tf\n\n')

        for group in groups:
            group_id = group.get('id')
            group_name = group.get('name', f'group_{group_id}')
            resource_name = clean_name(group_name)

            f.write(f'import {{\n')
            f.write(f'  to = jamfpro_static_computer_group.{resource_name}\n')
            f.write(f'  id = "{group_id}"\n')
            f.write(f'}}\n\n')

    print(f'Wrote {len(groups)} import blocks to {output_file}')


def write_smart_group_imports(groups, output_file='smart_groups_imports.tf'):
    if not groups:
        print('No smart computer groups to export')
        return

    with open(output_file, 'w') as f:
        f.write('# Jamf Pro Smart Computer Group Import Blocks\n')
        f.write('# Run: terraform plan -generate-config-out=generated.tf\n\n')

        for group in groups:
            group_id = group.get('id')
            group_name = group.get('name', f'group_{group_id}')
            resource_name = clean_name(group_name)

            f.write(f'import {{\n')
            f.write(f'  to = jamfpro_smart_computer_group.{resource_name}\n')
            f.write(f'  id = "{group_id}"\n')
            f.write(f'}}\n\n')

    print(f'Wrote {len(groups)} import blocks to {output_file}')


def write_extension_attribute_imports(eas, group_map, instance_url, token, output_file='extension_attributes_imports.tf'):
    if not eas:
        print('No extension attributes to export')
        return

    with open(output_file, 'w') as f:
        f.write('# Jamf Pro Computer Extension Attribute Import Blocks\n')
        f.write('# Run: terraform plan -generate-config-out=generated.tf\n\n')

        for ea in eas:
            ea_id = ea.get('id')
            ea_name = ea.get('name', f'ea_{ea_id}')
            resource_name = clean_name(ea_name)

            details = get_extension_attribute_details(instance_url, token, ea_id)
            scope_groups = []

            if details and 'inventoryDisplay' in details:
                scope_groups = extract_scope_groups(details.get('inventoryDisplay'))

            if scope_groups:
                f.write(f'# Scoped to groups: ')
                group_names = []
                for gid in scope_groups:
                    if gid in group_map:
                        group_names.append(f"{group_map[gid]['name']} ({group_map[gid]['type']})")
                f.write(', '.join(group_names) + '\n')

            f.write(f'import {{\n')
            f.write(f'  to = jamfpro_computer_extension_attribute.{resource_name}\n')
            f.write(f'  id = "{ea_id}"\n')
            f.write(f'}}\n\n')

    print(f'Wrote {len(eas)} import blocks to {output_file}')


def write_script_imports(scripts, group_map, instance_url, token, output_file='scripts_imports.tf'):
    if not scripts:
        print('No scripts to export')
        return

    with open(output_file, 'w') as f:
        f.write('# Jamf Pro Script Import Blocks\n')
        f.write('# Run: terraform plan -generate-config-out=generated.tf\n\n')

        for script in scripts:
            script_id = script.get('id')
            script_name = script.get('name', f'script_{script_id}')
            resource_name = clean_name(script_name)

            details = get_script_details(instance_url, token, script_id)
            scope_groups = []

            if details:
                scope_groups = extract_scope_groups(details)

            if scope_groups:
                f.write(f'# Scoped to groups: ')
                group_names = []
                for gid in scope_groups:
                    if gid in group_map:
                        group_names.append(f"{group_map[gid]['name']} ({group_map[gid]['type']})")
                f.write(', '.join(group_names) + '\n')

            f.write(f'import {{\n')
            f.write(f'  to = jamfpro_script.{resource_name}\n')
            f.write(f'  id = "{script_id}"\n')
            f.write(f'}}\n\n')

    print(f'Wrote {len(scripts)} import blocks to {output_file}')


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Export Jamf Pro resources to Terraform import blocks'
    )

    parser.add_argument('--idp', action='store_true',
                        help='Export cloud identity providers')
    parser.add_argument('--static-groups', action='store_true',
                        help='Export static computer groups')
    parser.add_argument('--smart-groups', action='store_true',
                        help='Export smart computer groups')
    parser.add_argument('--extension-attributes', action='store_true',
                        help='Export computer extension attributes')
    parser.add_argument('--scripts', action='store_true',
                        help='Export scripts')
    parser.add_argument('--all', action='store_true',
                        help='Export all resource types')

    return parser.parse_args()


def main():
    args = parse_arguments()

    if not any([args.idp, args.static_groups, args.smart_groups,
                args.extension_attributes, args.scripts, args.all]):
        print('Error: No resource types specified')
        print('Use --help to see available options')
        sys.exit(1)

    instance_url = os.getenv('JAMF_INSTANCE_URL')
    client_id = os.getenv('JAMF_CLIENT_ID')
    client_secret = os.getenv('JAMF_CLIENT_SECRET')

    if not all([instance_url, client_id, client_secret]):
        print('Error: Missing environment variables')
        print('Required: JAMF_INSTANCE_URL, JAMF_CLIENT_ID, JAMF_CLIENT_SECRET')
        sys.exit(1)

    instance_url = instance_url.rstrip('/')

    try:
        print(f'Connecting to {instance_url}...')
        token = get_jamf_token(instance_url, client_id, client_secret)

        static_groups = []
        smart_groups = []
        group_map = {}

        if args.all or args.static_groups or args.extension_attributes or args.scripts:
            print('Fetching static computer groups...')
            static_groups = get_static_computer_groups(instance_url, token)
            print(f'Found {len(static_groups)} static group(s)')

        if args.all or args.smart_groups or args.extension_attributes or args.scripts:
            print('Fetching smart computer groups...')
            smart_groups = get_smart_computer_groups(instance_url, token)
            print(f'Found {len(smart_groups)} smart group(s)')

        if static_groups or smart_groups:
            group_map = build_group_map(static_groups, smart_groups)

        if args.all or args.idp:
            print('Fetching cloud identity providers...')
            idps = get_cloud_idps(instance_url, token)
            print(f'Found {len(idps)} cloud identity provider(s)')
            write_idp_imports(idps)

        if args.all or args.static_groups:
            write_static_group_imports(static_groups)

        if args.all or args.smart_groups:
            write_smart_group_imports(smart_groups)

        if args.all or args.extension_attributes:
            print('Fetching extension attributes...')
            eas = get_extension_attributes(instance_url, token)
            print(f'Found {len(eas)} extension attribute(s)')
            write_extension_attribute_imports(eas, group_map, instance_url, token)

        if args.all or args.scripts:
            print('Fetching scripts...')
            scripts = get_scripts(instance_url, token)
            print(f'Found {len(scripts)} script(s)')
            write_script_imports(scripts, group_map, instance_url, token)

        print('\nNext steps:')
        print('1. terraform init')
        print('2. terraform plan -generate-config-out=generated.tf')

    except Exception as e:
        print(f'Error: {e}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()