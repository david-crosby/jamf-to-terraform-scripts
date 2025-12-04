#!/usr/bin/env python3

import argparse
import logging
import os
import re
import sys

import requests


def setup_logger(log_file='jamf_export.log', console_level=logging.INFO, file_level=logging.DEBUG):
    logger = logging.getLogger('jamf_exporter')
    logger.setLevel(logging.DEBUG)

    # Prevent duplicate handlers if logger is reinitialized
    if logger.handlers:
        return logger

    # Console handler - INFO and above
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(console_level)
    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)

    # File handler - DEBUG and above
    file_handler = logging.FileHandler(log_file, mode='a')
    file_handler.setLevel(file_level)
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger


logger = setup_logger()


def get_jamf_token(instance_url, client_id, client_secret):
    logger.debug(f'Attempting authentication to {instance_url}')
    try:
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
            logger.error(f'Authentication failed with status code: {response.status_code}')
            logger.debug(f'Response body: {response.text}')
            raise Exception(f'Authentication failed: {response.status_code}')

        logger.info('Successfully authenticated to Jamf Pro')
        return response.json()['access_token']
    except requests.RequestException as e:
        logger.error(f'Network error during authentication: {e}')
        raise


def get_cloud_idps(instance_url, token):
    logger.debug('Fetching cloud identity providers')
    try:
        response = requests.get(
            f'{instance_url}/api/v1/cloud-idp',
            headers={'Authorization': f'Bearer {token}'}
        )

        if response.status_code != 200:
            logger.error(f'Failed to fetch cloud IDPs: {response.status_code}')
            logger.debug(f'Response body: {response.text}')
            raise Exception(f'Failed to fetch cloud IDPs: {response.status_code}')

        results = response.json().get('results', [])
        logger.debug(f'Retrieved {len(results)} cloud identity provider(s)')
        return results
    except requests.RequestException as e:
        logger.error(f'Network error fetching cloud IDPs: {e}')
        raise


def get_static_computer_groups(instance_url, token):
    logger.debug('Fetching static computer groups')
    try:
        response = requests.get(
            f'{instance_url}/api/v2/computer-groups/static-groups',
            headers={'Authorization': f'Bearer {token}'}
        )

        if response.status_code != 200:
            logger.error(f'Failed to fetch static computer groups: {response.status_code}')
            logger.debug(f'Response body: {response.text}')
            raise Exception(f'Failed to fetch static computer groups: {response.status_code}')

        results = response.json().get('results', [])
        logger.debug(f'Retrieved {len(results)} static computer group(s)')
        return results
    except requests.RequestException as e:
        logger.error(f'Network error fetching static computer groups: {e}')
        raise


def get_smart_computer_groups(instance_url, token):
    logger.debug('Fetching smart computer groups')
    try:
        response = requests.get(
            f'{instance_url}/api/v2/computer-groups/smart-groups',
            headers={'Authorization': f'Bearer {token}'}
        )

        if response.status_code != 200:
            logger.error(f'Failed to fetch smart computer groups: {response.status_code}')
            logger.debug(f'Response body: {response.text}')
            raise Exception(f'Failed to fetch smart computer groups: {response.status_code}')

        results = response.json().get('results', [])
        logger.debug(f'Retrieved {len(results)} smart computer group(s)')
        return results
    except requests.RequestException as e:
        logger.error(f'Network error fetching smart computer groups: {e}')
        raise


def get_extension_attributes(instance_url, token):
    logger.debug('Fetching extension attributes')
    try:
        response = requests.get(
            f'{instance_url}/api/v1/computer-extension-attributes',
            headers={'Authorization': f'Bearer {token}'}
        )

        if response.status_code != 200:
            logger.error(f'Failed to fetch extension attributes: {response.status_code}')
            logger.debug(f'Response body: {response.text}')
            raise Exception(f'Failed to fetch extension attributes: {response.status_code}')

        results = response.json().get('results', [])
        logger.debug(f'Retrieved {len(results)} extension attribute(s)')
        return results
    except requests.RequestException as e:
        logger.error(f'Network error fetching extension attributes: {e}')
        raise


def get_scripts(instance_url, token):
    logger.debug('Fetching scripts')
    try:
        response = requests.get(
            f'{instance_url}/api/v1/scripts',
            headers={'Authorization': f'Bearer {token}'}
        )

        if response.status_code != 200:
            logger.error(f'Failed to fetch scripts: {response.status_code}')
            logger.debug(f'Response body: {response.text}')
            raise Exception(f'Failed to fetch scripts: {response.status_code}')

        results = response.json().get('results', [])
        logger.debug(f'Retrieved {len(results)} script(s)')
        return results
    except requests.RequestException as e:
        logger.error(f'Network error fetching scripts: {e}')
        raise


def get_extension_attribute_details(instance_url, token, ea_id):
    logger.debug(f'Fetching details for extension attribute ID: {ea_id}')
    try:
        response = requests.get(
            f'{instance_url}/api/v1/computer-extension-attributes/{ea_id}',
            headers={'Authorization': f'Bearer {token}'}
        )

        if response.status_code != 200:
            logger.warning(f'Failed to fetch extension attribute {ea_id} details: {response.status_code}')
            return None

        return response.json()
    except requests.RequestException as e:
        logger.warning(f'Network error fetching extension attribute {ea_id} details: {e}')
        return None


def get_script_details(instance_url, token, script_id):
    logger.debug(f'Fetching details for script ID: {script_id}')
    try:
        response = requests.get(
            f'{instance_url}/api/v1/scripts/{script_id}',
            headers={'Authorization': f'Bearer {token}'}
        )

        if response.status_code != 200:
            logger.warning(f'Failed to fetch script {script_id} details: {response.status_code}')
            return None

        return response.json()
    except requests.RequestException as e:
        logger.warning(f'Network error fetching script {script_id} details: {e}')
        return None


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
        logger.info('No cloud identity providers to export')
        return

    logger.debug(f'Writing {len(idps)} cloud identity provider import blocks to {output_file}')
    try:
        with open(output_file, 'w') as f:
            f.write('# Jamf Pro Cloud Identity Provider Import Blocks\n')
            f.write('# Run: terraform plan -generate-config-out=generated.tf\n\n')

            for idp in idps:
                idp_id = idp.get('id')
                idp_name = idp.get('displayName', f'idp_{idp_id}')
                resource_name = clean_name(idp_name)

                logger.debug(f'Writing import block for IDP: {idp_name} (ID: {idp_id})')
                f.write(f'import {{\n')
                f.write(f'  to = jamfpro_cloud_identity_provider.{resource_name}\n')
                f.write(f'  id = "{idp_id}"\n')
                f.write(f'}}\n\n')

        logger.info(f'Wrote {len(idps)} import blocks to {output_file}')
    except IOError as e:
        logger.error(f'Failed to write to {output_file}: {e}')
        raise


def write_static_group_imports(groups, output_file='static_groups_imports.tf'):
    if not groups:
        logger.info('No static computer groups to export')
        return

    logger.debug(f'Writing {len(groups)} static computer group import blocks to {output_file}')
    try:
        with open(output_file, 'w') as f:
            f.write('# Jamf Pro Static Computer Group Import Blocks\n')
            f.write('# Run: terraform plan -generate-config-out=generated.tf\n\n')

            for group in groups:
                group_id = group.get('id')
                group_name = group.get('name', f'group_{group_id}')
                resource_name = clean_name(group_name)

                logger.debug(f'Writing import block for static group: {group_name} (ID: {group_id})')
                f.write(f'import {{\n')
                f.write(f'  to = jamfpro_static_computer_group.{resource_name}\n')
                f.write(f'  id = "{group_id}"\n')
                f.write(f'}}\n\n')

        logger.info(f'Wrote {len(groups)} import blocks to {output_file}')
    except IOError as e:
        logger.error(f'Failed to write to {output_file}: {e}')
        raise


def write_smart_group_imports(groups, output_file='smart_groups_imports.tf'):
    if not groups:
        logger.info('No smart computer groups to export')
        return

    logger.debug(f'Writing {len(groups)} smart computer group import blocks to {output_file}')
    try:
        with open(output_file, 'w') as f:
            f.write('# Jamf Pro Smart Computer Group Import Blocks\n')
            f.write('# Run: terraform plan -generate-config-out=generated.tf\n\n')

            for group in groups:
                group_id = group.get('id')
                group_name = group.get('name', f'group_{group_id}')
                resource_name = clean_name(group_name)

                logger.debug(f'Writing import block for smart group: {group_name} (ID: {group_id})')
                f.write(f'import {{\n')
                f.write(f'  to = jamfpro_smart_computer_group.{resource_name}\n')
                f.write(f'  id = "{group_id}"\n')
                f.write(f'}}\n\n')

        logger.info(f'Wrote {len(groups)} import blocks to {output_file}')
    except IOError as e:
        logger.error(f'Failed to write to {output_file}: {e}')
        raise


def write_extension_attribute_imports(eas, group_map, instance_url, token, output_file='extension_attributes_imports.tf'):
    if not eas:
        logger.info('No extension attributes to export')
        return

    logger.debug(f'Writing {len(eas)} extension attribute import blocks to {output_file}')
    try:
        with open(output_file, 'w') as f:
            f.write('# Jamf Pro Computer Extension Attribute Import Blocks\n')
            f.write('# Run: terraform plan -generate-config-out=generated.tf\n\n')

            for ea in eas:
                ea_id = ea.get('id')
                ea_name = ea.get('name', f'ea_{ea_id}')
                resource_name = clean_name(ea_name)

                logger.debug(f'Processing extension attribute: {ea_name} (ID: {ea_id})')
                details = get_extension_attribute_details(instance_url, token, ea_id)
                scope_groups = []

                if details and 'inventoryDisplay' in details:
                    scope_groups = extract_scope_groups(details.get('inventoryDisplay'))
                    if scope_groups:
                        logger.debug(f'Extension attribute {ea_name} has {len(scope_groups)} scope group(s)')

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

        logger.info(f'Wrote {len(eas)} import blocks to {output_file}')
    except IOError as e:
        logger.error(f'Failed to write to {output_file}: {e}')
        raise


def write_script_imports(scripts, group_map, instance_url, token, output_file='scripts_imports.tf'):
    if not scripts:
        logger.info('No scripts to export')
        return

    logger.debug(f'Writing {len(scripts)} script import blocks to {output_file}')
    try:
        with open(output_file, 'w') as f:
            f.write('# Jamf Pro Script Import Blocks\n')
            f.write('# Run: terraform plan -generate-config-out=generated.tf\n\n')

            for script in scripts:
                script_id = script.get('id')
                script_name = script.get('name', f'script_{script_id}')
                resource_name = clean_name(script_name)

                logger.debug(f'Processing script: {script_name} (ID: {script_id})')
                details = get_script_details(instance_url, token, script_id)
                scope_groups = []

                if details:
                    scope_groups = extract_scope_groups(details)
                    if scope_groups:
                        logger.debug(f'Script {script_name} has {len(scope_groups)} scope group(s)')

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

        logger.info(f'Wrote {len(scripts)} import blocks to {output_file}')
    except IOError as e:
        logger.error(f'Failed to write to {output_file}: {e}')
        raise


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
        logger.error('No resource types specified')
        logger.info('Use --help to see available options')
        sys.exit(1)

    instance_url = os.getenv('JAMF_INSTANCE_URL')
    client_id = os.getenv('JAMF_CLIENT_ID')
    client_secret = os.getenv('JAMF_CLIENT_SECRET')

    if not all([instance_url, client_id, client_secret]):
        logger.error('Missing environment variables')
        logger.info('Required: JAMF_INSTANCE_URL, JAMF_CLIENT_ID, JAMF_CLIENT_SECRET')
        sys.exit(1)

    instance_url = instance_url.rstrip('/')
    logger.info(f'Starting Jamf Pro export to Terraform')
    logger.debug(f'Target instance: {instance_url}')

    try:
        logger.info(f'Connecting to {instance_url}...')
        token = get_jamf_token(instance_url, client_id, client_secret)

        static_groups = []
        smart_groups = []
        group_map = {}

        if args.all or args.static_groups or args.extension_attributes or args.scripts:
            logger.info('Fetching static computer groups...')
            static_groups = get_static_computer_groups(instance_url, token)
            logger.info(f'Found {len(static_groups)} static group(s)')

        if args.all or args.smart_groups or args.extension_attributes or args.scripts:
            logger.info('Fetching smart computer groups...')
            smart_groups = get_smart_computer_groups(instance_url, token)
            logger.info(f'Found {len(smart_groups)} smart group(s)')

        if static_groups or smart_groups:
            logger.debug('Building group map for scope resolution')
            group_map = build_group_map(static_groups, smart_groups)
            logger.debug(f'Group map contains {len(group_map)} entries')

        if args.all or args.idp:
            logger.info('Fetching cloud identity providers...')
            idps = get_cloud_idps(instance_url, token)
            logger.info(f'Found {len(idps)} cloud identity provider(s)')
            write_idp_imports(idps)

        if args.all or args.static_groups:
            write_static_group_imports(static_groups)

        if args.all or args.smart_groups:
            write_smart_group_imports(smart_groups)

        if args.all or args.extension_attributes:
            logger.info('Fetching extension attributes...')
            eas = get_extension_attributes(instance_url, token)
            logger.info(f'Found {len(eas)} extension attribute(s)')
            write_extension_attribute_imports(eas, group_map, instance_url, token)

        if args.all or args.scripts:
            logger.info('Fetching scripts...')
            scripts = get_scripts(instance_url, token)
            logger.info(f'Found {len(scripts)} script(s)')
            write_script_imports(scripts, group_map, instance_url, token)

        logger.info('\nExport completed successfully')
        logger.info('Next steps:')
        logger.info('1. terraform init')
        logger.info('2. terraform plan -generate-config-out=generated.tf')

    except Exception as e:
        logger.error(f'Export failed: {e}')
        logger.debug('Exception details:', exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()