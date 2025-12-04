#!/usr/bin/env python3

import argparse
import logging
import os
import re
import sys
import time
from typing import Optional, Dict, List, Any

import requests

REQUEST_TIMEOUT = 30
MIN_REQUEST_INTERVAL = 0.1
last_request_time = 0


def setup_logger(log_file='jamf_export.log', console_level=logging.INFO, file_level=logging.DEBUG):
    logger = logging.getLogger('jamf_exporter')
    logger.setLevel(logging.DEBUG)

    if logger.handlers:
        return logger

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(console_level)
    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)

    file_handler = logging.FileHandler(log_file, mode='a')
    file_handler.setLevel(file_level)
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger


logger = setup_logger()


RESOURCE_CONFIGS = {
    'cloud_idp': {
        'endpoint': 'api/v1/cloud-idp',
        'display_name': 'cloud identity provider',
        'terraform_resource': 'jamfpro_cloud_identity_provider',
        'name_field': 'displayName',
        'output_file': 'idp_imports.tf',
        'header': 'Jamf Pro Cloud Identity Provider Import Blocks',
    },
    'static_groups': {
        'endpoint': 'api/v2/computer-groups/static-groups',
        'display_name': 'static computer group',
        'terraform_resource': 'jamfpro_static_computer_group',
        'name_field': 'name',
        'output_file': 'static_groups_imports.tf',
        'header': 'Jamf Pro Static Computer Group Import Blocks',
    },
    'smart_groups': {
        'endpoint': 'api/v2/computer-groups/smart-groups',
        'display_name': 'smart computer group',
        'terraform_resource': 'jamfpro_smart_computer_group',
        'name_field': 'name',
        'output_file': 'smart_groups_imports.tf',
        'header': 'Jamf Pro Smart Computer Group Import Blocks',
    },
    'extension_attributes': {
        'endpoint': 'api/v1/computer-extension-attributes',
        'display_name': 'extension attribute',
        'terraform_resource': 'jamfpro_computer_extension_attribute',
        'name_field': 'name',
        'output_file': 'extension_attributes_imports.tf',
        'header': 'Jamf Pro Computer Extension Attribute Import Blocks',
        'details_endpoint': 'api/v1/computer-extension-attributes/{id}',
        'has_scope': True,
        'scope_path': 'inventoryDisplay',
    },
    'scripts': {
        'endpoint': 'api/v1/scripts',
        'display_name': 'script',
        'terraform_resource': 'jamfpro_script',
        'name_field': 'name',
        'output_file': 'scripts_imports.tf',
        'header': 'Jamf Pro Script Import Blocks',
        'details_endpoint': 'api/v1/scripts/{id}',
        'has_scope': True,
        'scope_path': None,
    },
}


class FailureTracker:
    """Tracks partial failures during resource processing"""

    def __init__(self):
        self.failures: Dict[str, List[Dict[str, Any]]] = {}

    def add_failure(self, resource_type: str, resource_id: str, resource_name: str, error: str):
        """Record a failed resource operation"""
        if resource_type not in self.failures:
            self.failures[resource_type] = []

        self.failures[resource_type].append({
            'id': resource_id,
            'name': resource_name,
            'error': error
        })

    def has_failures(self) -> bool:
        """Check if any failures were recorded"""
        return len(self.failures) > 0

    def get_summary(self) -> str:
        """Get a formatted summary of all failures"""
        if not self.has_failures():
            return "No failures recorded."

        lines = ["\n" + "="*60, "PARTIAL FAILURE SUMMARY", "="*60]

        total_failures = sum(len(items) for items in self.failures.values())
        lines.append(f"\nTotal failed operations: {total_failures}")

        for resource_type, failures in self.failures.items():
            lines.append(f"\n{resource_type} ({len(failures)} failures):")
            for failure in failures:
                lines.append(f"  - {failure['name']} (ID: {failure['id']})")
                lines.append(f"    Error: {failure['error']}")

        lines.append("\n" + "="*60)
        return "\n".join(lines)


def rate_limit():
    """Implement simple rate limiting between API requests"""
    global last_request_time

    current_time = time.time()
    time_since_last_request = current_time - last_request_time

    if time_since_last_request < MIN_REQUEST_INTERVAL:
        sleep_time = MIN_REQUEST_INTERVAL - time_since_last_request
        logger.debug(f'Rate limiting: sleeping for {sleep_time:.3f} seconds')
        time.sleep(sleep_time)

    last_request_time = time.time()


def get_jamf_token(instance_url: str, client_id: str, client_secret: str) -> str:
    logger.debug(f'Attempting authentication to {instance_url}')
    try:
        response = requests.post(
            f'{instance_url}/api/oauth/token',
            data={
                'client_id': client_id,
                'client_secret': client_secret,
                'grant_type': 'client_credentials'
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code != 200:
            logger.error(f'Authentication failed with status code: {response.status_code}')
            raise Exception(f'Authentication failed: {response.status_code}')

        try:
            data = response.json()
        except ValueError as e:
            logger.error(f'Failed to parse authentication response as JSON: {e}')
            raise Exception('Invalid JSON response from authentication endpoint')

        if 'access_token' not in data:
            logger.error('Authentication response missing access_token field')
            raise Exception('Invalid authentication response: missing access_token')

        logger.info('Successfully authenticated to Jamf Pro')
        return data['access_token']
    except requests.Timeout:
        logger.error(f'Authentication request timed out after {REQUEST_TIMEOUT} seconds')
        raise
    except requests.RequestException as e:
        logger.error(f'Network error during authentication: {e}')
        raise


def fetch_api_resources(instance_url: str, token: str, endpoint: str, resource_name: str) -> List[Dict]:
    """Generic function to fetch API resources with consistent error handling"""
    logger.debug(f'Fetching {resource_name}')

    rate_limit()

    try:
        response = requests.get(
            f'{instance_url}/{endpoint}',
            headers={'Authorization': f'Bearer {token}'},
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code != 200:
            logger.error(f'Failed to fetch {resource_name}: {response.status_code}')
            logger.debug(f'Response body: {response.text[:500]}')
            raise Exception(f'Failed to fetch {resource_name}: {response.status_code}')

        try:
            data = response.json()
        except ValueError as e:
            logger.error(f'Failed to parse {resource_name} response as JSON: {e}')
            raise Exception(f'Invalid JSON response from {resource_name} endpoint')

        if not isinstance(data, dict):
            logger.error(f'Unexpected response format for {resource_name}: expected dict, got {type(data).__name__}')
            raise Exception(f'Invalid {resource_name} response format')

        results = data.get('results', [])
        logger.debug(f'Retrieved {len(results)} {resource_name}(s)')
        return results

    except requests.Timeout:
        logger.error(f'Request timed out after {REQUEST_TIMEOUT} seconds while fetching {resource_name}')
        raise
    except requests.RequestException as e:
        logger.error(f'Network error fetching {resource_name}: {e}')
        raise


def fetch_resource_details(instance_url: str, token: str, endpoint: str, resource_id: str,
                          resource_name: str, failure_tracker: FailureTracker) -> Optional[Dict]:
    """Generic function to fetch individual resource details with failure tracking"""
    logger.debug(f'Fetching details for {resource_name} ID: {resource_id}')

    rate_limit()

    try:
        response = requests.get(
            f'{instance_url}/{endpoint.format(id=resource_id)}',
            headers={'Authorization': f'Bearer {token}'},
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code != 200:
            error_msg = f'API returned status {response.status_code}'
            logger.warning(f'Failed to fetch {resource_name} {resource_id} details: {error_msg}')
            failure_tracker.add_failure(resource_name, resource_id, resource_name, error_msg)
            return None

        try:
            data = response.json()
        except ValueError as e:
            error_msg = f'Invalid JSON response: {str(e)}'
            logger.warning(f'Failed to parse {resource_name} {resource_id} details: {error_msg}')
            failure_tracker.add_failure(resource_name, resource_id, resource_name, error_msg)
            return None

        return data

    except requests.Timeout:
        error_msg = f'Request timed out after {REQUEST_TIMEOUT} seconds'
        logger.warning(f'Timeout fetching {resource_name} {resource_id} details')
        failure_tracker.add_failure(resource_name, resource_id, resource_name, error_msg)
        return None
    except requests.RequestException as e:
        error_msg = f'Network error: {str(e)}'
        logger.warning(f'Network error fetching {resource_name} {resource_id} details: {e}')
        failure_tracker.add_failure(resource_name, resource_id, resource_name, error_msg)
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


def write_resource_imports(resources: List[Dict], config: Dict, group_map: Optional[Dict] = None,
                         instance_url: Optional[str] = None, token: Optional[str] = None,
                         failure_tracker: Optional[FailureTracker] = None) -> None:
    """Generic function to write Terraform import blocks for resources"""
    if not resources:
        logger.info(f'No {config["display_name"]}s to export')
        return

    output_file = config['output_file']
    logger.debug(f'Writing {len(resources)} {config["display_name"]} import blocks to {output_file}')

    try:
        with open(output_file, 'w') as f:
            f.write(f'# {config["header"]}\n')
            f.write('# Run: terraform plan -generate-config-out=generated.tf\n\n')

            for resource in resources:
                resource_id = str(resource.get('id'))
                resource_name = resource.get(config['name_field'], f'{config["display_name"]}_{resource_id}')
                tf_resource_name = clean_name(resource_name)

                logger.debug(f'Processing {config["display_name"]}: {resource_name} (ID: {resource_id})')

                scope_groups = []
                if config.get('has_scope') and instance_url and token and failure_tracker:
                    details = fetch_resource_details(
                        instance_url, token,
                        config['details_endpoint'],
                        resource_id,
                        f'{config["display_name"]} {resource_name}',
                        failure_tracker
                    )

                    if details:
                        scope_path = config.get('scope_path')
                        scope_data = details.get(scope_path) if scope_path else details
                        scope_groups = extract_scope_groups(scope_data)
                        if scope_groups:
                            logger.debug(f'{config["display_name"]} {resource_name} has {len(scope_groups)} scope group(s)')

                if scope_groups and group_map:
                    group_names = []
                    for gid in scope_groups:
                        if gid in group_map:
                            group_names.append(f"{group_map[gid]['name']} ({group_map[gid]['type']})")
                    if group_names:
                        f.write(f'# Scoped to groups: {", ".join(group_names)}\n')

                f.write(f'import {{\n')
                f.write(f'  to = {config["terraform_resource"]}.{tf_resource_name}\n')
                f.write(f'  id = "{resource_id}"\n')
                f.write(f'}}\n\n')

        logger.info(f'Wrote {len(resources)} import blocks to {output_file}')
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

    failure_tracker = FailureTracker()

    try:
        logger.info(f'Connecting to {instance_url}...')
        token = get_jamf_token(instance_url, client_id, client_secret)

        static_groups = []
        smart_groups = []
        group_map = {}

        needs_groups = args.all or args.static_groups or args.smart_groups or args.extension_attributes or args.scripts

        if needs_groups:
            logger.info('Fetching computer groups...')

            if args.all or args.static_groups or args.extension_attributes or args.scripts:
                static_groups = fetch_api_resources(
                    instance_url, token,
                    RESOURCE_CONFIGS['static_groups']['endpoint'],
                    RESOURCE_CONFIGS['static_groups']['display_name']
                )
                logger.info(f'Found {len(static_groups)} static group(s)')

            if args.all or args.smart_groups or args.extension_attributes or args.scripts:
                smart_groups = fetch_api_resources(
                    instance_url, token,
                    RESOURCE_CONFIGS['smart_groups']['endpoint'],
                    RESOURCE_CONFIGS['smart_groups']['display_name']
                )
                logger.info(f'Found {len(smart_groups)} smart group(s)')

            if static_groups or smart_groups:
                logger.debug('Building group map for scope resolution')
                group_map = build_group_map(static_groups, smart_groups)
                logger.debug(f'Group map contains {len(group_map)} entries')

        if args.all or args.idp:
            logger.info('Fetching cloud identity providers...')
            idps = fetch_api_resources(
                instance_url, token,
                RESOURCE_CONFIGS['cloud_idp']['endpoint'],
                RESOURCE_CONFIGS['cloud_idp']['display_name']
            )
            logger.info(f'Found {len(idps)} cloud identity provider(s)')
            write_resource_imports(idps, RESOURCE_CONFIGS['cloud_idp'])

        if args.all or args.static_groups:
            write_resource_imports(static_groups, RESOURCE_CONFIGS['static_groups'])

        if args.all or args.smart_groups:
            write_resource_imports(smart_groups, RESOURCE_CONFIGS['smart_groups'])

        if args.all or args.extension_attributes:
            logger.info('Fetching extension attributes...')
            eas = fetch_api_resources(
                instance_url, token,
                RESOURCE_CONFIGS['extension_attributes']['endpoint'],
                RESOURCE_CONFIGS['extension_attributes']['display_name']
            )
            logger.info(f'Found {len(eas)} extension attribute(s)')
            write_resource_imports(
                eas, RESOURCE_CONFIGS['extension_attributes'],
                group_map, instance_url, token, failure_tracker
            )

        if args.all or args.scripts:
            logger.info('Fetching scripts...')
            scripts = fetch_api_resources(
                instance_url, token,
                RESOURCE_CONFIGS['scripts']['endpoint'],
                RESOURCE_CONFIGS['scripts']['display_name']
            )
            logger.info(f'Found {len(scripts)} script(s)')
            write_resource_imports(
                scripts, RESOURCE_CONFIGS['scripts'],
                group_map, instance_url, token, failure_tracker
            )

        logger.info('\nExport completed successfully')

        if failure_tracker.has_failures():
            logger.warning(failure_tracker.get_summary())

        logger.info('\nNext steps:')
        logger.info('1. terraform init')
        logger.info('2. terraform plan -generate-config-out=generated.tf')

    except Exception as e:
        logger.error(f'Export failed: {e}')
        logger.debug('Exception details:', exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()