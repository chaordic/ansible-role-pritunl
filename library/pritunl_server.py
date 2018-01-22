#!/usr/bin/python

# (c) 2016, Florian Dambrine <android.florian@gmail.com>
#
# This module is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This module is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
'''

import time
import uuid
import hmac
import hashlib
import base64
import requests

from six import iteritems
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import json

# Taken from https://pritunl.com/api
def pritunl_auth_request(module, method, path, headers=None, data=None):
    api_token = module.params.get('pritunl_api_token')
    api_secret = module.params.get('pritunl_api_secret')
    base_url = module.params.get('pritunl_url')
    validate_certs = module.params.get('validate_certs')

    auth_timestamp = str(int(time.time()))
    auth_nonce = uuid.uuid4().hex
    auth_string = '&'.join([api_token, auth_timestamp, auth_nonce,
        method.upper(), path])
    auth_signature = base64.b64encode(hmac.new(
        api_secret, auth_string, hashlib.sha256).digest())
    auth_headers = {
        'Auth-Token': api_token,
        'Auth-Timestamp': auth_timestamp,
        'Auth-Nonce': auth_nonce,
        'Auth-Signature': auth_signature,
    }
    if headers:
        auth_headers.update(headers)
    try:
        return getattr(requests, method.lower())(
            base_url + path,
            headers=auth_headers,
            data=data,
        )
    except Exception as e:
        module.fail_json(msg='Could not connect to %s: %s' % (base_url, e))

def post_pritunl_server(module):
    result = {}

    server_name = module.params.get('name')

    if server_name is None:
        module.fail_json(msg=("Please provide an server name "
                              "using name=<ServerName>"))

    # Grab existing orgs
    servers = list_pritunl_server(module, {"name": server_name})

    # Check if the pritunl server already exists
    # If yes do nothing
    if len(servers) > 0:
        result['changed'] = False
        result['response'] = servers

    # Otherwise create the server in Pritunl
    else:

        server_params = {
        'name': module.params.get('name'),
        'network': module.params.get('network'),
        'groups': module.params.get('groups'),
        'network_mode': module.params.get('network_mode'),
        'network_start': module.params.get('network_start'),
        'network_end': module.params.get('network_end'),
        'restrict_routes': module.params.get('restrict_values'),
        'ipv6': module.params.get('ipv6'),
        'ipv6_firewall': module.params.get('ipv6_firewall'),
        'bind_address': module.params.get('bind_address'),
        'port': module.params.get('port'),
        'protocol': module.params.get('protocol'),
        'dh_param_bits': module.params.get('dh_param_bits'),
        'multi_device': module.params.get('multi_device'),
        'dns_servers': module.params.get('dns_servers'),
        'search_domain': module.params.get('search_domain'),
        'otp_auth': module.params.get('otp_auth'),
        'cipher': module.params.get('cipher'),
        'hash': module.params.get('hash'),
        'jumbo_frames': module.params.get('jumbo_frames'),
        'lzo_compression': module.params.get('lzo_compression'),
        'inter_client': module.params.get('inter_client'),
        'ping_interval': module.params.get('ping_interval'),
        'ping_timeout': module.params.get('ping_timeout'),
        'link_ping_interval': module.params.get('link_ping_interval'),
        'link_ping_timeout': module.params.get('link_ping_timeout'),
        'onc_hostname': module.params.get('onc_hostname'),
        'alllowed_devices': module.params.get('allowed_devices'),
        'max_clients': module.params.get('max_clients'),
        'replica_count': module.params.get('replica_count'),
        'vxlan': module.params.get('vxlan'),
        'dns_mapping': module.params.get('dns_mapping'),
        'debug': module.params.get('debug'),
        'policy': module.params.get('policy')
        }

        response = pritunl_auth_request(module, 'POST', '/server',
                                        headers={'Content-Type': 'application/json'},
                                        data=json.dumps(server_params))

        if response.status_code != 200:
            module.fail_json(msg="Could not create server %s in Pritunl" % (server_name))
        else:
            result['changed'] = True
            result['response'] = response.json()

    module.exit_json(**result)

def list_pritunl_server(module, filters=None):
    servers = []

    response = pritunl_auth_request(module, 'GET', '/server')

    if response.status_code != 200:
        module.fail_json(msg='Could not retrieve servers from Pritunl')
    else:
        for server in response.json():
            # No filtering
            if filters is None:
                servers.append(server)

            else:
                filtered_flag = False

                for k, v in iteritems(filters):
                    if v != server[k]:
                        filtered_flag = True

                if not filtered_flag:
                    servers.append(server)

    return servers


def get_pritunl_server(module):
    server_name = module.params.get('name')

    filters = None

    if server_name is not None:
        filters = {"name": server_name}

    servers = list_pritunl_server(module, filters)

    result = {}
    result['changed'] = False
    result['response'] = servers

    module.exit_json(**result)

def main():
    argument_spec = {}

    argument_spec.update(dict(
        pritunl_url=dict(required=True, type='str', defaults='https://localhost:443'),
        pritunl_api_token=dict(required=True, type='str'),
        pritunl_api_secret=dict(required=True, type='str'),
        state=dict(required=False, choices=['list', 'present', 'absent'], default=None),
        validate_certs=dict(required=False, type='bool', default=True),
        name=dict(required=False, type='str', default=None),
        network=dict(required=False, type='str', default=None),
        groups=dict(required=False, type='list', default=None),
        network_mode=dict(required=False, type='str', default='tunnel'),
        network_start=dict(required=False, type='str', default=None),
        network_end=dict(required=False, type='str', default=None),
        restrict_routes=dict(required=False, type='bool', default=True),
        ipv6=dict(required=False, type='bool', default=False),
        ipv6_firewall=dict(required=False, type='bool', default=True),
        bind_address=dict(required=False, type='bool', default=None),
        port=dict(required=False, type='int', default=None),
        protocol=dict(required=False, type='str', default='udp'),
        dh_param_bits=dict(required=False, type='int', default=1536),
        multi_device=dict(required=False, type='bool', default=False),
        dns_servers=dict(required=False, type='list', default=None),
        search_domain=dict(required=False, type='str', default=None),
        otp_auth=dict(required=False, type='bool', default=False),
        cipher=dict(required=False, type='str', default='aes128'),
        hash=dict(required=False, type='str', default='sha1'),
        jumbo_frames=dict(required=False, type='bool', default=False),
        lzo_compression=dict(required=False, type='bool', default=False),
        inter_client=dict(required=False, type='bool', default=True),
        ping_interval=dict(required=False, type='int', default=10),
        ping_timeout=dict(required=False, type='int', default=60),
        link_ping_interval=dict(required=False, type='int', default=1),
        link_ping_timeout=dict(required=False, type='int', default=5),
        onc_hostname=dict(required=False, type='str', default=None),
        alllowed_devices=dict(required=False, type='str', default=None),
        max_clients=dict(required=False, type='int', default=100),
        replica_count=dict(required=False, type='int', default=1),
        vxlan=dict(required=False, type='bool', default=True),
        dns_mapping=dict(required=False, type='bool', default=False),
        debug=dict(required=False, type='bool', default=False),
        policy=dict(required=False, type='str', default=None)
    )),

    module = AnsibleModule(
        argument_spec=argument_spec
    )

    state = module.params.get('state')

    if state == 'list' or state is None:
        get_pritunl_server(module)
    elif state == 'present':
        post_pritunl_server(module)
    # elif state == 'absent':
        # delete_pritunl_organization(module)


if __name__ == '__main__':
    main()
