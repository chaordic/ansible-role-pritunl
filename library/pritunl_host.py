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

def put_pritunl_host(module):
   result = {}

   filters = module.params.get('filters')

   # Grab existing orgs
   hosts = list_pritunl_host(module, filters)

   # Check if the pritunl host exists
   # If not returns error
   if len(hosts) == 0:
       module.fail_json(msg='Any pritunl hosts found with this filter.')

   # Otherwise update the host in Pritunl
   else:

       host_id = hosts[0]['id']

       host_params = {
       'name': module.params.get('name'),
       'public_address': module.params.get('public_address'),
       'public_address6': module.params.get('public_address6'),
       'routed_subnet6': module.params.get('routed_subnet6'),
       'local_address': module.params.get('local_address'),
       'link_address': module.params.get('link_address'),
       'sync_address': module.params.get('sync_address'),
       'availability_group': module.params.get('availability_group'),
       'instance_id': module.params.get('instance_id')
       }

        for host in host_params:
            host

        for k, v in iteritems(host_params):
            if v != host[k]:
                filtered_flag = True
            

        response = pritunl_auth_request(module, 'PUT', "/host/%s" % host_id,
                                       headers={'Content-Type': 'application/json'},
                                       data=json.dumps(host_params))

       if response.status_code != 200:
           module.fail_json(msg="Could not update host %s in Pritunl" % (host_id))
       else:
           result['changed'] = True
           result['response'] = response.json()

   module.exit_json(**result)

def list_pritunl_host(module, filters=None):
    hosts = []

    response = pritunl_auth_request(module, 'GET', '/host')

    if response.status_code != 200:
        module.fail_json(msg='Could not retrieve hosts from Pritunl')
    else:
        for host in response.json():
            # No filtering
            if filters is None:
                hosts.append(host)

            else:
                filtered_flag = False

                for k, v in iteritems(filters):
                    if v != host[k]:
                        filtered_flag = True

                if not filtered_flag:
                    hosts.append(host)

    return hosts

def get_pritunl_host(module):
    filters = module.params.get('filters')

    hosts = list_pritunl_host(module, filters)

    result = {}
    result['changed'] = False
    result['response'] = hosts

    module.exit_json(**result)

def main():
    argument_spec = {}

    argument_spec.update(dict(
        pritunl_url=dict(required=True, type='str', defaults='https://localhost:443'),
        pritunl_api_token=dict(required=True, type='str'),
        pritunl_api_secret=dict(required=True, type='str'),
        state=dict(required=False, choices=['list', 'update'], default=None),
        filters=dict(required=False, type='dict', default=None),
        name=dict(required=False, type='str', default=None),
        public_address=dict(required=False, type='str', default=None),
        public_address6=dict(required=False, type='str', default=None),
        routed_subnet6=dict(required=False, type='str', default=None),
        local_address=dict(required=False, type='str', default=None),
        local_address6=dict(required=False, type='str', default=None),
        link_address=dict(required=False, type='str', default=None),
        sync_address=dict(required=False, type='str', default=None),
        availability_group=dict(required=False, type='str', default=None),
        instance_id=dict(required=False, type='str', default=None)
    )),

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[('state', 'update', ['filters'])]
    )

    state = module.params.get('state')

    if state == 'list' or state is None:
        get_pritunl_host(module)
    elif state == 'update':
        put_pritunl_host(module)

if __name__ == '__main__':
    main()
