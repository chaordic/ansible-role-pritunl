Ansible Role: pritunl
=========

A ansible role to install and configure [pritunl](https://pritunl.com/).

Requirements
------------

* ansible>=2.1

Role Variables
--------------

Available variables are listed below, along with default values (see `defaults/main.yml`):

```yaml
    pritunl_version: 1.28.1548.86
```

Set pritunl version.

```yaml
    pritunl_mongodb_version: 3.4
    pritunl_mongodb_external: False
```

Set mongodb version and define an external mongodb or not.

```yaml
    pritunl_increase_open_limit_file: True
```

Increases the open file limit on the system OS in order to prevent connections issues on servers with high load.

```yaml
    pritunl_mongodb_uri: mongodb://localhost:27017/pritunl
    pritunl_server_key_path: /var/lib/pritunl/pritunl.key
    pritunl_log_path: /var/log/pritunl.log
    pritunl_static_cache: "true"
    pritunl_server_cert_path: /var/lib/pritunl/pritunl.crt
    pritunl_temp_path: /tmp/pritunl_%r
    pritunl_bind_addr: 0.0.0.0
    pritunl_port: 443
    pritunl_debug: "false"
    pritunl_www_path: /usr/share/pritunl/www
    pritunl_local_address_interface: auto
```

pritunl configuration

```yaml
    pritunl_secondary_mongodb: False
    pritunl_secondary_mongodb_uri: ""
```

Enables secondary MongoDB database configuration.

```yaml
    pritunl_plugins:
      - name: graylog
        server: localhost
        port: 1999
```

Enable and installs pritunl graylog plugin.

Example Playbook
----------------
```yaml
- hosts: servers
  connection: ssh
  become: yes
  gather_facts: yes

  vars:
    pritunl_mongodb_external: True
    pritunl_secondary_mongodb: True
    pritunl_mongodb_uri: mongodb://db01:27017/pritunl
    pritunl_secondary_mongodb_uri: mongodb://db02:27017/pritunl

  roles:
     - role: pritunl.chaordic
```

License
-------

GPLv3

Author Information
------------------

Cloud Operations Team, SRE. Linx+Neemu+Chaordic
