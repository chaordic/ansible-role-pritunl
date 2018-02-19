def sso_authenticate(sso_type, host_id, host_name, user_name, user_email,
        remote_ip, sso_org_names, sso_group_names, **kwargs):

    default_groups = ['default']

    if 'auth_ok':
        return True, '', default_groups
    else:
        return False, None, None
