Overview
========

This is a plugin for OpenStack Keystone for integration with LDAP
(both "RFC 2307"-compliant servers and Active Directory).

User accounts (including authentication) are retrieved from
LDAP. Keystone cannot modify or delete any user account: all editing
has to be performed at LDAP server side.

Tenants are still stored at Keystone (as distinct from OpenStack
implementation that stores them in LDAP).


Installation
============

Issue::

    # yum install -y keystone-ldap


Configuration
=============

Login as root to your system and configure it.

Edit `/etc/keystone/keystone.conf`.


1. Change `identity.driver`::

    [identity]
    driver = keystone_ldap.core.Identity


2. Provide LDAP-specific information::

    [ldap]
    # URL of the organization’s LDAP server to query for
    # user information and group membership from
    url = ldap://<ldap server>

    # username to bind to the LDAP server with.
    # For an anonymous connection, set to empty string
    user = <user name>

    # password for the user identified by ldap.user
    password = <user password>

    # root of the tree containing all user accounts
    user_tree_dn = dc=mycompany,dc=net

    # root of the tree containing all group records
    group_tree_dn = ou=groups,dc=mycompany,dc=net

    # object class to recognize user records, e.g.,
    # person, organizationalPerson, or inetOrgPerson
    user_objectclass = organizationalPerson

    # attribute that will be used as user login name by
    # OpenStack and Focus
    user_name_attribute = sAMAccountName

    # attribute that will be used to build user's DN
    # like uid=admin,dc=mycompany,dc=net or
    # cn=admin,dc=mycompany,dc=net
    user_id_attribute = cn

    # name of systenant (its and only its users are
    # treated as Admins)
    systenant = systenant


For RFC 2307, you may set::

    user_objectclass = organizationalPerson
    user_name_attribute = uid
    user_id_attribute = uid
    systenant = systenant


For Active Directory, you may omit group_tree_dn and set::

    user_objectclass = organizationalPerson
    user_name_attribute = sAMAccountName
    user_id_attribute = cn
    systenant = systenant


Now run a simple script to reconfigure Altai. The script takes two
options: admin-login-name and admin-login-password::

    # keystone-ldap-configure admin secret


Smoke Testing
=============

Run on keystone's host::

    # curl localhost:35357/v2.0/users -H "x-auth-token: $(grep '^admin_token' /etc/keystone/keystone.conf | cut -d = -f 2)" | python -mjson.tool


You should see a list of users known by LDAP. The request is performed
with `admin_token` stored in /etc/keystone/keystone.conf, so, you need
not to provide a password.


Example::

    {
        "users": [
            {
                "email": "altai_admin@test.altai", 
                "enabled": true, 
                "fullName": "Admin Admin", 
                "id": "QWRtaW4gQWRtaW4=", 
                "memberOf": [
                    "altai_administrators"
                ], 
                "name": "altai_administrator"
            }, 
            {
                "email": "altai_user1@test.altai", 
                "enabled": false, 
                "fullName": "First User", 
                "id": "Rmlyc3QgVXNlcg==", 
                "memberOf": [
                    "altai_test", 
                    "altai_ad_poc"
                ], 
                "name": "altai_user1"
            }, 
            {
                "email": "altai_user2@altai.test", 
                "enabled": true, 
                "fullName": "Second User", 
                "id": "U2Vjb25kIFVzZXI=", 
                "memberOf": [
                    "altai_test", 
                    "altai_ad_poc"
                ], 
                "name": "altai_user2"
            }, 
            {
                "enabled": true, 
                "fullName": "sys user", 
                "id": "c3lzIHVzZXI=", 
                "memberOf": [
                    "altai_administrators"
                ], 
                "name": "_system"
            }
        ]
    }


Troubleshooting
===============

Ensure that `DEFAULT.debug` is `True` at
`/etc/keystone/keystone.conf` and look at
`/var/log/keystone/keystone.log`. 

