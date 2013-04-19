# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


import base64

import ldap
from ldap import filter as ldap_filter

from keystone import config
from keystone import exception
from keystone import identity
from keystone.common import ldap as common_ldap
from keystone.common import sql
from keystone.common import utils
from keystone.common.ldap import fakeldap
from keystone.identity import models
from keystone.identity.backends import sql as backends_sql
from keystone.identity.backends import ldap as backends_ldap


CONF = config.CONF


def _filter_user(user_ref):
    if user_ref:
        user_ref.pop('password', None)
    return user_ref


class LdapUser(models.User):
    optional_keys = models.User.optional_keys + ('fullName', 'memberOf')


class UserApi(common_ldap.BaseLdap):
    LDAP_TYPE_UNKNOWN = 0
    LDAP_TYPE_RFC_2307 = 1
    LDAP_TYPE_ACTIVE_DIRECTORY = 2
    LDAP_CAP_ACTIVE_DIRECTORY_OID = "1.2.840.113556.1.4.800"

    DEFAULT_OU = 'ou=Users'
    DEFAULT_STRUCTURAL_CLASSES = ['person']
    DEFAULT_ID_ATTRIBUTE = 'cn'
    DEFAULT_OBJECTCLASS = 'inetOrgPerson'
    group_tree_dn = None
    options_name = 'user'
    attribute_mapping = {
        'email': 'mail',
        'name': 'cn',
        'fullName': 'cn',
    }
    ldap_type = LDAP_TYPE_UNKNOWN

    # NOTE(ayoung): The RFC based schemas don't have a way to indicate
    # 'enabled' the closest is the nsAccount lock, which is on defined to
    # be part of any objectclass.
    # in the future, we need to provide a way for the end user to
    # indicate the field to use and what it indicates
    # NOTE(aababilov): use userAccountControl field to set enabled = False
    attribute_ignore = ['tenant_id', 'enabled', 'tenants']
    model = LdapUser

    def __init__(self, conf):
        super(UserApi, self).__init__(conf)
        attr_conf = "group_tree_dn"
        attr_val = getattr(conf.ldap, attr_conf, None)
        if attr_val:
            self.group_tree_dn = attr_val
        for attr_name in self.attribute_mapping:
            attr_conf = "%s_%s_attribute" % (self.options_name, attr_name)
            attr_val = getattr(conf.ldap, attr_conf, None)
            if attr_val:
                self.attribute_mapping[attr_name] = attr_val

    def get_connection(self, user=None, password=None):
        conn = super(UserApi, self).get_connection(user, password)
        if self.ldap_type == UserApi.LDAP_TYPE_UNKNOWN:
            root_attrs = conn.search_s(
                "", ldap.SCOPE_BASE, "(objectClass=*)")[0][1]
            self.ldap_type = (UserApi.LDAP_TYPE_ACTIVE_DIRECTORY
                              if (UserApi.LDAP_CAP_ACTIVE_DIRECTORY_OID in
                                  root_attrs.get("supportedCapabilities", []))
                              else
                              UserApi.LDAP_TYPE_RFC_2307)
        return conn

    def get_by_name(self, name, filter=None):
        users = self.get_all("(%s=%s)" %
                             (self.attribute_mapping["name"],
                              ldap_filter.escape_filter_chars(name)))
        try:
            return users[0]
        except IndexError:
            return None

    def _id_to_dn(self, id):
        try:
            unbased = base64.urlsafe_b64decode(str(id))
            unbased.decode('utf-8') # just to validate
            escaped =  ldap.dn.escape_dn_chars(unbased)
        except (ValueError, TypeError, UnicodeError):
            raise AssertionError('Invalid user / password')
        return "%s=%s,%s" % (self.id_attr, escaped, self.tree_dn)

    @staticmethod
    def _dn_to_id(dn):
        return base64.urlsafe_b64encode(ldap.dn.str2dn(dn)[0][0][1])

    def _ldap_res_to_model(self, res):
        obj = super(UserApi, self)._ldap_res_to_model(res)
        try:
            obj["enabled"] = (res[1]["userAccountControl"][0] & 2) == 0
        except (KeyError, IndexError):
            pass
        # return memberOf only for Active Directory
        # since for RFC 2307 it will be slow
        if self.ldap_type == UserApi.LDAP_TYPE_ACTIVE_DIRECTORY:
            obj["memberOf"] = self._user_groups(res)
        return obj

    def _user_groups(self, user_ldap):
        if self.ldap_type == UserApi.LDAP_TYPE_ACTIVE_DIRECTORY:
            try:
                return [x.split(",", 1)[0][3:]
                        for x in user_ldap[1]["memberOf"]]
            except (IndexError, KeyError):
                return []
        # for RFC 2307 we need a lookup
        if self.group_tree_dn:
            conn = self.get_connection()
            groups = conn.search_s(self.group_tree_dn,
                                   ldap.SCOPE_ONELEVEL,
                                   "(memberUid=%s)" % user_ldap[1]["uid"][0])
            return [g[1]["cn"][0] for g in groups]
        return []


for attr_name in UserApi.attribute_mapping:
    config.register_str(
        "%s_%s_attribute" % (UserApi.options_name, attr_name),
        group="ldap")
# name of systenant
config.register_str("systenant", group="ldap", default="systenant")
# root of the tree containing all group records
config.register_str("group_tree_dn", group="ldap")


class Identity(backends_sql.Identity):
    def __init__(self):
        super(Identity, self).__init__()
        self.LDAP_URL = CONF.ldap.url
        self.LDAP_USER = CONF.ldap.user
        self.LDAP_PASSWORD = CONF.ldap.password
        self.suffix = CONF.ldap.suffix
        self.systenant = getattr(CONF.ldap, "systenant", "systenant")

        self.user = UserApi(CONF)

    def _user_is_in_tenant(self, user_id, user_ldap, tenant_ref):
        users = set(tenant_ref.get("users") or [])
        try:
            if set(user_ldap[1][self.user.attribute_mapping["name"]]) & users:
                return True
        except (KeyError, IndexError):
            pass
        groups = set(tenant_ref.get("groups") or [])
        if set(self.user._user_groups(user_ldap)) & groups:
            return True
        return False

    def _get_metadata_ref(self, tenant_ref):
        return {
            "roles": [
                "Admin" if tenant_ref["name"] == self.systenant else "Member"
            ]
        }

    # Identity interface
    def authenticate(self, user_id=None, tenant_id=None, password=None):
        """Authenticate based on a user, tenant and password.

        Expects the user object to have a password field and the tenant to be
        in the list of tenants on the user.
        """
        if user_id is None:
            raise AssertionError('Invalid user / password')
        user_ldap = self.user._ldap_get(user_id)
        if user_ldap is None:
            raise AssertionError('Invalid user / password')

        user_ref = self.user._ldap_res_to_model(user_ldap)
        try:
            conn = self.user.get_connection(self.user._id_to_dn(user_id),
                                            password)
            if not conn:
                raise AssertionError('Invalid user / password')
        except Exception:
            raise AssertionError('Invalid user / password')

        if tenant_id:
            tenant_ref = self.get_tenant(tenant_id)
            if not tenant_ref:
                raise AssertionError('Invalid tenant')

            if not self._user_is_in_tenant(user_id, user_ldap, tenant_ref):
                raise AssertionError('Invalid tenant')
            metadata_ref = self._get_metadata_ref(tenant_ref)
        else:
            tenant_ref = None
            metadata_ref = {}
        return  (_filter_user(user_ref), tenant_ref, metadata_ref)

    # def get_tenant(self, tenant_id):
    # inherited

    # def get_tenant_by_name(self, tenant_name):
    # inherited

    def _get_user(self, user_id):
        user_ref = self.user.get(user_id)
        if not user_ref:
            return None
        return user_ref

    def get_user(self, user_id):
        user_ref = self._get_user(user_id)
        if (not user_ref):
            return None
        return _filter_user(user_ref)

    def get_user_by_name(self, user_name):
        """Get a user by name.

        Returns: user_ref or None.

        """
        user_ref = self.user.get_by_name(user_name)
        if not user_ref:
            return None
        return _filter_user(user_ref)

    def get_role(self, role_id):
        """Get a role by id.

        Returns: role_ref or None.

        """
        if role_id in ("Admin", "Member"):
            return {"id": role_id, "name": role_id}
        return None

    def list_users(self):
        """List all users in the system.

        NOTE(termie): I'd prefer if this listed only the users for a given
                      tenant.

        Returns: a list of user_refs or an empty list.

        """
        return self.user.get_all()

    def list_roles(self):
        """List all roles in the system.

        Returns: a list of role_refs or an empty list.

        """
        return [{"id": role_id, "name": role_id}
                for role_id in ("Admin", "Member")]

    def add_user_to_tenant(self, tenant_id, user_id):
        raise exception.NotImplemented()

    def remove_user_from_tenant(self, tenant_id, user_id):
        raise exception.NotImplemented()

    def get_all_tenants(self):
        return self.get_tenants()

    def get_tenants_for_user(self, user_id):
        """Get the tenants associated with a given user.

        Returns: a list of tenant ids.

        """
        if user_id is None:
            return []
        user_ldap = self.user._ldap_get(user_id)
        if user_ldap is None:
            return []
        return [tenant_ref["id"]
                for tenant_ref in self.get_all_tenants()
                if self._user_is_in_tenant(user_id, user_ldap, tenant_ref)]

    # def get_roles_for_user_and_tenant(self, user_id, tenant_id):
    # inherited (calls our overriden get_metadata)

    def add_role_to_user_and_tenant(self, user_id, tenant_id, role_id):
        """Add a role to a user within given tenant."""
        raise exception.NotImplemented()

    def remove_role_from_user_and_tenant(self, user_id, tenant_id, role_id):
        """Remove a role from a user within given tenant."""
        raise exception.NotImplemented()

    # user crud
    def create_user(self, user_id, user):
        raise exception.NotImplemented()

    def update_user(self, user_id, user):
        raise exception.NotImplemented()

    def delete_user(self, user_id):
        raise exception.NotImplemented()

    # tenant crud
    # def create_tenant(self, tenant_id, tenant):
    # def update_tenant(self, tenant_id, tenant):
    # def delete_tenant(self, tenant_id, tenant):
    # inherited

    # metadata crud

    def get_metadata(self, user_id, tenant_id):
        if user_id is None or tenant_id is None:
            return []
        tenant_ref = self.get_tenant(tenant_id)
        if not tenant_ref:
            return []
        user_ldap = self.user._ldap_get(user_id)
        if user_ldap is None:
            return []
        if not self._user_is_in_tenant(user_id, user_ldap, tenant_ref):
            return []
        return self._get_metadata_ref(tenant_ref)

    def create_metadata(self, user_id, tenant_id, metadata):
        raise exception.NotImplemented()

    def update_metadata(self, user_id, tenant_id, metadata):
        raise exception.NotImplemented()

    def delete_metadata(self, user_id, tenant_id, metadata):
        raise exception.NotImplemented()

    # role crud
    def create_role(self, role_id, role):
        raise exception.NotImplemented()

    def update_role(self, role_id, role):
        raise exception.NotImplemented()

    def delete_role(self, role_id):
        raise exception.NotImplemented()
