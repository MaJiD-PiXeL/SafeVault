from django.contrib.admin.apps import AdminConfig


class SafeVaultAdminConfig(AdminConfig):
    default_site = "accounts.admin_site.SecondFactorAdminSite"
