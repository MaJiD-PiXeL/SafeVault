from django.contrib.admin import AdminSite


class SecondFactorAdminSite(AdminSite):
    def has_permission(self, request):
        if not super().has_permission(request):
            return False
        from .mfa import session_verified
        return session_verified(request)
