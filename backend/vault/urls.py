from django.urls import path
from . import views
from . import api_views

app_name = "vault"

urlpatterns = [
    path("", views.home, name="home"),
    path("health/", views.health_check, name="health"),
    path("vaults/", api_views.VaultsView.as_view(), name="vaults"),
    path("vaults/<uuid:vault_id>/entries/", api_views.EntriesView.as_view(), name="entries"),
    path("vaults/<uuid:vault_id>/entries/<uuid:entry_id>/", api_views.EntryView.as_view(), name="entry"),
    path("vaults/<uuid:vault_id>/entries/<uuid:entry_id>/restore/", api_views.EntryRestoreView.as_view(), name="entry-restore"),
    path("vaults/<uuid:vault_id>/entries/<uuid:entry_id>/purge/", api_views.EntryPurgeView.as_view(), name="entry-purge"),
    path("security-settings/", api_views.SecuritySettingsView.as_view(), name="security-settings"),
    path("vaults/<uuid:vault_id>/restores/", api_views.RestoreView.as_view(), name="restore"),
    path("vaults/<uuid:vault_id>/restores/<uuid:backup_id>/", api_views.RestoreReceiptView.as_view(), name="restore-receipt"),
]
