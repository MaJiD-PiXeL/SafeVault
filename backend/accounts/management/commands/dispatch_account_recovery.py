from django.core.management.base import BaseCommand, CommandError

from accounts.recovery import dispatch_reset_requests, link_origin, EmailDeliveryError


class Command(BaseCommand):
    help = "Process up to 20 queued account password reset requests."

    def handle(self, *args, **options):
        try:
            link_origin()
        except EmailDeliveryError as error:
            raise CommandError(str(error)) from None
        sent, failed = dispatch_reset_requests()
        self.stdout.write(f"Recovery emails sent: {sent}. Delivery failures: {failed}.")
        if failed:
            raise CommandError("Some recovery emails could not be delivered. Check the configured mailer.")
