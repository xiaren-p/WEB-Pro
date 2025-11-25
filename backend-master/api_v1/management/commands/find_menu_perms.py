from django.core.management.base import BaseCommand
from api_v1.models import Menu


class Command(BaseCommand):
    help = "Find menus by permission token substring"

    def add_arguments(self, parser):
        parser.add_argument('token', nargs='?', default='notice')

    def handle(self, *args, **options):
        token = options.get('token')
        qs = Menu.objects.filter(perms__icontains=token)
        for m in qs:
            self.stdout.write(f"id={m.id} name={m.name} perms={m.perms}")
        if not qs.exists():
            self.stdout.write("no matches")
