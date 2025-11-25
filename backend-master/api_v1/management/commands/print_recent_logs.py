from django.core.management.base import BaseCommand
from api_v1.models import OperLog


class Command(BaseCommand):
    help = "Print recent operation logs with elapsed time"

    def add_arguments(self, parser):
        parser.add_argument('--limit', type=int, default=100, help='Number of rows to print')

    def handle(self, *args, **options):
        limit = options.get('limit') or 100
        qs = OperLog.objects.order_by('-id')[:limit]
        self.stdout.write("ID\tCreatedAt\tModule\tAction\tResult\tElapsed(ms)")
        for o in qs:
            self.stdout.write(f"{o.id}\t{o.created_at:%Y-%m-%d %H:%M:%S}\t{o.module}\t{o.action}\t{o.result}\t{o.elapsed_ms}")
