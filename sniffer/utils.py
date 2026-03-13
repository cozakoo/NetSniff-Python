from rich.console import Console
from rich.table import Table
import logging

console = Console()

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler("sniffer.log"), logging.StreamHandler()]
    )

def print_stats(stats: dict):
    table = Table(title="Estadísticas de captura")
    table.add_column("Métrica", style="cyan")
    table.add_column("Valor", style="green")
    for k, v in stats.items():
        table.add_row(k, str(v))
    console.print(table)