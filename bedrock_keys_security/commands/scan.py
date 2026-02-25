"""Scan command - discover phantom IAM users"""

import click


@click.command()
@click.option('--json', 'output_json', is_flag=True, help='Output results as JSON')
@click.option('--csv', 'csv_file', default=None, metavar='FILE', help='Export results to CSV file')
@click.pass_context
def scan(ctx, output_json, csv_file):
    """Scan for phantom IAM users (default command)"""
    scanner = ctx.obj.scanner

    phantoms = scanner.find_phantom_users()

    if output_json:
        click.echo(scanner.generate_json_report(phantoms))
    elif csv_file:
        click.echo(scanner.generate_table_report(phantoms))
        scanner.generate_csv_report(phantoms, csv_file)
    else:
        click.echo(scanner.generate_table_report(phantoms))
