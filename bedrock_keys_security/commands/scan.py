"""Scan command - discover phantom IAM users"""

import click

from bedrock_keys_security.utils import output


@click.command()
@click.option('--json', 'output_json', is_flag=True, help='Output results as JSON')
@click.option('--csv', 'csv_file', default=None, metavar='FILE', help='Export results to CSV file')
@click.pass_context
def scan(ctx, output_json, csv_file):
    """Scan for phantom IAM users (default command)"""
    scanner = ctx.obj.scanner

    if not output_json:
        click.echo(scanner.report_header())

    if output_json:
        phantoms = scanner.find_phantom_users()
        click.echo(scanner.generate_json_report(phantoms))
    else:
        with output.spinner():
            phantoms = scanner.find_phantom_users()
        click.echo(scanner.generate_table_report(phantoms))
        if csv_file:
            scanner.generate_csv_report(phantoms, csv_file)
