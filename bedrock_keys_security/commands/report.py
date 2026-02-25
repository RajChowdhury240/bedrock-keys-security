"""Report command - incident report generation"""

import click


@click.command()
@click.argument('username')
@click.option('--output', 'output_file', default=None, metavar='FILE', help='Save report to file')
@click.pass_context
def report(ctx, username, output_file):
    """Generate incident report for phantom user"""
    ctx.obj.scanner.generate_incident_report(username, output_file=output_file)
