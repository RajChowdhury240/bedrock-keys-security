"""Timeline command - CloudTrail timeline generation"""

import click


@click.command()
@click.argument('username')
@click.option('--days', type=int, default=7, help='Days to look back (default: 7)')
@click.pass_context
def timeline(ctx, username, days):
    """Generate CloudTrail timeline for phantom user"""
    ctx.obj.scanner.generate_timeline(username, days=days)
