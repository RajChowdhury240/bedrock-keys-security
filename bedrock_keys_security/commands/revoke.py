"""Revoke-key command - emergency key revocation"""

import sys
import click


@click.command('revoke-key')
@click.argument('username')
@click.option('--dry-run', is_flag=True, help='Simulate revocation without executing')
@click.pass_context
def revoke_key(ctx, username, dry_run):
    """Emergency revocation of Bedrock API key"""
    success = ctx.obj.scanner.revoke_key(username, dry_run=dry_run)
    sys.exit(0 if success else 1)
