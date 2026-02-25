"""Cleanup command - delete orphaned phantom users"""

import sys
import click


@click.command()
@click.option('--dry-run', is_flag=True, help='Simulate cleanup without deleting')
@click.option('--force', is_flag=True, help='Skip confirmation prompts (DANGEROUS)')
@click.option('--json', 'output_json', is_flag=True, help='Output results as JSON')
@click.pass_context
def cleanup(ctx, dry_run, force, output_json):
    """Delete orphaned phantom users"""
    scanner = ctx.obj.scanner

    phantoms = scanner.find_phantom_users()

    if not output_json:
        click.echo(scanner.generate_table_report(phantoms))

    stats = scanner.cleanup_orphaned_users(phantoms, dry_run=dry_run, force=force)
    sys.exit(0 if stats['failed'] == 0 else 1)
