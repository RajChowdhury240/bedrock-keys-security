"""Decode-key command - offline Bedrock API key forensics"""

import json
import sys
import click

from bedrock_keys_security.core.decoder import BedrockKeyDecoder
from bedrock_keys_security.utils.output import format_decode_table_output


@click.command('decode-key')
@click.argument('key')
@click.option('--json', 'output_json', is_flag=True, help='Output as JSON')
def decode_key(key, output_json):
    """Decode Bedrock API key (no AWS credentials needed)"""
    result = BedrockKeyDecoder.decode_key(key)

    # Redact sensitive fields
    if 'full_decoded' in result:
        del result['full_decoded']
    if 'presigned_url' in result:
        del result['presigned_url']
    if 'secret_preview' in result:
        result['secret_preview'] = '[REDACTED]'
    if 'credential_hint' in result:
        result['credential_hint'] = '[REDACTED]'

    if output_json:
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(format_decode_table_output(result))

    sys.exit(0 if 'error' not in result else 1)
