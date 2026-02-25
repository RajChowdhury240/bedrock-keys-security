"""Offline forensic decoder for AWS Bedrock API keys"""

import base64
import re
import urllib.parse
from typing import Dict, Optional


class BedrockKeyDecoder:
    """Decoder for AWS Bedrock API keys"""

    LONG_TERM_PREFIX = "ABSK"
    SHORT_TERM_PREFIX = "bedrock-api-key-"

    @staticmethod
    def detect_key_type(key: str) -> Optional[str]:
        """
        Detect the type of Bedrock API key

        Args:
            key: The API key string

        Returns:
            'long-term', 'short-term', or None
        """
        if key.startswith(BedrockKeyDecoder.LONG_TERM_PREFIX):
            return 'long-term'
        elif key.startswith(BedrockKeyDecoder.SHORT_TERM_PREFIX):
            return 'short-term'
        else:
            return None

    @staticmethod
    def decode_long_term_key(key: str) -> Dict:
        """
        Decode ABSK (long-term) Bedrock API key

        Format: ABSK + base64(BedrockAPIKey-{id}-at-{account_id}:{secret})

        Args:
            key: The ABSK... key string

        Returns:
            Dictionary with decoded information
        """
        try:
            # Remove ABSK prefix
            encoded_part = key[len(BedrockKeyDecoder.LONG_TERM_PREFIX):]

            # Base64 decode (add padding if needed)
            encoded_part += '=' * (-len(encoded_part) % 4)
            decoded_bytes = base64.b64decode(encoded_part)
            decoded_str = decoded_bytes.decode('utf-8')

            # Parse format: BedrockAPIKey-xxx-at-ACCOUNTID:secret
            if '-at-' not in decoded_str:
                return {
                    'error': 'Invalid format: missing -at- separator',
                    'decoded_string': decoded_str
                }

            parts = decoded_str.split('-at-')
            username = parts[0]

            if ':' not in parts[1]:
                return {
                    'error': 'Invalid format: missing : separator',
                    'decoded_string': decoded_str
                }

            account_secret = parts[1].split(':', 1)
            account_id = account_secret[0]
            secret_preview = account_secret[1][:8] + '...' if len(account_secret[1]) > 8 else account_secret[1]

            return {
                'type': 'long-term',
                'format': 'ABSK + base64(username-at-accountid:secret)',
                'username': username,
                'account_id': account_id,
                'secret_preview': secret_preview,
                'full_decoded': decoded_str,
                'security_notes': [
                    'AWS Account ID disclosed (enables reconnaissance)',
                    'IAM username disclosed (enables targeted attacks)',
                    'ABSK prefix enables automated secret scanning',
                    'Credential persists until explicitly revoked'
                ]
            }

        except Exception as e:
            return {
                'error': f'Decoding failed: {str(e)}',
                'type': 'long-term'
            }

    @staticmethod
    def decode_short_term_key(key: str) -> Dict:
        """
        Decode short-term Bedrock API key

        Format: bedrock-api-key- + base64(presigned_url)

        Args:
            key: The bedrock-api-key-... string

        Returns:
            Dictionary with decoded information
        """
        try:
            # Remove prefix
            encoded_part = key[len(BedrockKeyDecoder.SHORT_TERM_PREFIX):]

            # Base64 decode to get presigned URL
            decoded_bytes = base64.b64decode(encoded_part)
            decoded_url = decoded_bytes.decode('utf-8')

            # Parse URL
            parsed = urllib.parse.urlparse(decoded_url)
            params = urllib.parse.parse_qs(parsed.query)

            # Extract information
            action = params.get('Action', ['Unknown'])[0]
            expires = params.get('X-Amz-Expires', ['Unknown'])[0]
            credential = params.get('X-Amz-Credential', ['Unknown'])[0]
            date = params.get('X-Amz-Date', ['Unknown'])[0]

            # Parse region from credential string (format: AccessKeyID/date/region/service/aws4_request)
            region = 'Unknown'
            cred_parts = credential.split('/')
            if len(cred_parts) >= 3:
                region = cred_parts[2]

            # Extract account ID from security token
            account_id = 'Unknown'
            security_token = params.get('X-Amz-Security-Token', [''])[0]
            if security_token:
                try:
                    # Security token is base64-encoded and contains the account ID
                    token_decoded = base64.b64decode(security_token + '==').decode('utf-8', errors='ignore')
                    # Look for 12-digit account ID pattern
                    account_match = re.search(r'(\d{12})', token_decoded)
                    if account_match:
                        account_id = account_match.group(1)
                except Exception:
                    pass

            return {
                'type': 'short-term',
                'format': 'bedrock-api-key- + base64(presigned_url)',
                'presigned_url': decoded_url,
                'action': action,
                'region': region,
                'account_id': account_id,
                'expires_in_seconds': expires,
                'date': date,
                'credential_hint': credential[:30] + '...' if len(credential) > 30 else credential,
                'security_notes': [
                    'Temporary credential with time-limited validity',
                    'Cannot be revoked (must wait for expiration)',
                    'Presigned URL contains AWS credentials',
                    f'Expires in {expires} seconds from creation'
                ]
            }

        except Exception as e:
            return {
                'error': f'Decoding failed: {str(e)}',
                'type': 'short-term'
            }

    @staticmethod
    def decode_key(key: str) -> Dict:
        """
        Auto-detect and decode any Bedrock API key

        Args:
            key: The API key string

        Returns:
            Dictionary with decoded information
        """
        key_type = BedrockKeyDecoder.detect_key_type(key)

        if key_type == 'long-term':
            return BedrockKeyDecoder.decode_long_term_key(key)
        elif key_type == 'short-term':
            return BedrockKeyDecoder.decode_short_term_key(key)
        else:
            return {
                'error': 'Unknown key format',
                'expected_formats': [
                    'ABSK... (long-term key)',
                    'bedrock-api-key-... (short-term key)'
                ]
            }
