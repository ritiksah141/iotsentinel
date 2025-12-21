"""
Smart Error Messages Utility

Provides contextual error messages with helpful suggestions and recovery steps.
"""

from typing import Dict, Optional, List
from datetime import datetime, timedelta


class ErrorMessages:
    """Centralized error message handling with smart suggestions"""

    # Error message templates
    ERRORS = {
        'invalid_credentials': {
            'title': 'Invalid Credentials',
            'message': 'The username or password you entered is incorrect.',
            'icon': 'fa-exclamation-circle',
            'color': 'danger',
            'suggestions': [
                'Double-check your username and password',
                'Make sure Caps Lock is off',
                'Try resetting your password if you\'ve forgotten it'
            ],
            'action': {
                'text': 'Reset Password',
                'id': 'forgot-password-link'
            }
        },

        'account_locked': {
            'title': 'Account Temporarily Locked',
            'message': 'Too many failed login attempts. Your account has been locked for security.',
            'icon': 'fa-lock',
            'color': 'warning',
            'suggestions': [
                'Wait {lockout_time} before trying again',
                'Contact an administrator if you need immediate access',
                'Use the password reset option to regain access'
            ],
            'recovery_time': 300  # 5 minutes in seconds
        },

        'email_exists': {
            'title': 'Email Already Registered',
            'message': 'An account with this email address already exists.',
            'icon': 'fa-envelope',
            'color': 'warning',
            'suggestions': [
                'Try logging in instead of creating a new account',
                'Use the "Forgot Password" option if you can\'t remember your password',
                'Contact support if you believe this is an error'
            ],
            'action': {
                'text': 'Go to Login',
                'id': 'switch-to-login-tab'
            }
        },

        'username_taken': {
            'title': 'Username Not Available',
            'message': 'This username is already taken.',
            'icon': 'fa-user-times',
            'color': 'warning',
            'suggestions': [
                'Try adding numbers or underscores to your preferred username',
                'Use a variation of your name (e.g., john_doe, johndoe123)',
                'Check the username availability as you type'
            ],
            'alternatives': True  # Will generate username suggestions
        },

        'weak_password': {
            'title': 'Password Too Weak',
            'message': 'Your password doesn\'t meet the security requirements.',
            'icon': 'fa-shield-alt',
            'color': 'danger',
            'suggestions': [
                'Use at least 8 characters',
                'Include uppercase and lowercase letters',
                'Add numbers and special characters (!@#$%)',
                'Avoid common words and patterns'
            ],
            'examples': [
                'MyP@ssw0rd2024 (Good)',
                'Secure#Home99 (Good)',
                'password123 (Weak)'
            ]
        },

        'password_mismatch': {
            'title': 'Passwords Don\'t Match',
            'message': 'The passwords you entered don\'t match.',
            'icon': 'fa-exclamation-triangle',
            'color': 'danger',
            'suggestions': [
                'Make sure both password fields contain the exact same text',
                'Check for extra spaces at the beginning or end',
                'Try typing more carefully or use copy-paste'
            ]
        },

        'invalid_email': {
            'title': 'Invalid Email Format',
            'message': 'Please enter a valid email address.',
            'icon': 'fa-at',
            'color': 'danger',
            'suggestions': [
                'Email should be in the format: name@domain.com',
                'Check for typos in the domain name',
                'Make sure there are no spaces'
            ],
            'examples': [
                'user@example.com (Valid)',
                'john.doe@company.io (Valid)',
                'user@domain (Invalid - missing extension)'
            ]
        },

        'verification_code_invalid': {
            'title': 'Invalid Verification Code',
            'message': 'The verification code you entered is incorrect or has expired.',
            'icon': 'fa-key',
            'color': 'danger',
            'suggestions': [
                'Double-check the code from your email',
                'Make sure you entered all 6 digits',
                'Request a new code if yours has expired (valid for 15 minutes)',
                'Check your spam folder for the verification email'
            ],
            'action': {
                'text': 'Resend Code',
                'id': 'resend-verification-code'
            }
        },

        'verification_code_expired': {
            'title': 'Verification Code Expired',
            'message': 'Your verification code has expired.',
            'icon': 'fa-clock',
            'color': 'warning',
            'suggestions': [
                'Verification codes are valid for 15 minutes only',
                'Click below to receive a new code',
                'Check your email promptly when the new code arrives'
            ],
            'action': {
                'text': 'Send New Code',
                'id': 'send-verification-btn'
            }
        },

        'rate_limited': {
            'title': 'Too Many Attempts',
            'message': 'You\'ve made too many requests. Please slow down.',
            'icon': 'fa-hourglass-half',
            'color': 'warning',
            'suggestions': [
                'Wait {wait_time} before trying again',
                'This helps protect against automated attacks',
                'Contact support if you need immediate assistance'
            ],
            'show_countdown': True
        },

        'network_error': {
            'title': 'Connection Error',
            'message': 'Unable to connect to the server.',
            'icon': 'fa-wifi',
            'color': 'danger',
            'suggestions': [
                'Check your internet connection',
                'Refresh the page and try again',
                'Make sure the server is running',
                'Contact your network administrator if the problem persists'
            ]
        },

        'session_expired': {
            'title': 'Session Expired',
            'message': 'Your session has expired. Please log in again.',
            'icon': 'fa-user-clock',
            'color': 'info',
            'suggestions': [
                'Your session expired for security reasons',
                'Use "Remember Me" to stay logged in for 7 days',
                'Make sure cookies are enabled in your browser'
            ],
            'action': {
                'text': 'Log In Again',
                'id': 'login-button'
            }
        },

        'token_invalid': {
            'title': 'Invalid or Expired Link',
            'message': 'This password reset link is invalid or has expired.',
            'icon': 'fa-link',
            'color': 'danger',
            'suggestions': [
                'Password reset links expire after 1 hour',
                'Request a new password reset link',
                'Make sure you used the complete link from the email',
                'Try copying and pasting the link instead of clicking it'
            ],
            'action': {
                'text': 'Request New Link',
                'id': 'forgot-password-link'
            }
        },

        'email_send_failed': {
            'title': 'Email Delivery Failed',
            'message': 'We couldn\'t send the email. Please try again.',
            'icon': 'fa-envelope-open',
            'color': 'danger',
            'suggestions': [
                'Check that your email address is correct',
                'Make sure the SMTP server is configured',
                'Try again in a few moments',
                'Contact support if the problem continues'
            ]
        },

        'generic_error': {
            'title': 'Something Went Wrong',
            'message': 'An unexpected error occurred.',
            'icon': 'fa-bug',
            'color': 'danger',
            'suggestions': [
                'Refresh the page and try again',
                'Clear your browser cache',
                'Try using a different browser',
                'Contact support if the error persists'
            ]
        }
    }

    @classmethod
    def get_error(cls, error_type: str, **kwargs) -> Dict:
        """
        Get formatted error message with suggestions

        Args:
            error_type: Type of error (key from ERRORS dict)
            **kwargs: Additional context (e.g., wait_time, lockout_time)

        Returns:
            Dict with error details and formatted suggestions
        """
        error_data = cls.ERRORS.get(error_type, cls.ERRORS['generic_error']).copy()

        # Format suggestions with provided kwargs
        if 'suggestions' in error_data:
            error_data['suggestions'] = [
                suggestion.format(**kwargs) for suggestion in error_data['suggestions']
            ]

        # Add timestamp
        error_data['timestamp'] = datetime.now().isoformat()

        # Add error type
        error_data['error_type'] = error_type

        return error_data

    @classmethod
    def get_username_suggestions(cls, attempted_username: str, count: int = 3) -> List[str]:
        """
        Generate alternative username suggestions

        Args:
            attempted_username: The username that was taken
            count: Number of suggestions to generate

        Returns:
            List of suggested alternative usernames
        """
        import random

        suggestions = []
        base = attempted_username.rstrip('0123456789_-')

        # Add number suffixes
        suggestions.append(f"{base}{random.randint(10, 99)}")
        suggestions.append(f"{base}{random.randint(100, 999)}")

        # Add underscore variations
        suggestions.append(f"{base}_{random.randint(1, 99)}")

        # Add year
        current_year = datetime.now().year
        suggestions.append(f"{base}{current_year}")

        # Add random suffix
        suffixes = ['_dev', '_user', '_pro', '_tech', '_iot']
        suggestions.append(f"{base}{random.choice(suffixes)}")

        # Return unique suggestions
        return list(set(suggestions))[:count]

    @classmethod
    def format_countdown(cls, seconds: int) -> str:
        """
        Format seconds into human-readable countdown

        Args:
            seconds: Number of seconds

        Returns:
            Formatted string (e.g., "5 minutes", "30 seconds")
        """
        if seconds < 60:
            return f"{seconds} second{'s' if seconds != 1 else ''}"

        minutes = seconds // 60
        remaining_seconds = seconds % 60

        if remaining_seconds == 0:
            return f"{minutes} minute{'s' if minutes != 1 else ''}"
        else:
            return f"{minutes} minute{'s' if minutes != 1 else ''} and {remaining_seconds} second{'s' if remaining_seconds != 1 else ''}"

    @classmethod
    def get_rate_limit_message(cls, retry_after: int) -> Dict:
        """
        Get formatted rate limit error with countdown

        Args:
            retry_after: Seconds until user can retry

        Returns:
            Error dict with formatted wait time
        """
        wait_time = cls.format_countdown(retry_after)
        return cls.get_error('rate_limited', wait_time=wait_time)

    @classmethod
    def get_account_locked_message(cls, locked_until: datetime) -> Dict:
        """
        Get formatted account locked error with time remaining

        Args:
            locked_until: DateTime when account will be unlocked

        Returns:
            Error dict with formatted lockout time
        """
        now = datetime.now()
        if locked_until > now:
            seconds_remaining = int((locked_until - now).total_seconds())
            lockout_time = cls.format_countdown(seconds_remaining)
        else:
            lockout_time = "a few moments"

        return cls.get_error('account_locked', lockout_time=lockout_time)

    @classmethod
    def create_inline_error(cls, error_type: str, **kwargs) -> str:
        """
        Create HTML for inline error message display

        Args:
            error_type: Type of error
            **kwargs: Additional context

        Returns:
            HTML string for inline error
        """
        error = cls.get_error(error_type, **kwargs)

        html = f'''
        <div class="error-message-inline" style="
            background: rgba(239, 68, 68, 0.1);
            border-left: 4px solid var(--danger-color);
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        ">
            <div style="display: flex; align-items: start; gap: 0.75rem;">
                <i class="fa {error['icon']}" style="color: var(--danger-color); font-size: 1.25rem; margin-top: 0.25rem;"></i>
                <div style="flex: 1;">
                    <h6 style="margin: 0 0 0.5rem 0; color: var(--danger-color); font-weight: 600;">
                        {error['title']}
                    </h6>
                    <p style="margin: 0 0 0.75rem 0; color: var(--text-primary); font-size: 0.9rem;">
                        {error['message']}
                    </p>
                    {''.join([f'<div style="color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 0.25rem;"><i class="fa fa-check-circle" style="color: var(--accent-color); margin-right: 0.5rem;"></i>{suggestion}</div>' for suggestion in error.get('suggestions', [])])}
                </div>
            </div>
        </div>
        '''

        return html


# Convenience functions for common errors
def invalid_credentials():
    return ErrorMessages.get_error('invalid_credentials')

def email_exists():
    return ErrorMessages.get_error('email_exists')

def username_taken(attempted_username: str):
    error = ErrorMessages.get_error('username_taken')
    error['username_suggestions'] = ErrorMessages.get_username_suggestions(attempted_username)
    return error

def weak_password():
    return ErrorMessages.get_error('weak_password')

def password_mismatch():
    return ErrorMessages.get_error('password_mismatch')

def invalid_email():
    return ErrorMessages.get_error('invalid_email')

def verification_code_invalid():
    return ErrorMessages.get_error('verification_code_invalid')

def verification_code_expired():
    return ErrorMessages.get_error('verification_code_expired')

def rate_limited(retry_after: int):
    return ErrorMessages.get_rate_limit_message(retry_after)

def account_locked(locked_until: datetime):
    return ErrorMessages.get_account_locked_message(locked_until)

def session_expired():
    return ErrorMessages.get_error('session_expired')

def token_invalid():
    return ErrorMessages.get_error('token_invalid')

def network_error():
    return ErrorMessages.get_error('network_error')

def email_send_failed():
    return ErrorMessages.get_error('email_send_failed')
