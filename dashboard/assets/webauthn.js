/**
 * WebAuthn Client-Side Handler
 *
 * Handles biometric authentication using Web Authentication API
 * Supports Touch ID, Face ID, Windows Hello, and hardware security keys
 */

// Check if WebAuthn is supported
function isWebAuthnSupported() {
    return window.PublicKeyCredential !== undefined &&
           navigator.credentials !== undefined;
}

// Convert base64url to ArrayBuffer
function base64urlToBuffer(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padLen = (4 - (base64.length % 4)) % 4;
    const padded = base64 + '='.repeat(padLen);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

// Convert ArrayBuffer to base64url
function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// Register a new biometric credential
async function registerBiometric(username) {
    try {
        // Check support
        if (!isWebAuthnSupported()) {
            throw new Error('WebAuthn is not supported on this browser');
        }

        // Get registration options from server
        const optionsResponse = await fetch('/api/webauthn/register/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username })
        });

        if (!optionsResponse.ok) {
            throw new Error('Failed to get registration options');
        }

        const options = await optionsResponse.json();

        // Convert challenge and user ID to ArrayBuffer
        const publicKeyOptions = {
            ...options,
            challenge: base64urlToBuffer(options.challenge),
            user: {
                ...options.user,
                id: base64urlToBuffer(options.user.id)
            },
            excludeCredentials: options.excludeCredentials?.map(cred => ({
                ...cred,
                id: base64urlToBuffer(cred.id)
            })) || []
        };

        // Call Web Authentication API
        const credential = await navigator.credentials.create({
            publicKey: publicKeyOptions
        });

        if (!credential) {
            throw new Error('Failed to create credential');
        }

        // Prepare credential for server
        const credentialData = {
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            type: credential.type,
            response: {
                attestationObject: bufferToBase64url(credential.response.attestationObject),
                clientDataJSON: bufferToBase64url(credential.response.clientDataJSON)
            }
        };

        // Send to server for verification
        const verifyResponse = await fetch('/api/webauthn/register/verify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                credential: credentialData,
                challenge_key: options.challenge_key,
                device_name: getDeviceName()
            })
        });

        if (!verifyResponse.ok) {
            throw new Error('Failed to verify registration');
        }

        const result = await verifyResponse.json();
        return result;

    } catch (error) {
        console.error('Biometric registration error:', error);
        throw error;
    }
}

// Authenticate with biometric
async function authenticateBiometric(username = null) {
    try {
        // Check support
        if (!isWebAuthnSupported()) {
            throw new Error('WebAuthn is not supported on this browser');
        }

        // Get authentication options from server
        const optionsResponse = await fetch('/api/webauthn/login/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username })
        });

        if (!optionsResponse.ok) {
            throw new Error('Failed to get authentication options');
        }

        const options = await optionsResponse.json();

        // Convert challenge and allowed credentials to ArrayBuffer
        const publicKeyOptions = {
            ...options,
            challenge: base64urlToBuffer(options.challenge),
            allowCredentials: options.allowCredentials?.map(cred => ({
                ...cred,
                id: base64urlToBuffer(cred.id)
            })) || []
        };

        // Call Web Authentication API
        const credential = await navigator.credentials.get({
            publicKey: publicKeyOptions
        });

        if (!credential) {
            throw new Error('Failed to get credential');
        }

        // Prepare credential for server
        const credentialData = {
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            type: credential.type,
            response: {
                authenticatorData: bufferToBase64url(credential.response.authenticatorData),
                clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                signature: bufferToBase64url(credential.response.signature),
                userHandle: credential.response.userHandle ?
                    bufferToBase64url(credential.response.userHandle) : null
            }
        };

        // Send to server for verification
        const verifyResponse = await fetch('/api/webauthn/login/verify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                credential: credentialData,
                challenge_key: options.challenge_key
            })
        });

        if (!verifyResponse.ok) {
            throw new Error('Failed to verify authentication');
        }

        const result = await verifyResponse.json();
        return result;

    } catch (error) {
        console.error('Biometric authentication error:', error);
        throw error;
    }
}

// Get device name for credential
function getDeviceName() {
    const ua = navigator.userAgent;
    let deviceName = 'Unknown Device';

    // Detect platform
    if (ua.includes('Mac OS X')) {
        deviceName = 'Mac';
        if (ua.includes('Safari') && !ua.includes('Chrome')) {
            deviceName += ' (Touch ID)';
        }
    } else if (ua.includes('Windows NT')) {
        deviceName = 'Windows PC (Windows Hello)';
    } else if (ua.includes('iPhone')) {
        deviceName = 'iPhone (Face ID/Touch ID)';
    } else if (ua.includes('iPad')) {
        deviceName = 'iPad (Face ID/Touch ID)';
    } else if (ua.includes('Android')) {
        deviceName = 'Android Device';
    } else if (ua.includes('Linux')) {
        deviceName = 'Linux PC';
    }

    return deviceName;
}

// Show/hide biometric button based on support
function toggleBiometricUI() {
    const biometricButton = document.getElementById('biometric-login-btn');
    if (biometricButton) {
        if (isWebAuthnSupported()) {
            biometricButton.style.display = 'block';
        } else {
            biometricButton.style.display = 'none';
        }
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    toggleBiometricUI();
});

// Export functions for use in Dash callbacks
window.WebAuthnClient = {
    isSupported: isWebAuthnSupported,
    register: registerBiometric,
    authenticate: authenticateBiometric,
    toggleUI: toggleBiometricUI
};
