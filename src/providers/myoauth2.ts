import { IProvider } from 'react-simple-auth'

/*jwt playload sample
{
    "sub": "subject",
    "aud": ["product_api"],
    "nbf": 1539526040597,
    "user_name": "product_admin",
    "scope": ["read", "write"],
    "iss": "issuer",
    "exp": 1539526100,
    "iat": 1539526040597,
    "authorities": ["ROLE_PRODUCT_ADMIN"],
    "jti": "b0c49780-63a2-4be5-b0f2-2530855df856",
    "client_id": "curl_client"
};
*/

/*
implicit request:
http://localhost:8081/oauth/authorize?response_type=token&client_id=curl_client&redirect_uri=http%3a%2f%2flocalhost

Logon success and redirect
http://localhost/#access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdWJqZWN0IiwiYXVkIjpbInByb2R1Y3RfYXBpIl0sIm5iZiI6MTUzOTUyNzQ5NzU1NywidXNlcl9uYW1lIjoib2F1dGhfYWRtaW4iLCJzY29wZSI6WyJyZWFkIiwid3JpdGUiXSwiaXNzIjoiaXNzdWVyIiwiZXhwIjoxNTM5NTI3NTU3LCJpYXQiOjE1Mzk1Mjc0OTc1NTcsImF1dGhvcml0aWVzIjpbIlJPTEVfT0FVVEhfQURNSU4iXSwianRpIjoiZDFhOWRkOWQtODM5My00ZmQwLWJkNjUtY2ZjNzYwNjQwY2QyIiwiY2xpZW50X2lkIjoiY3VybF9jbGllbnQifQ.I6qj2ScbB6Ga4kN6v14YiVq3X-S-2mYj_8ZB1m_UkrQ
&token_type=bearer
&expires_in=59
&scope=read%20write

Logon error
http://localhost:8081/login?error
*/

export interface IdToken {
    iss: string
    sub: string
    aud: string
    exp: number
    iat: number
    nbf: number
    user_name: string
    at_hash: string
    nonce: string
}

export interface Session {
    accessToken: string
    expireDurationSeconds: number
//    idToken: string
    decodedIdToken: IdToken
}

export const microsoftProvider: IProvider<Session> = {
    buildAuthorizeUrl() {
        return `http://localhost:8081/oauth/authorize?response_type=token&client_id=curl_client&scope=read
        &redirect_uri=${encodeURIComponent(`${window.location.origin}/redirect.html`)}`
    },

    extractError(redirectUrl: string): Error | undefined {
        const errorMatch = redirectUrl.match(/error=([^&]+)/)
        if (!errorMatch) {
            return undefined
        }

        const errorReason = errorMatch[1]
        const errorDescriptionMatch = redirectUrl.match(/error_description=([^&]+)/)
        const errorDescription = errorDescriptionMatch ? errorDescriptionMatch[1] : ''
        return new Error(`Error during login. Reason: ${errorReason} Description: ${errorDescription}`)
    },

    extractSession(redirectUrl: string): Session {
        let accessToken: string = null!
        let decodedIdToken: IdToken = null!
        const accessTokenMatch = redirectUrl.match(/access_token=([^&]+)/)
        if (accessTokenMatch) {
            accessToken = accessTokenMatch[1]
            decodedIdToken = JSON.parse(atob(accessToken.split('.')[1]))
            // TODO validate token playload hash with hash from server
        }

        let expireDurationSeconds: number = 3600
        const expireDurationSecondsMatch = redirectUrl.match(/expires_in=([^&]+)/)
        if (expireDurationSecondsMatch) {
            expireDurationSeconds = parseInt(expireDurationSecondsMatch[1], 10)
        }

        return {
            accessToken,
            expireDurationSeconds,
            decodedIdToken
        }
    },

    validateSession(session: Session): boolean {
        const now = (new Date()).getTime() / 1000

        // With normal JWT tokens you can inspect the `exp` Expiration claim; however,
        // AAD V2 tokens are opaque and we must use the token meta about expiration time
        // "When you request an access token from the v2.0 endpoint, the v2.0 endpoint also returns metadata about the access token for your app to use."
        // See: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-tokens
        // Here we are leveraging the fact that the access token was issued at the same
        // time as the ID token and can use its `iat` Issued At claim + the duration
        // to compute an absolute expiration time
        const expiration = session.decodedIdToken.iat + session.expireDurationSeconds

        // 30 seconds minimum duration until token expires
        const minimumDuration = 30
        return (expiration - now) > minimumDuration
    },

    getAccessToken(session: Session, resourceId: string): string {
        return session.accessToken
    },

    getSignOutUrl(redirectUrl: string): string {
        return `https://login.microsoftonline.com/common/oauth2/v2.0/logout?post_logout_redirect_uri=${encodeURIComponent(redirectUrl)}`
    }
}