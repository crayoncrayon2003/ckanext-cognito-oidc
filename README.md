# ckanext-cognito-oidc

OpenID connect authenticator for CKAN.

This plugin is under development for Amazon Cognito.

And This plugin refers to the [ckanext-oidc-pkce](https://github.com/DataShades/ckanext-oidc-pkce)


The plugin adds an extra route to CKAN allowing login through an external
application. This route available at `/user/login/cognito-oidc`.
Original authentication system from CKAN is unchanged and it's up to
you(or another extension) to hide original login page if only SSO accounts are
allowed on the portal.

## Requirements

Compatibility with core CKAN versions:

| CKAN version    | Compatible?   |
| --------------- | ------------- |
| 2.9             | yes           |
| 3.10            | yes           |

## Installation

1. Install the package
   ```sh
   pip install ckanext-cognito-oidc
   ```

2. Add `cognito_oidc` to the `ckan.plugins` setting in your CKAN config file

3. Add SSO settings(refer [config settings](#config-settings) section for details)

## Config settings

```ini
# URL of SSO application
# Could be overriden at runtime with env var CKANEXT_COGNITO_OIDC_BASE_URL
ckanext.cognito_oidc.base_url = https://12345.example.cognito.com

# ClientID of SSO application
# Could be overriden at runtime with env var CKANEXT_COGNITO_OIDC_CLIENT_ID
ckanext.cognito_oidc.client_id = clientid

# ClientSecret of SSO application
# (optional, only need id Client App defines a secret, default: "")
# Could be overriden at runtime with env var CKANEXT_COGNITO_OIDC_CLIENT_SECRET
ckanext.cognito_oidc.client_secret = clientsecret

# Path to the authorization endpont inside SSO application
# (optional, default: /oauth2/default/v1/authorize)
ckanext.cognito_oidc.auth_path = /oauth2/authorize

# Path to the token endpont inside SSO application
# (optional, default: /oauth2/default/v1/token)
ckanext.cognito_oidc.token_path = /oauth2/token

# Path to the userinfo endpont inside SSO application
# (optional, default: /oauth2/default/v1/userinfo)
ckanext.cognito_oidc.userinfo_path = /oauth2/userinfo

# Path to the authentication response handler inside CKAN application
# (optional, default: /user/login/cognito_oidc/callback)
ckanext.cognito_oidc.redirect_path = /local/oidc/handler

# URL to redirect user in case of failed login attempt.  When empty(default)
# redirects to `came_from` URL parameter if availabe or to CKAN login page
# otherwise.
# (optional, default: )
ckanext.cognito_oidc.error_redirect = /user/register

# Scope of the authorization token. The plugin expects at least `sub`,
# `email` and `name` attributes.
# (optional, default: openid email profile)
ckanext.cognito_oidc.scope = openid+profile+aws.cognito.signin.user.admin

# For newly created CKAN users use the same ID as one from SSO application
# (optional, default: false)
ckanext.cognito_oidc.use_same_id = false

# When connecting to an existing(non-sso) account, override user's password
# so that it becomes impossible to login using CKAN authentication system.
# Enable this flag if you want to force SSO-logins for all users that once
# used SSO-login.
# (optional, default: false)
ckanext.cognito_oidc.munge_password = false

```

## Note
Userinfo Endpoints have standard attributes based on the OpenID Connect specification.

Amazon Cognito assigns all users a set of standard attributes based on the OpenID Connect specification. But standard attributes are optional by default for all users.([Developer Guide](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html))

This plugin replace attribute with the following.

* conditions : No "name" attribute in UserInfo response
* behavior   : treats attribute "username" as attribute "name"


## License

[AGPL](https://www.gnu.org/licenses/agpl-3.0.en.html)
