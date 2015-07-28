# Wordpress Authserver login plugin

This plugin replaces the standard Wordpress password-based login with a centralised one based on OAuth, named [Authserver](https://github.com/vierbergenlars/authserver). 

## Installation

1. Copy extension into `wp-content/plugins`
2. Run `composer install`
3. Register a new OAuth application in Authserver. Set its redirect URL to the `wp-login.php` page of the wordpress installation.

## Configuration

First run this query against your database (replace `wp_` by your database prefix), then activate the plugin.

```sql
INSERT INTO wp_options (option_name, option_value) VALUES
('authserver_login_authorize_url', '<authorize url>'), -- Ex: https://idp.industria.be/oauth/v2/auth
('authserver_login_token_url', '<token url>'), -- Ex: https://idp.industria.be/oauth/v2/token
('authserver_login_user_url', '<user api endpoint url>'), -- Ex: https://idp.industria.be/api/user
('authserver_login_logout_url', '<after logout redirect>'), -- Ex: https://idp.industria.be/usr/kill-session
('authserver_login_client_id', '<oauth application client id>'), -- From OAuth client page
('authserver_login_client_secret', '<oauth application client secret>'), -- From OAuth client page
('authserver_login_group_prefix', '<user group prefix>'); -- Common prefix for authserver groups that will be recognized as wordpress roles for the user.
```

## Authserver group to wordpress role synchronisation

This plugin allows all users with an account on authserver to login to the wordpress installation, but they will not have
any permissions.

To grant users certain permissions, you have to place them into a group prefixed with the value from `authserver_login_group_prefix`.
All wordpress roles are valid group names. 
These are roles in a default wordpress installation, be aware that plugins can add extra roles.

* `administrator`
* `editor`
* `author`
* `contributor`
* `subscriber`

If a user is a member of multiple groups that correspond to different roles, the union of all permissions granted by these roles will be taken.

To use custom sets of capabilities, install or build a plugin that adds one or more roles. (Refer to the [Wordpress documentation](https://developer.wordpress.org/plugins/users/roles-and-capabilities/) for more information.)

### Example

`authserver_login_group_prefix` is `wordpress_`

Alice is member of authserver groups `administrator` and `wordpress_author`. She will be granted the `author` role when logged in into wordpress.
Bob is member of authserver groups `wordpress_contributor` and `wordpress_administrator`. He will be granted the capabilities from both the `contributor` role and the `administrator` role.