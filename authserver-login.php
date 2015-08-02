<?php
/*
Plugin Name: Authserver Login
Plugin URI: https://github.com/IndustriaLeuven/wordpress-login-authserver
Description: Log in to wordpress with AuthServer
Version: 1.1
Author: Lars Vierbergen
Author URI: http://lars.vbgn.be
License: AGPL
License URI: https://gnu.org/licenses/agpl.html
*/

use fkooman\Guzzle\Plugin\BearerAuth\BearerAuth;
use fkooman\Guzzle\Plugin\BearerAuth\Exception\BearerErrorResponseException;
use fkooman\OAuth\Client\Api;
use fkooman\OAuth\Client\Callback;
use fkooman\OAuth\Client\ClientConfig;
use fkooman\OAuth\Client\Context;
use fkooman\OAuth\Client\Exception\AuthorizeException;
use fkooman\OAuth\Client\Exception\CallbackException;
use fkooman\OAuth\Client\SessionStorage;
use Guzzle\Http\Client;

require __DIR__.'/vendor/autoload.php';

if(!defined('WPINC'))
    exit;

add_filter('authenticate', 'authserver_login_authenticate', 1);

function authserver_login_authenticate($user)
{
    if(is_wp_error($user))
        return $user;

    $clientConfig = new ClientConfig(array(
        'authorize_endpoint' => get_option('authserver_login_authorize_url'),
        'client_id' => get_option('authserver_login_client_id'),
        'client_secret' => get_option('authserver_login_client_secret'),
        'token_endpoint' => get_option('authserver_login_token_url'),
        'redirect_uri' => wp_login_url(@$_GET['redirect_to']),
    ));

    $tokenStorage = new SessionStorage();
    $client = new Client();
    $api = new Api("authserver", $clientConfig, $tokenStorage, $client);
    $context = new Context("u", array("profile:username", "profile:realname", "profile:groups"));

    if(isset($_GET['code']) || isset($_GET['error'])) {
        try {
            $callback = new Callback("authserver", $clientConfig, $tokenStorage, $client);
            $callback->handleCallback($_GET);
        } catch(AuthorizeException $ex) {
            $error =  new WP_Error('authserver_login', 'Authentication error: '.$ex->getMessage());
            goto fail;
        } catch(CallbackException $ex) {
            $error = new WP_Error('authserver_login', 'Authentication error: '.$ex->getMessage());
            goto fail;
        }
    }

    $accessToken = $api->getAccessToken($context);
    if($accessToken === false) {
        header('HTTP/1.1 302 Found');
        header('Location: '.$api->getAuthorizeUri($context));
        exit;
    }

    try {
        $client->addSubscriber(new BearerAuth($accessToken->getAccessToken()));
        $response = $client->get(get_option('authserver_login_user_url'))
            ->send()
            ->json();
    } catch(BearerErrorResponseException $ex) {
        if($ex->getBearerReason() === 'invalid_token') {
            $api->deleteAccessToken($context);
            $api->deleteRefreshToken($context);
            header('HTTP/1.1 302 Found');
            header('Location: '.$api->getAuthorizeUri($context));
            exit;
        }
        $error = new WP_Error('authserver_login', 'Authentication error: '.$ex->getMessage());
        goto fail;
    }

    $group_prefix = get_option('authserver_login_group_prefix');
    $groups = array_map(
        function ($group) use($group_prefix) {
            return substr($group, strlen($group_prefix));
        },
        array_filter($response['groups'], function ($group) use ($group_prefix) {
            return strpos($group, $group_prefix) === 0;
        })
    );

    $user = get_user_by('email', $response['guid'].'@noreply.industria.be');

    // If no user exists: create a new one.
    if(!$user) {
        $i=0;
        do {
            $userId = wp_create_user($response['username'].str_repeat('_', $i++), '', $response['guid'].'@noreply.industria.be');
        } while(is_wp_error($userId) && $i < 15);

        if(is_wp_error($userId))  {
            $error = $userId;
            goto fail;

        }
        $user = get_user_by('id', $userId);
        $user->show_admin_bar_front = "false";
    }

    $user->display_name = $response['name'];
    $names = explode(' ', $response['name'], 2);
    $user->first_name = $names[0];
    $user->last_name = isset($names[1])?$names[1]:'';
    $user->nickname = $response['username'];
    $user->user_email = $response['guid'].'@noreply.industria.be';

    foreach($user->roles as $role) {
        if(!in_array($role, $groups))
            $user->remove_role($role);
    }

    foreach($groups as $group) {
        if(get_role($group))
            $user->add_role($group);
    }
    wp_update_user($user);


    $api->deleteAccessToken($context);
    $api->deleteRefreshToken($context);
    return $user;

fail:
    $api->deleteAccessToken($context);
    $api->deleteRefreshToken($context);
    return $error;
}

add_filter('wp_logout', 'authserver_login_logout');

function authserver_login_logout()
{
    header('Location: '.get_option('authserver_login_logout_url'));
    exit;
}

add_filter('login_redirect', 'authserver_login_login_redirect', 10, 3);

function authserver_login_login_redirect($redirect_to, $requested_redirect_to, $user)
{
    if(!$user instanceof WP_User)
        return $redirect_to;
    if(count($user->caps) == 0)
        return get_home_url();
    return $redirect_to;
}

add_action('admin_menu', 'authserver_login_remove_menu_pages');
function authserver_login_remove_menu_pages()
{
    remove_submenu_page('users.php', 'user-new.php');
}

add_filter('show_password_fields', function() {return false;});

add_action('user_profile_update_errors', 'authserver_user_profile_update_errors', 10, 3);
function authserver_user_profile_update_errors(WP_Error &$errors, $update, &$user) {
    if(!$update)
        return;
    $oldUser = get_user_by('id', $user->ID);
    if($oldUser->user_email !== $user->user_email)
        $errors->add('invalid_email', __('<strong>ERROR</strong>: This email address is your identifier. You cannot change it.'), array( 'form-field' => 'email' ));
}
