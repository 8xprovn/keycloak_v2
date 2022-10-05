<?php

namespace Keycloak\Auth\Guard;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Keycloak\Exceptions\KeycloakCallbackException;
use Keycloak\Models\KeycloakUser;
use Keycloak\Facades\KeycloakWeb;
use Illuminate\Contracts\Auth\UserProvider;

class KeycloakWebGuard
{
    /**
     * @var null|Authenticatable|KeycloakUser
     */
    protected $user;

    /**
     * Constructor.
     *
     * @param Request $request
     */
    public function __construct(UserProvider $provider, Request $request)
    {
        $this->provider = $provider;
        $this->request = $request;
    }

    /**
     * Determine if the current user is authenticated.
     *
     * @return bool
     */
    public function check()
    {
        return (bool) $this->user();
    }

    /**
     * Determine if the current user is a guest.
     *
     * @return bool
     */
    public function guest()
    {
        return ! $this->check();
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        return $this->user ?: $this->authenticate();
    }

    /**
     * Set the current user.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    public function setUser(?Authenticatable $user)
    {
        $this->user = $user;
    }

    /**
     * Get the ID for the currently authenticated user.
     *
     * @return int|string|null
     */
    public function id()
    {
        $user = $this->user();
        return $user->user_id ?? null;
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     *
     * @throws BadMethodCallException
     *
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        if (empty($credentials['access_token'])) {
            return false;
        }
        /**
         * Store the section
         */
        $credentials['refresh_token'] = $credentials['refresh_token'] ?? '';
        KeycloakWeb::saveToken($credentials);

        return $this->authenticate($credentials);
    }

    /**
     * Try to authenticate the user
     *
     * @throws KeycloakCallbackException
     * @return boolean
     */
    public function authenticate($credentials = array())
    {

        // Get Credentials
        if (!$credentials) {
            $credentials = KeycloakWeb::retrieveToken();    
        }
        if (empty($credentials['access_token'])) {
            return false;
        }
        $user = KeycloakWeb::getUserProfile($credentials);
        if (empty($user)) {
            KeycloakWeb::forgetToken();
            return false;
        }

        // Provide User
        $user = $this->provider->retrieveByCredentials($user);
        $this->setUser($user);

        return true;
    }
}
