<?php

namespace Keycloak\Auth\Guard;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Keycloak\Models\KeycloakUser;
use Keycloak\Facades\KeycloakWeb;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Support\Facades\Cookie;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

class KeycloakWebGuard
{
    protected $cookePrefix = 'imap_authen_';
    /**
     * @var null|Authenticatable|KeycloakUser
     */
    protected $user;
    protected $user_id;
    protected $id;
    protected $provider;
    protected $request;
    /**
     * Indicates if the logout method has been called.
     *
     * @var bool
     */
    protected $loggedOut = false;
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
        return (bool) $this->id();
    }
 

    public function basic($field = 'email', $extraConditions = [])
    {
        if ($this->check()) {
            return;
        }

        // If a username is set on the HTTP basic request, we will return out without
        // interrupting the request lifecycle. Otherwise, we'll need to generate a
        // request indicating that the given credentials were invalid for login.
        if ($this->verifyBasicEnv()) {
            return; // SUCCESS
        }

        return  throw new UnauthorizedHttpException('Basic', 'Invalid credentials.');
    }

    public function verifyBasicEnv(): bool
    {
        $header = $this->request->header('Authorization'); // dùng $this->request cho nhất quán

        if (!$header || stripos($header, 'Basic ') !== 0) {
            return false;
        }

        $decoded = base64_decode(substr($header, 6), true);
        if ($decoded === false) {
            return false;
        }

        [$username, $password] = array_pad(explode(':', $decoded, 2), 2, null);

        $envUser = env('BASIC_AUTH_USER');
        $envPass = env('BASIC_AUTH_PASS');

        return ($username !== null && $password !== null &&
            hash_equals((string)$envUser, (string)$username) &&
            hash_equals((string)$envPass, (string)$password));
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
    public function user(): Authenticatable|KeycloakUser|null
    {
        if ($this->loggedOut) {
            return null;
        }
        if (! is_null($this->user)) {
            return $this->user;
        }
        $userId = $this->id();
        $this->user = $this->provider->retrieveById($userId);
        return $this->user;
    }
    public function loginUsingAccessToken()
    {
        $cookie = $this->request->cookie($this->cookePrefix . 'refresh_token');
        if (!$cookie) {
            return false;
        }
        $token = KeycloakWeb::refreshAccessToken($cookie);
        if (!$token) {
            return false;
        }
        return $this->loginUsingToken($token);
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
        if ($this->loggedOut) {
            return;
        }
        if (! is_null($this->id)) {
            return $this->id;
        }
        $token = $this->request->bearerToken() ?? $this->request->cookie($this->cookePrefix . 'access_token');
        if (!$token) {
            return null;
        }
        // decode token
        $tokenDecode = KeycloakWeb::parseAccessToken($token);
        if (!$tokenDecode || empty($tokenDecode['sub'])) {
            return null;
        }
        $this->id = $tokenDecode['sub'];
        return $tokenDecode['sub'];
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
    // public function validate(array $credentials = [])
    // {      
    //     if (empty($credentials['access_token'])) {
    //         return false;
    //     }
    //     $token = KeycloakWeb::parseAccessToken($credentials['access_token']);
    //     if ($token && $token['sub']) {
    //         return true;
    //     }
    //     return false;
    // }
    public function login(Authenticatable $user, $remember = false)
    {

        $this->setUser($user);
    }
    public function loginUsingToken($credentials)
    {
        if (empty($credentials['access_token'])) {
            return false;
        }
        $token = KeycloakWeb::parseAccessToken($credentials['access_token']);
        if (!$token || empty($token['sub'])) {
            return false;
        }
        if (! is_null($user = $this->provider->retrieveById($token['sub']))) {
            $this->login($user);
            Cookie::queue($this->cookePrefix . 'access_token', $credentials['access_token'], 1440, null, null, true, false);
            Cookie::queue($this->cookePrefix . 'refresh_token', $credentials['refresh_token'], 8640, null, null, true, false);
            return $user;
        }
        return false;
    }
    public function logout()
    {
        Cookie::queue(Cookie::forget($this->cookePrefix . 'refresh_token'));
        Cookie::queue(Cookie::forget($this->cookePrefix . 'access_token'));
        $this->loggedOut = true;
        $this->user = null;
    }
    /**
     * Try to authenticate the user
     *
     * @return boolean
     */
    // public function authenticate($credentials = array())
    // {
    //     // Get Credentials
    //     if (!$credentials) {
    //         $credentials = KeycloakWeb::retrieveToken();    
    //     }
    //     if (empty($credentials['access_token']) && empty($credentials['refresh_token'])) {
    //         return false;
    //     }
    //     $user = KeycloakWeb::getUserProfile($credentials);
    //     if (empty($user)) {
    //         KeycloakWeb::forgetToken();
    //         return false;
    //     }
    //     // Provide User
    //     $user = $this->provider->retrieveByCredentials($user);
    //     $this->setUser($user);

    //     return true;
    // }
}
