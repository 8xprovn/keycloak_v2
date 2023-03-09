<?php

namespace Keycloak\Services;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Cookie;
use Keycloak\Auth\Guard\KeycloakWebGuard;
use Firebase\JWT\JWT;

class KeycloakService
{
    /**
     * The Session key for token
     */
    const KEYCLOAK_SESSION = 'imap_authen_';

    /**
     * Keycloak URL
     *
     * @var string
     */
    protected $baseUrl;

    /**
     * Keycloak Realm
     *
     * @var string
     */
    protected $realm;

    /**
     * Keycloak Client ID
     *
     * @var string
     */
    protected $clientId;

    /**
     * Keycloak Client Secret
     *
     * @var string
     */
    protected $clientSecret;

    /**
     * Keycloak OpenId Configuration
     *
     * @var array
     */
    protected $openid;

    /**
     * Keycloak OpenId Cache Configuration
     *
     * @var array
     */
    protected $cacheOpenid;

    /**
     * CallbackUrl
     *
     * @var array
     */
    protected $callbackUrl;

    /**
     * RedirectLogout
     *
     * @var array
     */
    protected $redirectLogout;

    protected $userProfile;
    /**
     * The Constructor
     * You can extend this service setting protected variables before call
     * parent constructor to comunicate with Keycloak smoothly.
     *
     * @param ClientInterface $client
     * @return void
     */
    public function __construct(ClientInterface $client)
    {
        if (is_null($this->baseUrl)) {
            $this->baseUrl = trim(env('KEYCLOAK_BASE_URL'));
        }
        if (is_null($this->clientId)) {
            $this->clientId = env('KEYCLOAK_CLIENT_ID');
        }

        if (is_null($this->clientSecret)) {
            $this->clientSecret = env('KEYCLOAK_CLIENT_SECRET');
        }
        if (is_null($this->callbackUrl)) {
            $this->callbackUrl = route('keycloak.callback');
        }
        if (is_null($this->redirectLogout)) {
            $this->redirectLogout = Config::get('keycloak-web.redirect_logout');
        }

        $this->httpClient = $client;
    }

    /**
     * Return the login URL
     *
     * @link https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
     *
     * @return string
     */
    public function getLoginUrl($state='')
    {

        $url = $this->baseUrl.'/oauth/authorize';
        $params = [
            'scope' => '',
            'client_id' => $this->clientId,
            'response_type' => 'code',
            'redirect_uri' => $this->callbackUrl,
            'state' => $state
        ];

        return $this->buildUrl($url, $params);
    }

    /**
     * Return the logout URL
     *
     * @return string
     */
    public function getLogoutUrl()
    {
        $url = $url = $this->baseUrl.'/oauth/logout';

        if (empty($this->redirectLogout)) {
            $this->redirectLogout = url('/');
        }
        return $this->buildUrl($url, []);
        //return $this->buildUrl($url, ['redirect_uri' => $this->redirectLogout]);
    }

    /**
     * Return the register URL
     *
     * @link https://stackoverflow.com/questions/51514437/keycloak-direct-user-link-registration
     *
     * @return string
     */
    public function getRegisterUrl()
    {
        $url = $this->getLoginUrl();
        return str_replace('/auth?', '/registrations?', $url);
    }
    /**
     * Get access token from Code
     *
     * @param  string $code
     * @return array
     */
    public function getAccessToken($code)
    {
        $url =  $this->baseUrl.'/oauth/token';
        $params = [
            'code' => $code,
            'client_id' => $this->clientId,
            'grant_type' => 'authorization_code',
            'redirect_uri' => $this->callbackUrl,
        ];

        if (! empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        $token = [];


        try {
            $response = $this->httpClient->request('POST', $url, ['form_params' => $params]);

            if ($response->getStatusCode() === 200) {
                $token = $response->getBody()->getContents();
                $token = json_decode($token, true);
            }
        } catch (GuzzleException $e) {
            $this->logException($e);
        }

        return $token;
    }

    /**
     * Refresh access token
     *
     * @param  string $refreshToken
     * @return array
     */
    public function refreshAccessToken($credentials)
    {
        if (empty($credentials['refresh_token'])) {
            return [];
        }

        $url =  $this->baseUrl.'/oauth/token';
        $params = [
            'client_id' => $this->clientId,
            'grant_type' => 'refresh_token',
            'refresh_token' => $credentials['refresh_token'],
            'redirect_uri' => $this->callbackUrl,
        ];

        if (! empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        $token = [];

        try {
            $response = $this->httpClient->request('POST', $url, ['form_params' => $params]);

            if ($response->getStatusCode() === 200) {
                $token = $response->getBody()->getContents();
                $token = json_decode($token, true);
            }
        } catch (GuzzleException $e) {
            $this->logException($e);
        }

        return $token;
    }
    public function getPermissionUser() {
        $userId = \Auth::id();
        if ($permission = session()->get(self::KEYCLOAK_SESSION.'user_permission_'.$userId)){
            return $permission;
        }
        $token = $this->retrieveToken();
        $response = \Http::withToken($token['access_token'])->get($this->baseUrl.'/api/permission',['service' => config('app.service_code')]);
        if ($response->successful()) {
            $permission = $response->json();
            session()->put(self::KEYCLOAK_SESSION.'user_permission_'.$userId, $permission);
            return $permission;
        }
        return false;
    }
    /**
     * Get access token from Code
     * @param  array $credentials
     * @return array
     */
    public function getUserProfile($credentials)
    {
        $credentials = $this->refreshTokenIfNeeded($credentials);
        if (empty($credentials['access_token'])) {
            $this->forgetToken();
            return [];
        }
        $user =  $this->parseAccessToken($credentials['access_token']);
        if (!$user) {
            return [];
        }
        if ($userProfile = session()->get(self::KEYCLOAK_SESSION.'user_profile_'.$user['sub'])){
            return $userProfile;
        }
        $userProfile = $this->retrieveProfile($credentials);
        if ($userProfile) {
            $userProfile['user_id'] = $user['sub'];
            session()->put(self::KEYCLOAK_SESSION.'user_profile_'.$user['sub'], $userProfile);
        }
        return $userProfile;
    }
    public function retrieveProfile($token) {
        $response = \Http::withToken($token['access_token'])->get(env('API_MICROSERVICE_URL').'/hr/employees/me');
        if ($response->successful()) {
            return $response->json();
        }
        return false;
    }
    /**
     * Get Access Token data
     *
     * @param string $token
     * @return array
     */
    public function parseAccessToken($token)
    {
        if (! is_string($token)) {
            return [];
        }
        $public_key = env('KEYCLOAK_REALM_PUBLIC_KEY');
        try {
            JWT::$leeway = 10;
            return (array)JWT::decode($token, $public_key , array('RS256'));
        }catch (\Exception $e) {
             return [];
        }
    }

    /**
     * Retrieve Token from Session
     *
     * @return void
     */
    public function retrieveToken()
    {

        // return array_filter([
           
        //     'access_token' => $_COOKIE[self::KEYCLOAK_SESSION.'access_token'] ?? '',
        //     'refresh_token' => $_COOKIE[self::KEYCLOAK_SESSION.'refresh_token'] ?? '',
        // ]);
        return array_filter([
            'refresh_token' => Cookie::get(self::KEYCLOAK_SESSION.'refresh_token'),
            'access_token' => Cookie::get(self::KEYCLOAK_SESSION.'access_token'),
            //'access_token' => session()->get(self::KEYCLOAK_SESSION.'access_token')
        ]);
        //return session()->get(self::KEYCLOAK_SESSION);
    }

    /**
     * Save Token to Session
     *
     * @return void
     */
    public function saveToken($credentials)
    {
        //Cookie make(string $name, string $value, int $minutes = 0, string|null $path = null, string|null $domain = null, bool|null $secure = null, bool $httpOnly = true, bool $raw = false, string|null $sameSite = null) 
        //session()->put(self::KEYCLOAK_SESSION.'access_token', $credentials['access_token']);
        Cookie::queue(self::KEYCLOAK_SESSION.'access_token', $credentials['access_token'], 3600, null, null, true, false);
        Cookie::queue(self::KEYCLOAK_SESSION.'refresh_token', $credentials['access_token'], 1440, null, null, true, false);

        //setcookie(self::KEYCLOAK_SESSION.'access_token', $credentials['access_token'], time() + 21600 , '/', null , false , false);
        //setcookie(self::KEYCLOAK_SESSION.'refresh_token', $credentials['refresh_token'], time() + 259200 , '/', null , false , false); // 3 ngay
        
        //Cookie::queue(cookie(self::KEYCLOAK_SESSION.'access_token', $credentials['access_token'], 180, '/' , null , false, false));
        //setcookie("TestCookie", $credentials['access_token'], 180, '/' , null , false, false);
        //cookie('name', 'value', $minutes);
        // session()->put(self::KEYCLOAK_SESSION, $credentials);
        // session()->save();
    }

    /**
     * Remove Token from Session
     *
     * @return void
     */
    public function forgetToken()
    {
        //session()->forget(self::KEYCLOAK_SESSION.'access_token');
        //\Session::invalidate();
        //setcookie(self::KEYCLOAK_SESSION.'access_token', "", time() - 86400,'/');
        //setcookie(self::KEYCLOAK_SESSION.'refresh_token', "", time() - 86400,'/');
        Cookie::queue(Cookie::forget(self::KEYCLOAK_SESSION.'refresh_token'));
        Cookie::queue(Cookie::forget(self::KEYCLOAK_SESSION.'access_token'));
    }

    /**
     * Build a URL with params
     *
     * @param  string $url
     * @param  array $params
     * @return string
     */
    public function buildUrl($url, $params)
    {
        $parsedUrl = parse_url($url);
        if (empty($parsedUrl['host'])) {
            return trim($url, '?') . '?' . Arr::query($params);
        }

        if (! empty($parsedUrl['port'])) {
            $parsedUrl['host'] .= ':' . $parsedUrl['port'];
        }

        $parsedUrl['scheme'] = (empty($parsedUrl['scheme'])) ? 'https' : $parsedUrl['scheme'];
        $parsedUrl['path'] = (empty($parsedUrl['path'])) ? '' : $parsedUrl['path'];

        $url = $parsedUrl['scheme'] . '://' . $parsedUrl['host'] . $parsedUrl['path'];
        $query = [];

        if (! empty($parsedUrl['query'])) {
            $parsedUrl['query'] = explode('&', $parsedUrl['query']);

            foreach ($parsedUrl['query'] as $value) {
                $value = explode('=', $value);

                if (count($value) < 2) {
                    continue;
                }

                $key = array_shift($value);
                $value = implode('=', $value);

                $query[$key] = urldecode($value);
            }
        }

        $query = array_merge($query, $params);

        return $url . '?' . Arr::query($query);
    }
    /**
     * Check we need to refresh token and refresh if needed
     *
     * @param  array $credentials
     * @return array
     */
    protected function refreshTokenIfNeeded($credentials)
    {
        if (!empty($credentials['access_token'])) {
            $info = $this->parseAccessToken($credentials['access_token']);
            $exp = $info['exp'] ?? 0;

            if (time() < $exp) {
                return $credentials;
            }
        }
        $credentials = $this->refreshAccessToken($credentials);
        if (empty($credentials['access_token'])) {
            $this->forgetToken();
            return [];
        }
        $this->saveToken($credentials);
        return $credentials;
    }

    /**
     * Log a GuzzleException
     *
     * @param  GuzzleException $e
     * @return void
     */
    protected function logException(GuzzleException $e)
    {
        if (empty($e->getResponse())) {
            Log::error('[Keycloak Service] ' . $e->getMessage());
            return;
        }

        $error = [
            'request' => $e->getRequest(),
            'response' => $e->getResponse()->getBody()->getContents(),
        ];

        Log::error('[Keycloak Service] ' . print_r($error, true));
    }

    /**
     * Base64UrlDecode string
     *
     * @link https://www.php.net/manual/pt_BR/function.base64-encode.php#103849
     *
     * @param  string $data
     * @return string
     */
    protected function base64UrlDecode($data)
    {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
}
