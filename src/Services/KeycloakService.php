<?php

namespace Keycloak\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Config;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Exception;

class KeycloakService
{
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

    /**
     * The Constructor
     * You can extend this service setting protected variables before call
     * parent constructor to comunicate with Keycloak smoothly.
     *
     * @return void
     */
    public function __construct()
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
            $response = Http::acceptJson()->post($url, $params);
            if ($response->successful()) {
                // Xử lý và trả kết quả khi thành công
                return $response->json(); // Hoặc $response->body() nếu bạn muốn lấy toàn bộ nội dung
            } 
            Log::info('[Keycloak Service: getAccessToken] ' . $response->body());
        } catch (Exception $e) {
            Log::error('[Keycloak Service: getAccessToken] ' . $e->getMessage());
        }
        return $token;
    }

    /**
     * Refresh access token
     *
     * @param  string $refreshToken
     * @return array
     */
    public function refreshAccessToken($token)
    {
        $url =  $this->baseUrl.'/oauth/token';
        $params = [
            'client_id' => $this->clientId,
            'grant_type' => 'refresh_token',
            'refresh_token' => $token,
            'redirect_uri' => $this->callbackUrl,
        ];

        if (! empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }
        try {
            $response = Http::acceptJson()->post($url, $params);
            if ($response->successful()) {
                // Xử lý và trả kết quả khi thành công
                return $response->json(); // Hoặc $response->body() nếu bạn muốn lấy toàn bộ nội dung
            } 
            Log::info('[Keycloak Service: refreshAccessToken] ' . $response->body());
        } catch (Exception $e) {
            Log::error('[Keycloak Service: refreshAccessToken] ' . $e->getMessage());
        }
        return [];
    }
    public function getPermissionUser($user) {
        return \Microservices::Authorization('EmployeeToRole')->employee(['service' => config('app.service_code'),'group' => 'admin','user_id' => $user->_id,'department_id' => $user->department_id]);
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
            return (array)JWT::decode($token, new Key($public_key, 'RS256'));
        }catch (Exception $e) {
             return [];
        }
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
