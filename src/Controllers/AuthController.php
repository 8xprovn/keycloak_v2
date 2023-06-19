<?php

namespace Keycloak\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Keycloak\Exceptions\KeycloakCallbackException;
use Keycloak\Facades\KeycloakWeb;

class AuthController extends Controller
{
    /**
     * Redirect to login
     *
     * @return view
     */
    public function login(Request $request)
    {
        $uri = $request->query('redirect_uri');
        if (!$uri) {
            $uri = env('APP_URL');
        }
        $state = base64_encode($uri);
        $url = KeycloakWeb::getLoginUrl($state);
        return redirect($url);
    }

    /**
     * Redirect to logout
     *
     * @return view
     */
    public function logout()
    {
        KeycloakWeb::forgetToken();

        $url = KeycloakWeb::getLogoutUrl();
        return redirect($url);
    }

    /**
     * Redirect to register
     *
     * @return view
     */
    public function register()
    {
        $url = KeycloakWeb::getRegisterUrl();
        return redirect($url);
    }

    /**
     * Keycloak callback page
     *
     * @throws KeycloakCallbackException
     *
     * @return view
     */
    public function callback(Request $request)
    {
        if (! empty($request->input('error'))) {
            $error = $request->input('error_description');
            $error = ($error) ?: $request->input('error');

            throw new KeycloakCallbackException($error);
        }
        $code = $request->input('code');
        $state = $request->input('state');

        $state = base64_decode($state);
        if(empty($state)) return redirect(route('keycloak.logout'));
  
        if (! empty($code)) {
            $token = KeycloakWeb::getAccessToken($code);
            if (Auth::validate($token)) {
                return redirect($state);
            }
        }
        return redirect(route('keycloak.logout'));
    }
}
