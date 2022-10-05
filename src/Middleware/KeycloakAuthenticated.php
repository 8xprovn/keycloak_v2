<?php

namespace Keycloak\Middleware;

use Illuminate\Auth\Middleware\Authenticate;
use Keycloak\Facades\KeycloakWeb;

class KeycloakAuthenticated extends Authenticate
{
    /**
     * Redirect user if it's not authenticated.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     */
    protected function redirectTo($request)
    {
        $url = KeycloakWeb::getLoginUrl();
        return $url;
        //return redirect($url);
    }
}
