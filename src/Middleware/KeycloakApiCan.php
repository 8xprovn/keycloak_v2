<?php

namespace Keycloak\Middleware;

use Closure;
use Illuminate\Support\Facades\Auth;
use Keycloak\Facades\KeycloakWeb;

class KeycloakApiCan extends KeycloakAuthenticated
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string|null  $guard
     * @return mixed
     */
    public function handle($request, Closure $next, ...$guards)
    {
        $is_superadmin = (\Auth::id() == 1) ? true : false;
        \Auth::user()->is_superadmin = $is_superadmin;

        if ($is_superadmin) {
            return $next($request);
        }
        //router name
        $current_name = $request->route()->getName();
        if(\Gate::allows($current_name)){
            return $next($request);
        }
        return response(['error' => '403', 'error_description' => 'Không đủ quyền truy cập vào tài nguyên này'], 403);
    }
}
