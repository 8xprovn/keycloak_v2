<?php

namespace Keycloak\Middleware;

use Closure;
use Illuminate\Support\Facades\Auth;
use Keycloak\Facades\KeycloakWeb;

class KeycloakCan extends KeycloakAuthenticated
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
        $allowed_permissions = KeycloakWeb::getPermissionUser(); /// khong duoc cap quyen j
        if (!$allowed_permissions) {
            
            if($request->ajax()){
                return response(['error' => '403', 'error_description' => 'Không đủ quyền truy cập vào tài nguyên này'], 403);
            }
            else {
                abort(403);
            }
        }
        // if($request->ajax()){
        //     if ($request->isMethod('get')) {
        //         return $next($request);
        //     }   
        // }
        $is_superadmin = (!empty($allowed_permissions['role']) && $allowed_permissions['role'] == 'superadmin') ? true : false;
        $current_nameas = \Request::route()->getName(); //router name
        \Gate::before(function () use ($is_superadmin) {
            //return true;
            if($is_superadmin){
                return $is_superadmin;
            }
        });
        if(!empty($allowed_permissions)){
            \Gate::define('home', function ($user) {
                return true;
            });
            foreach($allowed_permissions as $allowed_permission) {
                \Gate::define($allowed_permission, function ($user) {
                    return true;
                });
            }
            
        }
        if(\Gate::allows($current_nameas)){
            return $next($request);
        }
        if($request->ajax()){
            return response(['error' => '403', 'error_description' => 'Không đủ quyền truy cập vào tài nguyên này'], 403);
        }
        else {
            abort(403);
        }
    }
}
