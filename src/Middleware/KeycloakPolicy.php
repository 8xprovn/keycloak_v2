<?php

namespace Keycloak\Middleware;

use Closure;
//use Illuminate\Support\Facades\Auth;

class KeycloakPolicy 
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
        ///////// GET SITE ////////
        $prefix = strtolower($request->segment(1));
        $PATH = ''; $as = '';
        if (in_array($prefix,['me','manager'])) {
            $PATH = ucfirst($prefix).'\\';
            $as = $prefix.'.';
        }
        else {
            $prefix = '';
        }
        \Config::set('route.site',$prefix);
        \Config::set('route.as',$as);
        \Gate::guessPolicyNamesUsing(function ($modelClass) use ($PATH) {
            return 'App\\Policies\\' . $PATH . ucfirst(class_basename($modelClass)) . 'Policy';
        });
        return $next($request);
    }
}
