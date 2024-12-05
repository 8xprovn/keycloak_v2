<?php

namespace Keycloak\Middleware;

use Closure;
use Illuminate\Support\Facades\Auth;
use Keycloak\Facades\KeycloakWeb;
use Illuminate\Support\Facades\Gate;
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
        try{
            $message = 'Không đủ quyền truy cập vào tài nguyên này';
            $user = Auth::user();
            /// TOKEN ADMIN ///
            if ($user->is_superadmin) {
                return $next($request);
            }
            $allowed_permissions = KeycloakWeb::getPermissionUser($user); /// khong duoc cap quyen j
            if (!$allowed_permissions) {
                throw new \Exception('Không lấy được thông tin về quyền truy cập');
            }

            $is_superadmin = (!empty($allowed_permissions['is_superadmin'])) ? true : false;
            $user->setAttributes(['is_superadmin' => $is_superadmin]);
            if ($is_superadmin) {
                return $next($request);
            }
            
            if (empty($allowed_permissions['permission'])) {
                throw new \Exception($message);
            }

            //router name
            $current_nameas = $request->route()->getName();
            foreach($allowed_permissions['permission'] as $k => $permission) {
                if (strpos($permission,':') !== false){
                    $arrPermission = explode(':',$permission);
                    $permission = $arrPermission[0];
                    if ($current_nameas == $permission) {
                        $request->headers->set('erp-authorization-policy', $arrPermission[1]);
                    }
                    $allowed_permissions['permission'][$k] = $permission;
                }
            }
            $user->permissions = $allowed_permissions['permission'];
            if(!Gate::allows($current_nameas)){
                throw new \Exception($message);
            }
            return $next($request);
        }catch(\Throwable $e){
            if(request()->expectsJson()){
                return response(['error' => '403', 'error_description' => $e->getMessage()], 403);
            }
            else {
                abort(403);
            }
        }
    }
}
