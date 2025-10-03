<?php

namespace Keycloak\Auth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;

class KeycloakWebUserProvider implements UserProvider
{
    /**
     * The user model.
     *
     * @var string
     */
    protected $model;

    /**
     * The Constructor
     *
     * @param string $model
     */
    public function __construct($model)
    {
        $this->model = '\\' . ltrim($model, '\\');
    }

    /**
     * Retrieve a user by the given credentials.
     *
     * @param  array  $credentials
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveByCredentials(array $credentials)
    {
        throw new \BadMethodCallException('Unexpected method [retrieveByToken] call');
        // $class = $this->model;

        // return new $class($credentials);
    }

    /**
     * Retrieve a user by their unique identifier.
     *
     * @param  mixed  $identifier
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveById($identifier)
    {
        if (!$identifier) {
            return null;
        }
        switch ($identifier) {
            case 1:
                $user = ['is_superadmin' => true, '_id' => 1];
                break;
            default:
                $service = config('app.service_code');
                if ($service === 'erp_hr_backend_v2') {
                    $model = \App::make(\App\Models\Hr\Employee::class);
                    $user = $model->detail($identifier);
                } else {
                    $user = \Microservices::Hr('Employees')->detail($identifier);
                }

                break;
        }
        // $user = ($identifier == 1) ? ['is_superadmin' => true,'_id' => 1] : \Microservices::Hr('Employees')->detail($identifier);
        $class = $this->model;
        return new $class($user);
    }

    /**
     * Retrieve a user by their unique identifier and "remember me" token.
     *
     * @param  mixed  $identifier
     * @param  string  $token
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveByToken($identifier, $token)
    {
        throw new \BadMethodCallException('Unexpected method [retrieveByToken] call');
    }

    /**
     * Update the "remember me" token for the given user in storage.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  string  $token
     * @return void
     */
    public function updateRememberToken(Authenticatable $user, $token)
    {
        throw new \BadMethodCallException('Unexpected method [updateRememberToken] call');
    }

    /**
     * Validate a user against the given credentials.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  array  $credentials
     * @return bool
     */
    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        throw new \BadMethodCallException('Unexpected method [validateCredentials] call');
    }
    public function rehashPasswordIfRequired(Authenticatable $user, array $credentials, bool $force = false)
    {
        return false;
    }
}
