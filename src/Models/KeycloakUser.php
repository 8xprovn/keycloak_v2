<?php

namespace Keycloak\Models;

use Auth;
use Illuminate\Contracts\Auth\Authenticatable;

class KeycloakUser implements Authenticatable
{
    /**
     * Attributes we retrieve from Profile
     *
     * @var array
     */
    protected $fillable = [
        '_id',
        'first_name',
        'last_name',
        'fullname',
        'email',
        'branch_id',
        'rel_branch_id',
        'branch_city_code',
        'department_id',
        'type',
        'job_title_id',
        'brand_id',
        'avatar',
        'subordinates',
        'is_superadmin'
    ];
    protected $id;
    /**
     * User attributes
     *
     * @var array
     */
    protected $attributes = [];

    /**
     * Constructor
     *
     * @param array $profile Keycloak user info
     */
    public function __construct(array $profile)
    {
        $this->setAttributes($profile);
        $this->id = $this->getKey();
    }

    /**
     * Magic method to get attributes
     *
     * @param  string $name
     * @return mixed
     */
    public function __get(string $name)
    {
        return $this->attributes[ $name ] ?? null;
    }
    public function setAttributes($name, $value = '') {
        if (!is_array($name)) {
            $name = [$name => $value];
        }
        foreach ($name as $key => $value) {
            if (in_array($key, $this->fillable)) {
                $this->attributes[ $key ] = $value;
            }
        }
        return $this->attributes[ $key ] = $value;
    }
    /**
     * Get the value of the model's primary key.
     *
     * @return mixed
     */
    public function getKey()
    {
        return $this->_id;
    }

    /**
     * Get the name of the unique identifier for the user.
     *
     * @return string
     */
    public function getAuthIdentifierName()
    {
        return '_id';
    }

    /**
     * Get the unique identifier for the user.
     *
     * @return mixed
     */
    public function getAuthIdentifier()
    {
        return $this->_id;
    }

    /**
     * Check user has roles
     *
     * @see KeycloakWebGuard::hasRole()
     *
     * @param  string|array  $roles
     * @param  string  $resource
     * @return boolean
     */
    public function hasRole($roles, $resource = '')
    {
        return Auth::hasRole($roles, $resource);
    }

    /**
     * Get the password for the user.
     *
     * @return string
     * @codeCoverageIgnore
     */
    public function getAuthPassword()
    {
        throw new \BadMethodCallException('Unexpected method [getAuthPassword] call');
    }
    /**
     * Get the password name.
     *
     * @return string
     * @codeCoverageIgnore
     */
    public function getAuthPasswordName() {
        return 'password'; 
    }
    /**
     * Get the token value for the "remember me" session.
     *
     * @return string
     * @codeCoverageIgnore
     */
    public function getRememberToken()
    {
        throw new \BadMethodCallException('Unexpected method [getRememberToken] call');
    }

    /**
     * Set the token value for the "remember me" session.
     *
     * @param string $value
     * @codeCoverageIgnore
     */
    public function setRememberToken($value)
    {
        throw new \BadMethodCallException('Unexpected method [setRememberToken] call');
    }

    /**
     * Get the column name for the "remember me" token.
     *
     * @return string
     * @codeCoverageIgnore
     */
    public function getRememberTokenName()
    {
        throw new \BadMethodCallException('Unexpected method [getRememberTokenName] call');
    }
}
