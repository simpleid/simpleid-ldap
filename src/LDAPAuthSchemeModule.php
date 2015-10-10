<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

namespace SimpleID\Modules\LDAP;

use Psr\Log\LogLevel;
use SimpleID\Auth\PasswordAuthSchemeModule;
use SimpleID\Store\StoreManager;

/**
 * Password-based authentication scheme.
 *
 * This authentication scheme uses a user name and a password supplied
 * by the user.  A hash is generated from the password, which is compared
 * against the hash stored in the user store.
 *
 * Currently only bcrypt and pbkdf2 password hashing algorithms are
 * supported.
 */
class LDAPAuthSchemeModule extends PasswordAuthSchemeModule {

    public function __construct() {
        parent::__construct();

        if (!$this->f3->exists('config.ldap.host') || !$this->f3->exists('config.ldap.port') || !$this->f3->exists('config.ldap.basedn')) {
            $this->f3->get('logger')->log(\Psr\Log\LogLevel::CRITICAL, 'LDAP configuration parameters not found.');
            $this->f3->error(500, $this->t('LDAP configuration parameters host, port or basedn not found'));
        }
    }

    /**
     * Verifies a set of credentials using the default user name-password authentication
     * method.
     *
     * @param string $uid the name of the user to verify
     * @param array $credentials the credentials supplied by the browser
     * @return bool whether the credentials supplied matches those for the specified
     * user
     */
    protected function verifyCredentials($uid, $credentials) {
        $store = StoreManager::instance();

        $test_user = $store->loadUser($uid);
        if ($test_user == NULL) return false;

        // We look for the value ldap.auth in the user file.  If this is set to
        // true, we proceed to LDAP authentication.  If it is false or missing,
        // we use password authentication.
        //
        // LDAPStoreModule will always set this value to true.
        if (!$test_user->pathExists('ldap.auth') || !$test_user->pathGet('ldap.auth')) {
            return parent::verifyCredentials($uid, $credentials);
        }

        /* We could try and look for the user by uid or by the mail
           attribute in LDAP.  It depends on whether the uid entered
           in the login form contains the '@' symbol */
        $ldap_attr = 'uid';
        if(strpos($uid, '@')) {
            $ldap_attr = 'mail';
        }

        $cn = @ldap_connect($this->f3->get('config.ldap.host'), $this->f3->get('config.ldap.port'));
        if (!$cn) {
            $this->f3->get('logger')->log(\Psr\Log\LogLevel::ERROR, 'Could not connect to LDAP server');
            return false;
        }

        ldap_set_option($cn, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($cn, LDAP_OPT_REFERRALS, 0);

        if ($this->f3->exists('config.ldap.starttls') && $this->f3->get('config.ldap.starttls')) {
            $result = @ldap_start_tls($cn);
            if (!$result) {
                $this->f3->get('logger')->log(\Psr\Log\LogLevel::ERROR, 'Could not connect to LDAP server: ' . ldap_error($cn));
                return false;
            }
        }

        $result = @ldap_bind($cn);
        if (!$result) {
            $this->f3->get('logger')->log(\Psr\Log\LogLevel::ERROR, 'Could not connect to LDAP server: ' . ldap_error($cn));
            return false;
        }

        $search = @ldap_search($cn, $this->f3->get('config.ldap.basedn'), $ldap_attr . '=' . $uid, array('dn'));
        if (!$search) {
            $this->f3->get('logger')->log(\Psr\Log\LogLevel::ERROR, 'Error occurred when searching LDAP server: ' . ldap_error($cn));
            @ldap_unbind($cn);
            return false;
        }

        $count = @ldap_count_entries($cn, $search);
        if($count == 0) {
            $this->f3->get('logger')->log(\Psr\Log\LogLevel::ERROR, "No matches for $ldap_attr = $uid");
        } elseif ($count > 1) {
            $this->f3->get('logger')->log(\Psr\Log\LogLevel::ERROR, "Multiple matches for $ldap_attr = $uid");
        }

        if ($count != 1) {
            @ldap_free_result($search);
            @ldap_unbind($cn);
            return false;
        }

        $entry = ldap_first_entry($cn, $search);
        if (!$entry) {
            $this->f3->get('logger')->log(\Psr\Log\LogLevel::ERROR, 'Error occurred when retrieving search results: ' . ldap_error($cn));
            @ldap_free_result($search);
            @ldap_unbind($cn);
            return false;
        }

        $ldap_dn = ldap_get_dn($cn, $entry);
        if (!$ldap_dn) {
            $this->f3->get('logger')->log(\Psr\Log\LogLevel::ERROR, 'Error occurred when retrieving search results: ' . ldap_error($cn));
            @ldap_free_result($search);
            @ldap_unbind($cn);
            return false;
        }

        $result = @ldap_bind($cn, $ldap_dn, $credentials['password']['password']);
        if (!$result) {            
            $this->f3->get('logger')->log(\Psr\Log\LogLevel::WARNING, 'Cannot bind using user name and password: ' . ldap_error($cn));
            return false;
        }

        @ldap_free_result($search);
        @ldap_unbind($cn);

        return true;
    }

    /**
     * @see SimpleID\API\AuthHooks::secretUserDataPathsHook()
     */
    public function secretUserDataPathsHook() {
        return array('ldap.auth');
    }
}
?>
