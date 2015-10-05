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

use \Net_LDAP2;
use \Net_LDAP2_Filter;
use \PEAR;
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

    protected $ldap_cfg;

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

        $starttls = ($this->f3->exists('config.ldap.starttls')) ? $this->f3->get('config.ldap.starttls') : false;

        $ldap_cfg = array (
            'host' => $this->f3->get('config.ldap.host'),
            'port' => $this->f3->get('config.ldap.port'),
            'version' => 3,
            'starttls' => $starttls,
            'basedn' => $this->f3->get('config.ldap.basedn')
        );

        $ldap = Net_LDAP2::connect($ldap_cfg);

        // Testing for connection error
        if (PEAR::isError($ldap)) {
            $this->f3->get('logger')->log(\Psr\Log\LogLevel::ERROR, 'Could not connect to LDAP server: ' . $ldap->getMessage());
            return false;
        }

        $filter = Net_LDAP2_Filter::create($ldap_attr, 'equals', $uid);
        $requested_attributes = array('dn');
        $ldap_res = $ldap->search(null, $filter,
            array('attributes' => $requested_attributes));
        if (Net_LDAP2::isError($ldap_res)) {
            $this->f3->get('logger')->log(\Psr\Log\LogLevel::ERROR, 'Error occurred when searching LDAP server: ' . $ldap_res->getMessage());
            $ldap->done();
            return false;
        }

        if($ldap_res->count() == 0) {
            $this->f3->get('logger')->log(\Psr\Log\LogLevel::ERROR, "No matches for $ldap_attr = $uid");
        } else if($ldap_res->count() > 1) {
            $this->f3->get('logger')->log(\Psr\Log\LogLevel::ERROR, "Multiple matches for $ldap_attr = $uid");
        }

        if ($ldap_res->count() != 1) {
            $ldap_res->done();
            $ldap->done();
            return false;
        }

        $ldap_entry = $ldap_res->shiftEntry();
        $ldap_dn = $ldap_entry->dn();
        if (Net_LDAP2::isError($ldap_dn)) {
            $this->f3->get('logger')->log(\Psr\Log\LogLevel::ERROR, 'Error occurred when retrieving search results:', $ldap_dn->getMessage());
            $ldap_res->done();
            $ldap->done();
            return false;
        }

        $ldap_rebind = $ldap->bind($ldap_dn, $credentials['password']['password']);
        if (Net_LDAP2::isError($ldap_rebind)) {            
            $this->f3->get('logger')->log(\Psr\Log\LogLevel::WARNING, 'LDAP bind failure:', $ldap_rebind->getMessage());
            return false;
        }

        $ldap_res->done();
        $ldap->done();

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
