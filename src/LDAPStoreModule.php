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
use SimpleID\Store\StoreModule;
use SimpleID\Models\User;

/**
 * A store module that uses the file system for all of
 * its storage requirements.
 */
class LDAPStoreModule extends StoreModule {

    protected $ldap_config;

    protected $attribute_map = array(
        'dn' => 'ldap.dn',
        'uid' => 'uid',
        'cn' => 'userinfo.name',
        'mail' => 'email'
    );

    public function __construct() {
        parent::__construct();

        if (!$this->f3->exists('config.ldap.host') || !$this->f3->exists('config.ldap.port') || !$this->f3->exists('config.ldap.basedn')) {
            $this->f3->get('logger')->log(\Psr\Log\LogLevel::CRITICAL, 'LDAP configuration parameters not found.');
            $this->f3->error(500, $this->t('LDAP configuration parameters host, port or basedn not found'));
        }

        $this->ldap_config = $this->f3->get('config.ldap');
    }

    public function getStores() {
        return array('user:read');
    }

    public function find($type, $criteria, $value) {
        switch ($type) {
            case 'user':
                return $this->findUser($criteria, $value);
        }
    }

    public function exists($type, $id) {
        switch ($type) {
            case 'user':
                return $this->hasUser($id);
            default:
                return null;
        }
    }

    public function read($type, $id) {
        switch ($type) {
            case 'user':
                return $this->readUser($id);
            default:
                return null;
        }
    }

    public function write($type, $id, $value) {
    }

    public function delete($type, $id) {
    }

    /**
     * Finds a user
     *
     * @param string $criteria the criteria name
     * @param string $value the criteria value
     * @return User the item or null if no item is found
     */
    protected function findUser($criteria, $value) {
        $result = NULL;

        $cn = $this->ldapConnect();
        if ($cn) {
            if ($criteria == 'uid') {
                $filter = $this->getLDAPFilter($uid);
            } else {
                $filter_map = array_flip($this->attribute_map);
                if (!isset($filter_map[$criteria])) return null;
                $filter = $filter_map[$criteria] . '=' . $value;
            }

            $search = @ldap_search($cn, $this->ldap_config['basedn'], $filter, array_keys('uid', 'mail'));
            if (!$search) return null;
            
            $count = @ldap_count_entries($cn, $search);
            if($count == 0) {
                $this->f3->get('logger')->log(\Psr\Log\LogLevel::ERROR, "No matches");
            } elseif ($count > 1) {
                $this->f3->get('logger')->log(\Psr\Log\LogLevel::ERROR, "Multiple matches");
            }

            if ($count != 1) {
                @ldap_free_result($search);
                $this->ldapDisconnect($cn);
                return null;
            }

            $entry = ldap_first_entry($cn, $search);
            if (!$entry) {
                $this->f3->get('logger')->log(\Psr\Log\LogLevel::ERROR, 'Error occurred when retrieving search results: ' . ldap_error($cn));
                @ldap_free_result($search);
                $this->ldapDisconnect($cn);
                return null;
            }

            $attrs = ldap_get_attributes($cn, $entry);
            if ($attrs['uid']) {
                $result = $attrs['uid'][0];
            } elseif ($attrs['mail']) {
                $result = $attrs['mail'][0];
            }

            @ldap_free_result($search);
            $this->ldapDisconnect($cn);
        }

        return $result;
    }

    /**
     * Returns whether the user name exists in the user store.
     *
     * @param string $uid the name of the user to check
     * @return bool whether the user name exists
     */
    protected function hasUser($uid) {
        $cn = $this->ldapConnect();
        if ($cn) {
            $search = @ldap_search($cn, $this->ldap_config['basedn'], $this->getLDAPFilter($uid), array('dn'));
            if (!$search) return false;
            $result = (@ldap_count_entries($cn, $search) === 1);
            @ldap_free_result($result);
            $this->ldapDisconnect($cn);
            return $result;
        }
        return false;
    }

    /**
     * Loads user data for a specified user name.
     *
     * The user name must exist.  You should check whether the user name exists with
     * the {@link store_user_exists()} function
     *
     * @param string $uid the name of the user to load
     * @return User data for the specified user
     */
    protected function readUser($uid) {
        if (!$this->hasUser($uid)) return null;

        $cn = $this->ldapConnect();
        if ($cn) {
            $search = @ldap_search($cn, $this->ldap_config['basedn'], $this->getLDAPFilter($uid), array_keys($this->attribute_map));
            if (!$search) return null;
            
            $count = @ldap_count_entries($cn, $search);
            if($count == 0) {
                $this->f3->get('logger')->log(\Psr\Log\LogLevel::ERROR, "No matches for $uid");
            } elseif ($count > 1) {
                $this->f3->get('logger')->log(\Psr\Log\LogLevel::ERROR, "Multiple matches for $uid");
            }

            if ($count != 1) {
                @ldap_free_result($search);
                $this->ldapDisconnect($cn);
                return null;
            }

            $entry = ldap_first_entry($cn, $search);
            if (!$entry) {
                $this->f3->get('logger')->log(\Psr\Log\LogLevel::ERROR, 'Error occurred when retrieving search results: ' . ldap_error($cn));
                @ldap_free_result($search);
                $this->ldapDisconnect($cn);
                return null;
            }

            $user = new User();
            $attrs = ldap_get_attributes($cn, $entry);
            for ($i = 0; $i < $attrs['count']; $i++) {
                $attr = $attrs[$i];
                if (isset($this->attribute_map[$attr])) {
                    $user->pathSet($this->attribute_map[$attr], $attrs[$attr][0]);
                }
            }
            $user->pathSet('ldap.auth', true);

            @ldap_free_result($search);
            $this->ldapDisconnect($cn);
            return $user;
        }

        return null;
    }

    protected function ldapConnect() {
        $cn = @ldap_connect($this->ldap_config['host'], $this->ldap_config['port']);
        if (!$cn) {
            $this->f3->get('logger')->log(\Psr\Log\LogLevel::ERROR, 'Could not connect to LDAP server');
            return false;
        }

        ldap_set_option($cn, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($cn, LDAP_OPT_REFERRALS, 0);

        if (isset($this->ldap_config['starttls']) && $this->ldap_config['starttls']) {
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

        return $cn;
    }

    protected function ldapDisconnect($cn) {
        @ldap_unbind($cn);
    }

    protected function getLDAPFilter($uid) {
        $ldap_attr = 'uid';
        if(strpos($uid, '@')) {
            $ldap_attr = 'mail';
        }
        return $ldap_attr . '=' . $uid;
    }
}

?>
