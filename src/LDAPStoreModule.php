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
use SimpleID\Store\StoreModule;
use SimpleID\Models\User;

/**
 * A store module that uses the file system for all of
 * its storage requirements.
 */
class LDAPStoreModule extends StoreModule {

    protected $config;

    public function __construct() {
        parent::__construct();
        $this->config = $this->f3->get('config');

        $this->checkConfig();
    }

    protected function checkConfig() {
        if (!is_dir($this->config['identities_dir'])) {
            $this->f3->get('logger')->log(\Psr\Log\LogLevel::CRITICAL, 'Identities directory not found.');
            $this->f3->error(500, $this->t('Identities directory not found.  See the <a href="!url">manual</a> for instructions on how to set up SimpleID.', array('!url' => 'http://simpleid.koinic.net/docs/2/installing/')));
        }

        if (!is_dir($this->config['store_dir']) || !is_writeable($this->config['store_dir'])) {
            $this->f3->get('logger')->log(\Psr\Log\LogLevel::CRITICAL, 'Store directory not found or not writeable.');
            $this->f3->error(500, $this->t('Store directory not found or not writeable.  See the <a href="!url">manual</a> for instructions on how to set up SimpleID.', array('!url' => 'http://simpleid.koinic.net/docs/2/installing/')));
        }
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
        $cache = \Cache::instance();
        $index = $cache->get('users_' . rawurldecode($criteria) . '.storeindex');
        if ($index === false) $index = array();
        if (isset($index[$value])) return $index[$value];

        $result = NULL;

        $dir = opendir($this->config['identities_dir']);

        while (($file = readdir($dir)) !== false) {
            $filename = $this->config['identities_dir'] . '/' . $file;

            if (is_link($filename)) $filename = readlink($filename);
            if ((filetype($filename) != "file") || (!preg_match('/^(.+)\.user\.yml$/', $file, $matches))) continue;

            $uid = $matches[1];
            $test_user = $this->readUser($uid);

            $test_value = $test_user->pathGet($criteria);

            if ($test_value !== null) {
                if (is_array($test_value)) {
                    foreach ($test_value as $test_element) {
                        if (trim($test_element) != '') $index[$test_element] = $uid;
                        if ($test_element == $value) $result = $uid;
                    }
                } else {
                    if (trim($test_value) != '') {
                        $index[$test_value] = $uid;
                        if ($test_value == $value) $result = $uid;
                    }
                }
            }
        }

        closedir($dir);

        $cache->set('users_' . rawurldecode($criteria) . '.storeindex', $index);

        return $result;
    }

    /**
     * Returns whether the user name exists in the user store.
     *
     * @param string $uid the name of the user to check
     * @return bool whether the user name exists
     */
    protected function hasUser($uid) {
        if ($this->isValidName($uid)) {
            $identity_file = $this->config['identities_dir'] . "/$uid.user.yml";
            return (file_exists($identity_file));
        } else {
            return false;
        }
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
        if (!$this->isValidName($uid) || !$this->hasUser($uid)) return null;

        $user = $this->readSavedUserData($uid);

        $identity_file = $this->config['identities_dir'] . "/$uid.user.yml";

        try {
            $data =Spyc::YAMLLoad($identity_file);
        } catch (Exception $e) {
            $this->f3->get('logger')->log(\Psr\Log\LogLevel::ERROR, 'Cannot read user file ' . $identity_file . ': ' . $e->getMessage());
            trigger_error('Cannot read user file ' . $identity_file . ': ' . $e->getMessage(), E_USER_ERROR);
        }

        if ($data != null) $user->loadData($data);

        return $user;
    }

}

?>
