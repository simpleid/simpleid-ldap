<?
/**
 * The LDAP server name and TCP port.
 *
 * LDAP_HOST can also contain a full LDAP URL, which is necessary
 * when specifying that LDAPS should be used, e.g.
 * 
 *   define('LDAP_HOST', 'ldaps://ldap.example.org:636');
 *
 */
define('LDAP_HOST', 'localhost');
define('LDAP_PORT', 389);

/**
 * The LDAP base DN for the search
 */
define('LDAP_BASE_DN', 'dc=example,dc=org');


?>
