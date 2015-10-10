# Using the LDAP Modules

## Introduction

This distribution contains two modules:

- `SimpleID\Modules\LDAP\LDAPAuthSchemeModule`, which allows authentication
  of user credentials against an LDAP directory

- `SimpleID\Modules\LDAP\LDAPStoreModule`, which allows the list of users to be
  stored on an LDAP directory.

The two modules can be used in the following ways:

1. You want to continue to store user data on the filesystem, but you want
   passwords to be authenticated against an LDAP directory.  This is similar to
   the `simpleid-ldap` extension for SimpleID 1.

2. In addition to 1, you also want to use the LDAP directory to store
   the list of users, instead of creating a user file for each user.

## LDAP Configuration

In addition to [enabling the modules](http://simpleid.koinic.net/docs/2/modules/#enabling),
you will need to specify the LDAP server in the configuration file `config.php`.

```yaml
ldap:
    host: ldap.example.com
    port: 389
    basedn: 'dc=example,dc=com'
    starttls: true
```

## Authenticating using an LDAP directory

To authenticate using an LDAP directory, do the following:

1. In `config.php` enable `SimpleID\Modules\LDAP\LDAPAuthSchemeModule` and disable
   `SimpleID\Auth\PasswordAuthSchemeModule`.  For example:

    ```yaml
        modules: 
            # - 'SimpleID\Auth\PasswordAuthSchemeModule'
            - 'SimpleID\Modules\LDAP\LDAPAuthSchemeModule'
    ```

2. Make sure the LDAP server is specified `config.php` in accordance with
   the previous section.

3. For each user you wish to use LDAP authentication, edit its user
   file, and add the following `ldap` object:

    ```yaml
    ldap:
        auth: true
    ```

    If you do not add this line, the user will be authenticated against
    the password stored in the user file.

### How authentication works

1. The module makes an anonymous bind to the LDAP server

2. It looks at the username from the login form,
  
  - if it contains an @ symbol, it will search the LDAP server for
    a user with the `mail` attribute matching the login name
  - otherwise, it will search for a user with the matching `uid` attribute

3. If more than one LDAP entry is found, access is denied

4. The module then attempts to re-bind to the LDAP server using the DN of the 
   matched LDAP entry, and using the password supplied in the login
   form

5. If the re-bind is successful, access is granted


## Using an LDAP directory to store users

To store the list of users on the LDAP directory instead of using user
files:

1. Follow the instructions in the previous section to enable LDAP authentication.

2. In `config.php` enable `SimpleID\Modules\LDAP\LDAPStoreModule`.

### How storage works

1. The module makes an anonymous bind to the LDAP server

2. When the module is asked to retrieve a user, it examines the
   user ID:
  
  - if it contains an @ symbol, it will search the LDAP server for
    a user with the `mail` attribute matching the login name
  - otherwise, it will search for a user with the matching `uid` attribute

3. A user exists if and only if exactly one LDAP entry is found

4. If a user is found, the `dn`, `uid`, `mail` and `cn` attributes are
   extracted from the LDAP entry and a user is created