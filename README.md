pam_saslauthd
=============
Checks and sets passwords using libsasl2.  You should be able to use
this instead of _pam\_unix_ for primary authentication.  NOT heavily
tested and therefore NOT recommended for actual deployments.  Probably
also has some bugs in the password changing functions.

RECOGNIZED ARGUMENTS
--------------------
- *realm*=_REALM_
 - use REALM for the given realm instead of the default
- *service*=_SERVICE_
 - use the given service instead of the PAM service's name
- *use_first_pass
 - use the AUTHTOK on the stack (auth only)
- *try_first_pass*
 - use the AUTHTOK on the stack if it exists, otherwise prompt the user (auth only, this is the default)
- *use_authtok*
 - use the AUTHTOK on the stack instead of prompting the user for the current or new password (password only)

MODULE SERVICES PROVIDED
------------------------
- auth
 - check a password against the secrets in a sasldb
- password
 - sets secrets in a sasldb

CAVEATS
-------
Do not allow this module to call saslauthd if saslauthd is configured
to use PAM unless you override the service name.  If you do, you will
cause a bad recursion.

FILES
-----
- /usr/lib/sasl2/SERVICE.conf
 - The configuration file which libsasl2 will consult to determine how the user's password should be verified.
