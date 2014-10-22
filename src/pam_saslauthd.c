/*
 * Copyright 2001,2005 Red Hat, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#define PAM_SM_AUTHENTICATE
#define PAM_SM_CHAUTHTOK
#include <security/pam_modules.h>

#include <sasl/sasl.h>

#define PREFIX "pam_saslauthd: "

/* This is just awful -- the callback handed back a structure, and it's assumed
 * that we know how it was allocated so that we can free it properly. */
static void
free_responses(struct pam_response *responses, size_t num)
{
	size_t l;
	if (responses != NULL) {
		for (l = 0; l < num; l++) {
			if (responses[l].resp != NULL) {
				free(responses[l].resp);
			}
		}
		free(responses);
	}
}

static int
get_conv(pam_handle_t *pamh, struct pam_conv **conv)
{
	*conv = NULL;
	return pam_get_item(pamh, PAM_CONV, (const void **) conv);
}

static int
set_string(pam_handle_t *pamh, int item, const char *newval)
{
	return pam_set_item(pamh, item, (const void*) newval);
}

static int
get_const_string(pam_handle_t *pamh, int item, const char **out)
{
	*out = NULL;
	return pam_get_item(pamh, item, (const void **) out);
}

static void
log_debug(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	vsyslog(LOG_DEBUG, fmt, va);
	va_end(va);
}

static void
log_info(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	vsyslog(LOG_INFO, fmt, va);
	va_end(va);
}

static void
log_warning(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	vsyslog(LOG_WARNING, fmt, va);
	va_end(va);
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *user, *password;
	int secondpass, ret;
	struct pam_conv *conv;
	struct pam_response *responses;
	int debug;

	const char *service, *realm;
	struct sasl_conn *conn;
	struct sasl_callback cb = {
		SASL_CB_LIST_END,
		NULL,
		NULL,
	};

	/* Find the conversation function.  This should never fail. */
	ret = get_conv(pamh, &conv);
	if (ret != PAM_SUCCESS) {
		syslog(LOG_CRIT, PREFIX
		       "error determining conversation function");
		return PAM_SYSTEM_ERR;
	}

	/* Parse the arguments. */
	debug = 0;
	realm = NULL;
	service = NULL;
	secondpass = 1;
	for (ret = 0; ret < argc; ret++) {
		if (strcmp(argv[ret], "debug") == 0) {
			debug++;
			continue;
		}
	}
	for (ret = 0; ret < argc; ret++) {
		if (strcmp(argv[ret], "use_first_pass") == 0) {
			secondpass = 0;
			if (debug) {
				log_debug(PREFIX "use_first_pass");
			}
			continue;
		}
		if (strcmp(argv[ret], "try_first_pass") == 0) {
			secondpass = 1;
			if (debug) {
				log_debug(PREFIX "try_first_pass");
			}
			continue;
		}
		if (strncmp(argv[ret], "service=", 8) == 0) {
			service = argv[ret] + 8;
			if (debug) {
				log_debug(PREFIX "override service = \"%s\"",
					  service);
			}
			continue;
		}
		if (strncmp(argv[ret], "realm=", 6) == 0) {
			realm = argv[ret] + 6;
			if (debug) {
				log_debug(PREFIX "set realm = \"%s\"", realm);
			}
			continue;
		}
	}

	/* Find the user.  This should never fail. */
	ret = pam_get_user(pamh, &user, NULL);
	if ((ret != PAM_SUCCESS) || (user == NULL) || (strlen(user) == 0)) {
		log_warning(PREFIX "error determining user");
		return PAM_USER_UNKNOWN;
	}

	/* If there was no overriding service given, use the PAM service. */
	if (service == NULL) {
		ret = get_const_string(pamh, PAM_SERVICE, &service);
		if (ret != PAM_SUCCESS) {
			syslog(LOG_CRIT, PREFIX "error determining service");
			return PAM_SYSTEM_ERR;
		}
	}

	/* Read the currently entered password. */
	password = NULL;
	ret = get_const_string(pamh, PAM_AUTHTOK, &password);
	if (((ret != PAM_SUCCESS) || (password == NULL)) && secondpass) {
		/* If we didn't get a password, and we're allowed to ask
		 * the user for one, try it. */
		struct pam_message message = {
			PAM_PROMPT_ECHO_OFF, "Password: ",
		};
		const struct pam_message *messages[] = {
			&message,
		};
		if (debug) {
			log_debug(PREFIX "prompting for password");
		}
		ret = conv->conv(sizeof(messages) / sizeof(messages[0]),
				 messages,
				 &responses,
				 conv->appdata_ptr);
		if (ret == PAM_SUCCESS) {
			if ((responses == NULL) ||
			    (responses[0].resp_retcode != PAM_SUCCESS)) {
				/* No response. */
				log_warning(PREFIX "PAM conversation error");
				ret = PAM_CONV_ERR;
			} else {
				/* Got a response. */
				if (responses[0].resp != NULL) {
					if (password == NULL) {
						set_string(pamh, PAM_AUTHTOK,
							   responses[0].resp);
					}
					password = strdup(responses[0].resp);
				}
			}
		}
		free_responses(responses,
			       sizeof(messages) / sizeof(messages[0]));
	}

	if (ret != PAM_SUCCESS) {
		return ret;
	}

	if (password == NULL) {
		log_warning(PREFIX "NULL password");
		return PAM_CONV_ERR;
	}

	/* Initialize libsasl. */
	ret = sasl_server_init(&cb, service ? service : "PAM");
	if (ret != SASL_OK) {
		log_warning(PREFIX "error initializing server: %s",
			    sasl_errstring(ret, NULL, NULL));
		return PAM_SYSTEM_ERR;
	}
	if (debug) {
		log_debug(PREFIX "sasl_server_init");
	}

	/* Initialize a connection context. */
	ret = sasl_server_new(service,
			      NULL,
			      realm,
			      NULL,
			      NULL,
			      &cb,
			      SASL_SEC_NOANONYMOUS,
			      &conn);
	if (ret != SASL_OK) {
		if (debug) {
			log_debug(PREFIX "error allocating server context: %s",
				  sasl_errstring(ret, NULL, NULL));
		}
		return PAM_SYSTEM_ERR;
	}
	if (debug) {
		log_debug(PREFIX "sasl_server_new");
	}

	/* Check the user's password. */
	ret = sasl_checkpass(conn,
			     user, strlen(user),
			     password, strlen(password));
			     
	if (ret != SASL_OK) {
		log_warning(PREFIX "error checking password: %s",
			    sasl_errstring(ret, NULL, NULL));
		sasl_dispose(&conn);
		return PAM_AUTH_ERR;
	}
	if (debug) {
		log_debug(PREFIX "sasl_checkpass");
	}

	/* Good to go. */
	sasl_dispose(&conn);
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *user, *oldpassword, *password;
	int migrate, use_authtok, ret, debug, use_first_pass;
	struct pam_conv *conv;
	struct pam_response *responses;
	const char *service, *realm;
	struct sasl_conn *conn;
	struct sasl_callback cb = {
		SASL_CB_LIST_END,
		NULL,
		NULL,
	};

	/* Parse the argument list. */
	debug = 0;
	realm = NULL;
	use_first_pass = 0;
	use_authtok = 0;
	service = NULL;
	migrate = 0;
	for (ret = 0; ret < argc; ret++) {
		if (strcmp(argv[ret], "debug") == 0) {
			debug++;
			continue;
		}
	}
	for (ret = 0; ret < argc; ret++) {
		if (strncmp(argv[ret], "service=", 8) == 0) {
			service = argv[ret] + 8;
			if (debug) {
				log_debug(PREFIX "override service = \"%s\"",
					  service);
			}
			continue;
		}
		if (strncmp(argv[ret], "realm=", 6) == 0) {
			realm = argv[ret] + 6;
			if (debug) {
				log_debug(PREFIX "set realm = \"%s\"", realm);
			}
			continue;
		}
		if (strcmp(argv[ret], "migrate") == 0) {
			migrate++;
			if (debug) {
				log_debug(PREFIX "migrate");
			}
			continue;
		}
		if (strcmp(argv[ret], "use_first_pass") == 0) {
			use_first_pass++;
			if (debug) {
				log_debug(PREFIX "use_first_pass");
			}
			continue;
		}
		if (strcmp(argv[ret], "use_authtok") == 0) {
			use_authtok++;
			if (debug) {
				log_debug(PREFIX "use_authtok");
			}
			continue;
		}
	}
	if (debug) {
		if (flags & PAM_PRELIM_CHECK) {
			log_debug(PREFIX
				  "called for password change phase one");
		}
		if (flags & PAM_UPDATE_AUTHTOK) {
			log_debug(PREFIX
				  "called for password change phase two");
		}
	}

	/* Get the conversation pointer.  This should never fail. */
	ret = get_conv(pamh, &conv);
	if ((ret != PAM_SUCCESS) || (conv == NULL) || (conv->conv == NULL)) {
		log_warning(PREFIX "error determining conversation function");
		return PAM_SYSTEM_ERR;
	}

	/* If we didn't get a service override, use the PAM service's name. */
	if (service == NULL) {
		ret = get_const_string(pamh, PAM_SERVICE, &service);
		if ((ret != PAM_SUCCESS) ||
		    (service == NULL) ||
		    (strlen(service) == 0)){
			log_warning(PREFIX "error determining service");
			return PAM_SYSTEM_ERR;
		}
	}

	/* Get the user name.  This should never fail. */
	ret = pam_get_user(pamh, &user, NULL);
	if ((ret != PAM_SUCCESS) || (user == NULL) || (strlen(user) == 0)) {
		log_warning(PREFIX "error determining user");
		return PAM_USER_UNKNOWN;
	}

	/* Ask for the old password. */
	ret = get_const_string(pamh, PAM_OLDAUTHTOK, &oldpassword);
	if (((ret != PAM_SUCCESS) || (oldpassword == NULL)) &&
	    !use_first_pass) {
		struct pam_message message = {
			PAM_PROMPT_ECHO_OFF,
			"Password: ",
		};
		const struct pam_message *messages[] = {
			&message,
		};
		if (debug) {
			log_debug(PREFIX "asking for current password");
		}
		ret = conv->conv(sizeof(messages) / sizeof(messages[0]),
				 messages,
				 &responses,
				 conv->appdata_ptr);
		if (ret == PAM_SUCCESS) {
			if ((responses == NULL) ||
			    (responses[0].resp_retcode != PAM_SUCCESS)) {
				/* No response. */
				log_warning(PREFIX "PAM conversation error");
				ret = PAM_CONV_ERR;
			} else {
				/* Got a response. */
				if (responses[0].resp != NULL) {
					if (oldpassword == NULL) {
						set_string(pamh, PAM_OLDAUTHTOK,
							   responses[0].resp);
					}
					oldpassword = strdup(responses[0].resp);
				}
			}
		}
		free_responses(responses,
			       sizeof(messages) / sizeof(messages[0]));
	}

	if (ret != PAM_SUCCESS) {
		return ret;
	}

	if (oldpassword == NULL) {
		log_warning(PREFIX "error reading current password");
		return PAM_CONV_ERR;
	}

	/* Ask for the new password. */
	if (flags & PAM_UPDATE_AUTHTOK) {
		ret = get_const_string(pamh, PAM_AUTHTOK, &password);
		if (((ret != PAM_SUCCESS) || (password == NULL)) &&
		    !use_authtok) {
			struct pam_message message = {
				PAM_PROMPT_ECHO_OFF,
				"New password: ",
			};
			const struct pam_message *messages[] = {
				&message,
			};
			if (debug) {
				log_debug(PREFIX "asking for new password");
			}
			ret = conv->conv(sizeof(messages) / sizeof(messages[0]),
					 messages,
					 &responses,
					 conv->appdata_ptr);
			if (ret == PAM_SUCCESS) {
				if ((responses == NULL) ||
				    (responses[0].resp_retcode != PAM_SUCCESS)) {
					/* No response. */
					ret = PAM_CONV_ERR;
					log_warning(PREFIX
						    "PAM conversation error");
				} else {
					/* Got a response. */
					if (responses[0].resp != NULL) {
						if (password == NULL) {
							set_string(pamh, PAM_AUTHTOK,
								   responses[0].resp);
						}
						password = strdup(responses[0].resp);
					}
				}
			}
			free_responses(responses,
				       sizeof(messages) / sizeof(messages[0]));
		}

		if (ret != PAM_SUCCESS) {
			return ret;
		}

		if (password == NULL) {
			log_warning(PREFIX
				    "PAM conversation error: no password read");
			return PAM_CONV_ERR;
		}
	}

	/* Initialize libsasl. */
	ret = sasl_server_init(&cb, service ? service : "PAM");
	if (ret != SASL_OK) {
		log_warning(PREFIX "error initializing server: %s",
			    sasl_errstring(ret, NULL, NULL));
		return PAM_SYSTEM_ERR;
	}
	if (debug) {
		log_debug(PREFIX "sasl_server_init");
	}

	/* Allocate a new server structure. */
	ret = sasl_server_new(service ? service : "PAM",
			      NULL,
			      realm,
			      NULL,
			      NULL,
			      &cb,
			      SASL_SEC_NOANONYMOUS,
			      &conn);
	if (ret != SASL_OK) {
		log_warning(PREFIX "error allocating server context: %s",
			    sasl_errstring(ret, NULL, NULL));
		return PAM_SYSTEM_ERR;
	}
	if (debug) {
		log_debug(PREFIX "sasl_server_new");
	}

	if (flags & PAM_PRELIM_CHECK) {
		/* Check the password. */
		ret = sasl_checkpass(conn,
				     user, strlen(user),
				     oldpassword, strlen(oldpassword));
		sasl_dispose(&conn);
		if (ret != SASL_OK) {
			if (migrate) {
				log_warning(PREFIX "ignoring password check");
				return PAM_IGNORE;
			} else {
				log_warning(PREFIX
					    "error checking password: %s",
					    sasl_errstring(ret, NULL, NULL));
				sasl_dispose(&conn);
				switch (ret) {
				case SASL_NOMECH:
					return PAM_SYSTEM_ERR;
				case SASL_NOUSER:
					return PAM_USER_UNKNOWN;
				default:
					return PAM_AUTH_ERR;
				}
			}
		} else {
			log_info(PREFIX "password check for \"%s\" succeeds",
				 user);
			return PAM_SUCCESS;
		}
	}

	if (flags & PAM_UPDATE_AUTHTOK) {
		/* On the update, we need to set the password. */
		ret = sasl_setpass(conn,
				   user,
				   password,
				   strlen(password),
				   oldpassword ? oldpassword : "",
				   strlen(oldpassword ? oldpassword : ""),
				   SASL_SET_CREATE);
		sasl_dispose(&conn);
		if (ret != SASL_OK) {
			log_warning(PREFIX
				    "error setting password for \"%s\": %s",
				    user, sasl_errstring(ret, NULL, NULL));
			switch (ret) {
			case SASL_DISABLED:
				return PAM_AUTH_ERR;
			case SASL_NOCHANGE:
			case SASL_NOVERIFY:
			case SASL_WEAKPASS:
			case SASL_PWLOCK:
				return PAM_AUTHTOK_ERR;
			case SASL_NOMECH:
			case SASL_NOUSERPASS:
			case SASL_FAIL:
			default:
				return PAM_SYSTEM_ERR;
			}
		}
		log_info(PREFIX "set password for \"%s\"", user);
		return PAM_SUCCESS;
	}

	/* Neither preliminary check nor the update, we're so confused. */
	log_warning(PREFIX "don't know what to do");
	sasl_dispose(&conn);
	return PAM_SYSTEM_ERR;
}
