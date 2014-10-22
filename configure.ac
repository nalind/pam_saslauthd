AC_INIT(pam_saslauthd,0.0)
AM_INIT_AUTOMAKE([foreign])
AC_DISABLE_STATIC
AC_PROG_LIBTOOL
AC_CHECK_HEADER(sasl/sasl.h,,[AC_ERROR([unable to find Cyrus SASL 2.x development headers])])
AC_CHECK_HEADER(security/pam_modules.h,,[AC_ERROR([unable to find PAM development headers])])
AC_CHECK_FUNC(sasl_setpass,,[AC_CHECK_LIB(sasl2,sasl_setpass)])
AM_MAINTAINER_MODE
AC_CONFIG_HEADER(src/config.h)
AC_OUTPUT(Makefile src/Makefile pam_saslauthd.spec src/pam_saslauthd.8)
