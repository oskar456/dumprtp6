dnl Process this file with autoconf to produce a configure script.
AC_INIT([dumprtp6], [0.3])
AC_CONFIG_SRCDIR([dumprtp6.c])
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(config.h)

dnl Checks for programs.
AC_PROG_CC
AC_CHECK_FUNCS(getopt_long getaddrinfo getnameinfo, ,
	       AC_MSG_ERROR(Required functions missing))
AC_CHECK_FUNCS(program_invocation_short_name)

AC_OUTPUT(Makefile)
echo -e "\nAll done. Run make now."


