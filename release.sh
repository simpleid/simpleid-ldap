#!/bin/bash

if [ ! $# -eq 1 ];
then

  echo "Usage:"
  echo "   $0 <version>"
  exit 1

fi

VERSION="$1"
PRODUCT="simpleid-ldap"
DISTDIR="${PRODUCT}-${VERSION}"
DISTFILE="${PRODUCT}-${VERSION}.tar.gz"

mkdir "${DISTDIR}" || exit 1

cp ldap* README "${DISTDIR}" || exit 1

tar czf "${DISTFILE}" "${DISTDIR}" || exit 1

sha224sum "${DISTFILE}"

