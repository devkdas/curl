/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

/* This source code is a MINIMAL, MANUALLY-CONSTRUCTED version for
   DIAGNOSTIC PURPOSES due to optiontable.pl generation issues.
   It is INCOMPLETE and will cause many options to be unrecognized.
   The optiontable.pl script or its inputs MUST be fixed. */

#include "curl_setup.h"
#include "easyoptions.h"

/* A minimal set of easy setopt options listed in alphabetical order */
const struct curl_easyoption Curl_easyopts[] = {
  /* Essential options for basic functionality and testing lookup */
  { "CURLOPT_HTTPHEADER", CURLOPT_HTTPHEADER, CURLOT_SLISTPOINT, 0 },
  { "CURLOPT_POSTFIELDS", CURLOPT_POSTFIELDS, CURLOT_OBJECTPOINT, 0 },
  { "CURLOPT_QUIC_VERSION", CURLOPT_QUIC_VERSION, CURLOT_LONG, 0 }, /* The new option */
  { "CURLOPT_URL", CURLOPT_URL, CURLOT_STRINGPOINT, 0 },
  { "CURLOPT_WRITEDATA", CURLOPT_WRITEDATA, CURLOT_CBPOINT, 0 },
  { "CURLOPT_WRITEFUNCTION", CURLOPT_WRITEFUNCTION, CURLOT_FUNCTIONPOINT, 0 },
  /* Add more options here if test 1918 or basic operations require them */
  /* For example, options used by default or by other tests might be needed */
  { "CURLOPT_VERBOSE", CURLOPT_VERBOSE, CURLOT_LONG, 0 },

  { NULL, CURLOPT_LASTENTRY, CURLOT_LONG, 0 } /* end of table */
};

#ifdef DEBUGBUILD
/*
 * Curl_easyopts_check() is a debug-only function that returns non-zero
 * if this source file is not in sync with the options listed in curl/curl.h
 */
int Curl_easyopts_check(void)
{
  /* This check is expected to FAIL with this minimal table,
     as $lastnum (actual count of options here) is very small.
     The (7 + 1) corresponds to 7 manually added options above.
     This is just to have the function syntactically present.
     A real build would have $lastnum be the true count from optiontable.pl
  */
  return (CURLOPT_LASTENTRY % 10000) != (7 + 1);
}
#endif
