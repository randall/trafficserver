/** @file

  Some utility and support functions for the management module.

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */
#include "tscore/ink_platform.h"
#include "tscore/ink_sock.h"
#include "MgmtUtils.h"
#include "MgmtSocket.h"
#include "tscore/Diags.h"

#include "LocalManager.h"

static int use_syslog = 0;

/* mgmt_use_syslog()
 *
 *    Called to indicate that the syslog should be used and
 *       the log has been opened
 */
void
mgmt_use_syslog()
{
  use_syslog = 1;
}

/*
 * mgmt_read_pipe()
 * - Reads from a pipe
 *
 * Returns: bytes read
 *          0 on EOF
 *          -errno on error
 */

int
mgmt_read_pipe(int fd, char *buf, int bytes_to_read)
{
  char *p        = buf;
  int bytes_read = 0;

  while (bytes_to_read > 0) {
    int err = read_socket(fd, p, bytes_to_read);
    if (err == 0) {
      return err;
    } else if (err < 0) {
      // Turn ECONNRESET into EOF.
      if (errno == ECONNRESET || errno == EPIPE) {
        return bytes_read ? bytes_read : 0;
      }

      if (mgmt_transient_error()) {
        mgmt_sleep_msec(1);
        continue;
      }

      return -errno;
    }

    bytes_to_read -= err;
    bytes_read += err;
    p += err;
  }

  return bytes_read;
}

/*
 * mgmt_write_pipe()
 * - Writes to a pipe
 *
 * Returns: bytes written
 *          0 on EOF
 *          -errno on error
 */

int
mgmt_write_pipe(int fd, char *buf, int bytes_to_write)
{
  char *p           = buf;
  int bytes_written = 0;

  while (bytes_to_write > 0) {
    int err = write_socket(fd, p, bytes_to_write);
    if (err == 0) {
      return err;
    } else if (err < 0) {
      if (mgmt_transient_error()) {
        mgmt_sleep_msec(1);
        continue;
      }

      return -errno;
    }

    bytes_to_write -= err;
    bytes_written += err;
    p += err;
  }

  return bytes_written;
}

void
mgmt_log(const char *message_format, ...)
{
  va_list ap;
  char extended_format[4096], message[4096];

  va_start(ap, message_format);
  if (diags) {
    NoteV(message_format, ap);
  } else {
    if (use_syslog) {
      snprintf(extended_format, sizeof(extended_format), "log ==> %s", message_format);
      vsprintf(message, extended_format, ap);
      syslog(LOG_WARNING, "%s", message);
    } else {
      snprintf(extended_format, sizeof(extended_format), "[E. Mgmt] log ==> %s", message_format);
      vsprintf(message, extended_format, ap);
      ink_assert(fwrite(message, strlen(message), 1, stderr) == 1);
    }
  }

  va_end(ap);
  return;
} /* End mgmt_log */

void
mgmt_elog(const int lerrno, const char *message_format, ...)
{
  va_list ap;
  char extended_format[4096], message[4096];

  va_start(ap, message_format);

  if (diags) {
    ErrorV(message_format, ap);
    if (lerrno != 0) {
      Error("last system error %d: %s", lerrno, strerror(lerrno));
    }
  } else {
    if (use_syslog) {
      snprintf(extended_format, sizeof(extended_format), "ERROR ==> %s", message_format);
      vsprintf(message, extended_format, ap);
      syslog(LOG_ERR, "%s", message);
      if (lerrno != 0) {
        syslog(LOG_ERR, " (last system error %d: %s)", lerrno, strerror(lerrno));
      }
    } else {
      snprintf(extended_format, sizeof(extended_format), "Manager ERROR: %s", message_format);
      vsprintf(message, extended_format, ap);
      ink_assert(fwrite(message, strlen(message), 1, stderr) == 1);
      if (lerrno != 0) {
        snprintf(message, sizeof(message), "(last system error %d: %s)", lerrno, strerror(lerrno));
        ink_assert(fwrite(message, strlen(message), 1, stderr) == 1);
      }
    }
  }
  va_end(ap);
  return;
} /* End mgmt_elog */

void
mgmt_fatal(const int lerrno, const char *message_format, ...)
{
  va_list ap;

  va_start(ap, message_format);

  if (diags) {
    if (lerrno != 0) {
      Error("last system error %d: %s", lerrno, strerror(lerrno));
    }

    FatalV(message_format, ap);
  } else {
    char extended_format[4096], message[4096];
    snprintf(extended_format, sizeof(extended_format), "FATAL ==> %s", message_format);
    vsprintf(message, extended_format, ap);

    ink_assert(fwrite(message, strlen(message), 1, stderr) == 1);

    if (use_syslog) {
      syslog(LOG_ERR, "%s", message);
    }

    if (lerrno != 0) {
      fprintf(stderr, "[E. Mgmt] last system error %d: %s", lerrno, strerror(lerrno));

      if (use_syslog) {
        syslog(LOG_ERR, " (last system error %d: %s)", lerrno, strerror(lerrno));
      }
    }
  }

  va_end(ap);

  mgmt_cleanup();
  ::exit(1);
} /* End mgmt_fatal */

static inline int
get_interface_mtu(int sock_fd, struct ifreq *ifr)
{
  if (ioctl(sock_fd, SIOCGIFMTU, ifr) < 0) {
    mgmt_log("[getAddrForIntr] Unable to obtain MTU for "
             "interface '%s'",
             ifr->ifr_name);
    return 0;
  } else {
#if defined(solaris) || defined(hpux)
    return ifr->ifr_metric;
#else
    return ifr->ifr_mtu;
#endif
  }
}

void
mgmt_sleep_sec(int seconds)
{
  sleep(seconds);
}

void
mgmt_sleep_msec(int msec)
{
  usleep(msec * 1000);
}
