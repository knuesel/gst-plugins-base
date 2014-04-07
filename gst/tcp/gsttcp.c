/* GStreamer
 * Copyright (C) <1999> Erik Walthinsen <omega@cse.ogi.edu>
 * Copyright (C) <2004> Thomas Vander Stichele <thomas at apestaart dot org>
 *
 * gsttcp.c: TCP functions
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <unistd.h>
#include "gsttcp.h"

#ifdef G_OS_WIN32
# include <winsock2.h>
# ifndef socklen_t
#  define socklen_t int
# endif
#else
# include <sys/socket.h>
# include <arpa/inet.h>
# include <netinet/in.h>
# include <netdb.h>
# include <sys/ioctl.h>
#endif

#ifdef HAVE_FIONREAD_IN_SYS_FILIO
#include <sys/filio.h>
#endif

#include <gst/gst-i18n-plugin.h>

GST_DEBUG_CATEGORY_EXTERN (tcp_debug);
#define GST_CAT_DEFAULT tcp_debug

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* resolve host to IP address, throwing errors if it fails */
/* host can already be an IP address */
/* returns a newly allocated gchar * with the dotted ip address,
   or NULL, in which case it already fired an error. */
gchar *
gst_tcp_host_to_ip (GstElement * element, const gchar * host)
{
  struct hostent *hostinfo;
  char **addrs;
  gchar *ip;
  struct in_addr addr;

#ifdef G_OS_WIN32
  long inaddress;
#endif

  GST_DEBUG_OBJECT (element, "resolving host %s", host);

  /* first check if it already is an IP address */
#ifdef G_OS_WIN32
  inaddress = inet_addr(host);
  addr.S_un.S_addr = inaddress;
  if (inaddress != INADDR_NONE) {
#else
  if (inet_aton (host, &addr)) {
#endif
    ip = g_strdup (host);
    goto beach;
  }
  /* FIXME: could do a localhost check here */

  /* perform a name lookup */
  if (!(hostinfo = gethostbyname (host)))
    goto resolve_error;

  if (hostinfo->h_addrtype != AF_INET)
    goto not_ip;

  addrs = hostinfo->h_addr_list;

  /* There could be more than one IP address, but we just return the first */
  ip = g_strdup (inet_ntoa (*(struct in_addr *) *addrs));

beach:
  GST_DEBUG_OBJECT (element, "resolved to IP %s", ip);
  return ip;

resolve_error:
  {
    GST_ELEMENT_ERROR (element, RESOURCE, NOT_FOUND, (NULL),
        ("Could not find IP address for host \"%s\".", host));
    return NULL;
  }
not_ip:
  {
    GST_ELEMENT_ERROR (element, RESOURCE, NOT_FOUND, (NULL),
        ("host \"%s\" is not an IP host", host));
    return NULL;
  }
}

/* write buffer to given socket incrementally.
 * Returns number of bytes written.
 */
gint
gst_tcp_socket_write (int socket, const void *buf, size_t count)
{
  size_t bytes_written = 0;

  while (bytes_written < count) {
    ssize_t wrote = send (socket, (const char *) buf + bytes_written,
        count - bytes_written, MSG_NOSIGNAL);

    if (wrote <= 0) {
      GST_WARNING ("error while writing");
      return bytes_written;
    }
    bytes_written += wrote;
  }

  GST_LOG ("wrote %" G_GSIZE_FORMAT " bytes successfully", bytes_written);
  return bytes_written;
}

/* atomically read count bytes into buf, cancellable. return val of GST_FLOW_OK
 * indicates success, anything else is failure.
 */
static GstFlowReturn
gst_tcp_socket_read (GstElement * this, int socket, void *buf, size_t count,
    GstPoll * fdset)
{
  ssize_t n;
  size_t bytes_read;
#ifdef G_OS_WIN32
  u_long num_to_read;
#else
  int num_to_read;
#endif
  int ret;

  bytes_read = 0;

  while (bytes_read < count) {
    /* do a blocking select on the socket */
    /* no action (0) is an error too in our case */
    if ((ret = gst_poll_wait (fdset, GST_CLOCK_TIME_NONE)) <= 0) {
      if (ret == -1 && errno == EBUSY)
        goto cancelled;
      else
        goto select_error;
    }

    /* ask how much is available for reading on the socket */
#ifdef G_OS_WIN32
    if (ioctlsocket (socket, FIONREAD, &num_to_read) != 0)
#else
    if (ioctl (socket, FIONREAD, &num_to_read) < 0)
#endif
      goto ioctl_error;

    if (num_to_read == 0)
      goto got_eos;

    /* sizeof(ssize_t) >= sizeof(int), so I know num_to_read <= SSIZE_MAX */

    num_to_read = MIN (num_to_read, count - bytes_read);

#ifdef G_OS_WIN32
    n = recv (socket, (char*)(((guint8*)buf) + bytes_read), num_to_read, 0);
#else
    n = read (socket, ((guint8 *) buf) + bytes_read, num_to_read);
#endif

    if (n < 0)
      goto read_error;

    if (n < num_to_read)
      goto short_read;

    bytes_read += num_to_read;
  }

  return GST_FLOW_OK;

  /* ERRORS */
select_error:
  {
    GST_ELEMENT_ERROR (this, RESOURCE, READ, (NULL),
        ("select failed: %s", g_strerror (errno)));
    return GST_FLOW_ERROR;
  }
cancelled:
  {
    GST_DEBUG_OBJECT (this, "Select was cancelled");
    return GST_FLOW_WRONG_STATE;
  }
ioctl_error:
  {
    GST_ELEMENT_ERROR (this, RESOURCE, READ, (NULL),
        ("ioctl failed: %s", g_strerror (errno)));
    return GST_FLOW_ERROR;
  }
got_eos:
  {
    GST_DEBUG_OBJECT (this, "Got EOS on socket stream");
    return GST_FLOW_UNEXPECTED;
  }
read_error:
  {
    GST_ELEMENT_ERROR (this, RESOURCE, READ, (NULL),
        ("read failed: %s", g_strerror (errno)));
    return GST_FLOW_ERROR;
  }
short_read:
  {
    GST_ELEMENT_ERROR (this, RESOURCE, READ, (NULL),
        ("short read: wanted %d bytes, got %" G_GSSIZE_FORMAT, num_to_read, n));
    return GST_FLOW_ERROR;
  }
}

/* close the socket and reset the fd.  Used to clean up after errors. */
void
gst_tcp_socket_close (GstPollFD * socket)
{
  if (socket->fd >= 0) {
#ifdef G_OS_WIN32
    closesocket (socket->fd);
#else
    close (socket->fd);
#endif
    socket->fd = -1;
  }
}

/* read a buffer from the given socket
 * returns:
 * - a GstBuffer in which data should be read
 * - NULL, indicating a connection close or an error, to be handled with
 *         EOS
 */
GstFlowReturn
gst_tcp_read_buffer (GstElement * this, GstPollFD* socket, GstPoll * fdset,
    GstBuffer ** buf)
{
  int ret;
  ssize_t bytes_read;
#ifdef G_OS_WIN32
  u_long readsize;
#else
  int readsize;
#endif

  *buf = NULL;

  /* do a blocking select on the socket */
  /* no action (0) is an error too in our case */
  if ((ret = gst_poll_wait (fdset, GST_CLOCK_TIME_NONE)) <= 0) {
    if (ret == -1 && errno == EBUSY)
      goto cancelled;
    else
      goto select_error;
  }

  if (gst_poll_fd_has_closed(fdset, socket)) {
     goto got_eos;
  }

  /* ask how much is available for reading on the socket */
#ifdef G_OS_WIN32
  if (ioctlsocket(socket->fd, FIONREAD, &readsize) != 0)
#else
  if (ioctl (socket->fd, FIONREAD, &readsize) < 0)
#endif
    goto ioctl_error;

  if (readsize == 0)
    goto got_eos;

  /* sizeof(ssize_t) >= sizeof(int), so I know readsize <= SSIZE_MAX */

  *buf = gst_buffer_new_and_alloc (readsize);

#ifdef G_OS_WIN32
  bytes_read = recv (socket->fd, (char*)GST_BUFFER_DATA(*buf), readsize, 0);
#else
  bytes_read = read (socket->fd, GST_BUFFER_DATA (*buf), readsize);
#endif

  if (bytes_read < 0)
    goto read_error;

  if (bytes_read < readsize)
    /* but mom, you promised to give me readsize bytes! */
    goto short_read;

  GST_LOG_OBJECT (this, "returning buffer of size %d", GST_BUFFER_SIZE (*buf));
  return GST_FLOW_OK;

  /* ERRORS */
select_error:
  {
    GST_ELEMENT_ERROR (this, RESOURCE, READ, (NULL),
        ("select failed: %s", g_strerror (errno)));
    return GST_FLOW_ERROR;
  }
cancelled:
  {
    GST_DEBUG_OBJECT (this, "Select was cancelled");
    return GST_FLOW_WRONG_STATE;
  }
ioctl_error:
  {
    GST_ELEMENT_ERROR (this, RESOURCE, READ, (NULL),
        ("ioctl failed: %s", g_strerror (errno)));
    return GST_FLOW_ERROR;
  }
got_eos:
  {
    GST_DEBUG_OBJECT (this, "Got EOS on socket stream");
    return GST_FLOW_UNEXPECTED;
  }
read_error:
  {
    GST_ELEMENT_ERROR (this, RESOURCE, READ, (NULL),
        ("read failed: %s", g_strerror (errno)));
    gst_buffer_unref (*buf);
    *buf = NULL;
    return GST_FLOW_ERROR;
  }
short_read:
  {
    GST_ELEMENT_ERROR (this, RESOURCE, READ, (NULL),
        ("short read: wanted %d bytes, got %" G_GSSIZE_FORMAT, readsize,
            bytes_read));
    gst_buffer_unref (*buf);
    *buf = NULL;
    return GST_FLOW_ERROR;
  }
}
