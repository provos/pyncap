# Python bindings for ISC's Ncap library
# Copyright (c) 2008 Niels Provos.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

cdef extern from "Python.h":
  ctypedef void PyObject

cdef extern from "sys/types.h":
  ctypedef unsigned size_t

cdef extern from "stdio.h":
  ctypedef void FILE

  FILE *fdopen(int filedes, char *mode)
  void fclose(FILE *fp)

cdef extern from "time.h":
  ctypedef long time_t
  ctypedef struct timespec:
    time_t tv_sec
    long tv_nsec

cdef extern from "stdlib.h":
  void *malloc(int len)
  void free(void *buf)

cdef extern from "ncap.h":
    ctypedef enum ncap_np_e:
        ncap_ip4
        ncap_ip6

    ctypedef enum ncap_tp_e:
        ncap_udp
        ncap_tcp

    ctypedef enum ncap_result_e:
        ncap_success
        ncap_failure

    ctypedef enum ncap_ft_e:
        ncap_ncap
        ncap_pcap

    ctypedef struct ncap_pvt
    ctypedef ncap_pvt *ncap_pvt_t

    ctypedef union ncap_np
    ctypedef union ncap_tp
    
    ctypedef struct ncap_msg:
      timespec ts
      unsigned user1
      unsigned user2
      ncap_np_e np
      ncap_tp_e tp
      size_t paylen
      char *payload
      
    ctypedef ncap_msg *ncap_msg_t
    ctypedef ncap_msg *ncap_msg_ct

    ctypedef struct ncap
    ctypedef ncap *ncap_t

    ctypedef void (*ncap_callback_t)(ncap *ncap, void *ctx,
                                     ncap_msg_ct msg_ct,
                                     char *msg)
    ctypedef void (*ncap_watcher_t)(ncap_t ncap, void *ctx, int fdes)

    ctypedef struct ncap:
        ncap_pvt_t pvt
        char *errstr
        ncap_result_e (*add_if)(ncap_t ncap, char *name, char *bpf,
                               int promisc, int vlans[], int vlan, int *fdes)
        ncap_result_e (*drop_if)(ncap_t ncap, int fdes)
        ncap_result_e (*add_fp)(ncap_t ncap, FILE *, ncap_ft_e, char *)
        ncap_result_e (*drop_fp)(ncap_t ncap, FILE *)
        ncap_result_e (*add_dg)(ncap_t, int fdes, char *)
        ncap_result_e (*drop_dg)(ncap_t, int fdes)
        ncap_result_e (*watch_fd)(ncap_t ncap, int fdes,
                                  ncap_watcher_t cb, void *ctx)
        ncap_result_e (*drop_fd)(ncap_t, int fdes)
        ncap_result_e (*filter)(ncap_t ncap, char *filter)
        ncap_result_e (*collect)(ncap_t ncap, int polling, ncap_callback_t cb,
                                 void *closure)
        ncap_result_e (*write)(ncap_t ncap, ncap_msg_ct msg, int fdes)
        void (*stop)(ncap *obj)
        void (*destroy)(ncap *obj)

    ncap_t ncap_create(int maxmsg)

cdef extern from "wrap.h":
  object wrap_ncap_msg_to_python(ncap_msg_t msg)
  ncap_msg_t wrap_python_to_ncap_msg(PyObject *obj)

class NCapError(Exception):
    pass

#
# Deal with the callback from collect
#

cdef void callback(ncap_t ncap, void *ctx, ncap_msg_ct msg, char *some):
  cdef object converted

  converted = wrap_ncap_msg_to_python(msg)
  
  (<object>ctx)(some, converted)

cdef void watcher(ncap_t ncap, void *ctx, int fdes):
  (<object>ctx)(fdes)

#
# The ncap interfaces are not well suited for binding to Python,
# we need to fake up a file class
#

cdef class NCapFile:
  """Convert a Python File object into a FILE object."""
  cdef FILE *_fp
  
  def __cinit__(self, file):
    self._fp = fdopen(file.fileno(), "r")
    if not self._fp:
      raise NCapError, "Cannot create file from %s" % file

  def __dealloc__(self):
    fclose(self._fp)

#
# Make NCap into a proper class
#
cdef class NCap:
    cdef ncap_t _ncap
    cdef object _files

    def __cinit__(self, maxmsg):
      """Creates an NCap instances with messages up to maxmsg bytes."""
      self._ncap = ncap_create(maxmsg)
      self._files = {}

    def __dealloc__(self):
      self._ncap.destroy(self._ncap)

    def LastError(self):
      """Returns the last encountered error string."""
      return self._ncap.errstr

    def AddIf(self, name, bpf, promisc, vlans):
      """Adds capture to the interface called "name" with the bpf filter
      "bpf". The capture is promiscuous if "promisc" is True. A list of
      VLANs can be passed in via "vlans"
      """
      cdef int fdes
      cdef ncap_result_e result
      cdef int *c_vlans
      
      c_vlans = <int *>malloc(8 * len(vlans))
      for off in range(len(vlans)):
        c_vlans[off] = vlans[off]
        
      result = self._ncap.add_if(self._ncap, name, bpf, promisc,
                                   c_vlans, len(vlans), &fdes)
      free(c_vlans)
        
      if result != ncap_success:
        raise NCapError, self._ncap.errstr

      return fdes

    def DropIf(self, fdes):
      """Drops the interface associated with the file descriptor fdes.
      Returns true on success and false otherwise."""
      cdef ncap_result_e result
      
      result = self._ncap.drop_if(self._ncap, fdes)
      return result == ncap_success

    def AddFp(self, file, fmt, label):
      """Adds the opened file to the data collection.  fmt describes if the
      data is formatted either in pcap or in ncap.  The label is used to label
      the data stream."""
      cdef ncap_result_e result
      cdef ncap_ft_e format

      if fmt == "ncap":
        format = ncap_ncap
      elif fmt == "pcap":
        format = ncap_pcap
      else:
        raise NCapError, "unknown data format: %s" % fmt

      if self._files.has_key(file.fileno()):
        raise NCapError, "already associated fd %d" % file.fileno()

      # this has side effects, even if the add_fp fails, we have create this
      # file object and it needs to be dropped with drop_fp
      nf = NCapFile(file)
      self._files[file.fileno()] = nf

      result = self._ncap.add_fp(self._ncap, <FILE*>nf._fp, format, label)

      return result == ncap_success

    def DropFp(self, file):
      """Drop a previously added file object."""
      cdef ncap_result_e result

      if not self._files.has_key(file.fileno()):
        raise NCapError, "the fd is not associated: %d" % file.fileno()

      nf = self._files[file.fileno()]

      result = self._ncap.drop_fp(self._ncap, <FILE*>nf._fp)

      del self._files[file.fileno()]

      return result == ncap_success

    def AddDg(self, fdes, label):
      cdef ncap_result_e result

      result = self._ncap.add_dg(self._ncap, fdes, label)
      return result == ncap_success

    def DropDg(self, fdes):
      cdef ncap_result_e result

      result = self._ncap.drop_dg(self._ncap, fdes)
      return result == ncap_success

    def WatchFd(self, fdes, cb):
      cdef ncap_result_e result

      result = self._ncap.watch_fd(self._ncap, fdes,
                                   <ncap_watcher_t>watcher, <void*>cb)

      return result == ncap_success

    def DropFd(self, fdes):
      cdef ncap_result_e result

      result = self._ncap.drop_fd(self._ncap, fdes)
      return result == ncap_success

    def Filter(self, filter):
      """Installs a new pcap filter on the capture thingy.
      Returns true on success, false otherwise."""

      cdef ncap_result_e result

      result = self._ncap.filter(self._ncap, filter)
      return result == ncap_success

    def Stop(self):
      """Stops the collect loop."""

      self._ncap.stop(self._ncap)

    def Write(self, msg, fdes):
      cdef ncap_msg_t ncap_msg
      cdef ncap_result_e result
      
      ncap_msg = wrap_python_to_ncap_msg(<PyObject *>msg)
      if not ncap_msg:
        raise NCapError, "cannot convert to ncap_msg"

      result = self._ncap.write(self._ncap, ncap_msg, fdes)
      return result == ncap_success

    def Collect(self, polling, f):
      """Run data collection, either once if polling is set or
      until Stop() has been called.   The callback is invoked for
      each collected message."""
      cdef ncap_result_e result

      result = self._ncap.collect(self._ncap, polling,
                                  <ncap_callback_t>callback, <void*>f)

      return result == ncap_success
