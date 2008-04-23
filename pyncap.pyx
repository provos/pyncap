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

    ctypedef struct ncap:
        ncap_pvt_t pvt
        char *errstr
        ncap_result_e (*add_if)(ncap *ncap, char *name, char *bpf,
                               int promisc, int vlans[], int vlan, int *fdes)
        ncap_result_e (*drop_if)(ncap *ncap, int fdes)
        ncap_result_e (*filter)(ncap *ncap, char *filter)
        ncap_result_e (*write)(ncap *ncap, ncap_msg_ct msg, int fdes)
        void (*stop)(ncap *obj)
        void (*destroy)(ncap *obj)

    ctypedef ncap *ncap_t

    ctypedef void (*ncap_callback_t)(ncap_t ncap, void *ctx,
                                     ncap_msg_ct msg_ct,
                                     char *msg)
    ctypedef void (*ncap_watcher_t)(ncap_t ncap, void *ctx, int fdes)

    ncap_t ncap_create(int maxmsg)

cdef extern from "wrap.h":
  PyObject* wrap_ncap_msg_to_python(ncap_msg_t msg)
  ncap_msg_t wrap_python_to_ncap_msg(PyObject *obj)

class NCapError(Exception):
    pass

#
# Make NCap into a proper class
#
cdef class NCap:
    cdef ncap_t _ncap

    def __cinit__(self, maxmsg):
      """Creates an NCap instances with messages up to maxmsg bytes."""
      self._ncap = ncap_create(maxmsg)

    def __dealloc__(self):
      self._ncap.destroy(self._ncap)

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
