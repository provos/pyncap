#include <Python.h>

#include <sys/types.h>
#include <arpa/inet.h>
#include <ncap.h>

#include "wrap.h"

static PyObject *
ncap_tp_to_python(ncap_tp_e what, const union ncap_tp *tp)
{
	if (what == ncap_tcp) {
		return Py_BuildValue(
			"{sIsIsIsI}",
			"sport", tp->tcp.sport,
			"dport", tp->tcp.dport,
			"offset", tp->tcp.offset,
			"flags", tp->tcp.flags);
	} else {
		return Py_BuildValue(
			"{sIsI}",
			"sport", tp->udp.sport,
			"dport", tp->udp.dport);
	}
}

static int
python_to_ncap_tp(ncap_tp_e what, PyObject *src, union ncap_tp *dst)
{
	PyObject *sport, *dport;

	sport = PyDict_GetItemString(src, "sport");
	dport = PyDict_GetItemString(src, "dport");
	if (src == NULL || dst == NULL ||
	    !PyInt_Check(sport) || !PyInt_Check(dport))
		return (-1);

	if (what == ncap_tcp) {
		PyObject *flags, *offset;
		flags = PyDict_GetItemString(src, "flags");
		offset = PyDict_GetItemString(src, "offset");

		if (flags == NULL || offset == NULL ||
		    !PyInt_Check(flags) || !PyInt_Check(offset))
			return (-1);

		dst->tcp.sport = PyInt_AsLong(sport);
		dst->tcp.dport = PyInt_AsLong(dport);
		dst->tcp.flags = PyInt_AsLong(flags);
		dst->tcp.offset = PyInt_AsLong(offset);
	} else {
		dst->udp.sport = PyInt_AsLong(sport);
		dst->udp.dport = PyInt_AsLong(dport);
	}

	return (0);
}

static PyObject *
ncap_np_to_python(ncap_np_e what, const union ncap_np *np)
{
	void *nsrc, *ndst;
	char src[64], dst[64];
	int af;

	if (what == ncap_ip6) {
		af = AF_INET6;
		nsrc = (void *)&np->ip6.src;
		ndst = (void *)&np->ip6.dst;
	} else {
		af = AF_INET;
		nsrc = (void *)&np->ip4.src;
		ndst = (void *)&np->ip4.dst;
	}

	if (inet_ntop(af, nsrc, src, sizeof(src)) == NULL)
		return NULL;

	if (inet_ntop(af, ndst, dst, sizeof(dst)) == NULL)
		return NULL;

	return Py_BuildValue("{ssss}", "src", src, "dst", dst);
}

static int
python_to_ncap_np(ncap_np_e what, PyObject *src, union ncap_np *dst)
{
	PyObject *psrc, *pdst;
	const char *asrc, *adst;

	if ((psrc = PyDict_GetItemString(src, "src")) == NULL)
		return (-1);
	if ((pdst = PyDict_GetItemString(src, "dst")) == NULL)
		return (-1);

	if ((asrc = PyString_AsString(psrc)) == NULL)
		return (-1);
	if ((adst = PyString_AsString(pdst)) == NULL)
		return (-1);

	if (what == ncap_ip6) {
		if (inet_pton(AF_INET6, asrc, &dst->ip6.src) == -1)
			return (-1);
		if (inet_pton(AF_INET6, adst, &dst->ip6.dst) == -1)
			return (-1);
	} else {
		if (inet_pton(AF_INET, asrc, &dst->ip4.src) == -1)
			return (-1);
		if (inet_pton(AF_INET, adst, &dst->ip4.dst) == -1)
			return (-1);
	}

	return (0);
}

PyObject *
wrap_ncap_msg_to_python(ncap_msg_ct msg)
{
	PyObject *npu = NULL, *tpu = NULL;
	PyObject *obj = NULL;

	if ((npu = ncap_np_to_python(msg->np, &msg->npu)) == NULL)
		goto error;
	if ((tpu = ncap_tp_to_python(msg->tp, &msg->tpu)) == NULL)
		goto error;

	obj = Py_BuildValue(
		"{sLsIsIsssssNsNss#}",
		"ts", (long long)msg->ts.tv_sec * 1000000L +
		msg->ts.tv_nsec / 1000,
		"user1", msg->user1,
		"user2", msg->user2,
		"np", msg->np == ncap_ip6? "ip6" : "ip4",
		"tp", msg->tp == ncap_tcp? "tcp" : "udp",
		"npu", npu,
		"tpu", tpu,
		"payload", msg->payload ? (char *)msg->payload : "", msg->paylen
	    );

	if (obj == NULL)
		goto error;

	return obj;

error:
	Py_XDECREF(npu);
	Py_XDECREF(tpu);

	return NULL;
}

int
wrap_python_to_ncap_msg(PyObject *src, ncap_msg_t dst)
{
	return -1;
}
