#include <Python.h>

#include <ncap.h>

#include "wrap.h"

PyObject *
wrap_ncap_msg_to_python(ncap_msg_t msg)
{
    Py_INCREF(Py_None);
    return Py_None;
}

ncap_msg_t
wrap_python_to_ncap_msg(PyObject *obj)
{
	return NULL;
}
