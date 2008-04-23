#ifndef _WRAP_H_
#define _WRAP_H_

PyObject *wrap_ncap_msg_to_python(ncap_msg_ct msg);
ncap_msg_t wrap_python_to_ncap_msg(PyObject *);

#endif /* _WRAP_H_ */
