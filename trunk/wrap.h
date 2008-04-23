#ifndef _WRAP_H_
#define _WRAP_H_

PyObject *wrap_ncap_msg_to_python(ncap_msg_ct msg);
int wrap_python_to_ncap_msg(PyObject *src, ncap_msg_t dst);

#endif /* _WRAP_H_ */
