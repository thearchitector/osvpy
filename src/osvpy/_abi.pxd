from libc.stdint cimport uintptr_t, uint32_t, int64_t
from libc.stddef cimport size_t

cdef extern from "libosvpy.h" nogil:
    ctypedef struct osv_value:
        uint32_t tag
        uint32_t kind
        uint32_t row
        uint32_t sub
        uint32_t number
        size_t size
    int osv_batch_create(char*, size_t, uintptr_t*)
    int osv_batch_start(uintptr_t)
    int osv_batch_wait(uintptr_t)
    int osv_batch_cancel(uintptr_t)
    int osv_batch_finish(uintptr_t, uintptr_t*)
    int osv_batch_release(uintptr_t)
    int osv_result_release(uintptr_t)
    int osv_result_get(
        uintptr_t, uint32_t, uint32_t, uint32_t, uint32_t,
        int64_t, char*, size_t, osv_value*,
    )
