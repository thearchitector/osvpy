# cython: language_level=3, freethreading_compatible=True
"""Immutable views of a completed Go report. No child handles or caches."""
from ._abi cimport *
from cpython.unicode cimport PyUnicode_DecodeUTF8
from cpython.number cimport PyNumber_AsSsize_t
from cpython.slice cimport PySlice_GetIndicesEx
from libc.stdlib cimport malloc, free
import threading
from collections.abc import Sequence
from .exceptions import NativeLibraryError

cdef object construction_key = object()
cdef object construction_args = (construction_key,)

cdef extern from *:
    """
    /* Reuse the immutable constructor arguments while retaining Cython's
       tp_new initialization (including GC and any generated type state). */
    static PyObject *osv_new_view(PyObject *cls, PyObject *args) {
        return ((PyTypeObject *)cls)->tp_new((PyTypeObject *)cls, args, NULL);
    }
    """
    object osv_new_view(object cls, object args)

if osv_abi_version() != 6:
    raise ImportError("osvpy native ABI mismatch; rebuild or reinstall osvpy")

cdef int check(int status) except -1:
    if status:
        code = {1: "internal_error", 2: "report_overflow",
                3: "allocation_failure", 4: "cancelled"}.get(status, "internal_error")
        raise NativeLibraryError(f"Native batch failed: {code}", code=code)
    return 0

cdef class _Owner:
    # Every view/sequence holds this owner strongly. Dropping the final Python
    # reference (including through cyclic GC) removes the Go report's sole root.
    cdef uintptr_t handle

    def __dealloc__(self):
        if self.handle:
            osv_result_release(self.handle)
            self.handle = 0

cdef class _View:
    cdef _Owner owner
    cdef uint32_t kind, row, sub

    def __cinit__(self, key=None):
        if key is not construction_key:
            raise TypeError("Results and views are created by scan()")

    def __init__(self):
        raise TypeError("Results and views are created by scan()")

    @property
    def index(self):
        return self.row

    def __hash__(self):
        return hash((id(self.owner), self.kind, self.row, self.sub))

    def __eq__(self, other):
        if not isinstance(other, _View):
            return NotImplemented
        return (self.owner is (<_View>other).owner and
                self.kind == (<_View>other).kind and
                self.row == (<_View>other).row and
                self.sub == (<_View>other).sub)

    def __reduce_ex__(self, protocol):
        raise TypeError("Native results cannot be pickled")

cdef class IndexedSequence:
    cdef _Owner owner
    cdef uint32_t kind, row, sub, field
    cdef Py_ssize_t size

    def __cinit__(self, key=None):
        if key is not construction_key:
            raise TypeError("Sequences are created by result properties")

    def __init__(self):
        raise TypeError("Sequences are created by result properties")

    def __len__(self):
        return self.size

    def __getitem__(self, index):
        cdef Py_ssize_t i, start, stop, step, length
        cdef list items
        if isinstance(index, slice):
            PySlice_GetIndicesEx(index, self.size, &start, &stop, &step, &length)
            items = []
            for i in range(length):
                items.append(read(self.owner, self.kind, self.row, self.sub,
                                  self.field, start + i * step))
            return tuple(items)
        i = PyNumber_AsSsize_t(index, IndexError)
        if i < 0:
            i += self.size
        if i < 0 or i >= self.size:
            raise IndexError("result sequence index out of range")
        return read(self.owner, self.kind, self.row, self.sub, self.field, i)

    def __iter__(self):
        cdef Py_ssize_t i
        for i in range(self.size):
            yield read(self.owner, self.kind, self.row, self.sub, self.field, i)

    def __hash__(self):
        return hash((id(self.owner), self.kind, self.row, self.sub, self.field))

    def __eq__(self, other):
        if not isinstance(other, IndexedSequence):
            return NotImplemented
        return (self.owner is (<IndexedSequence>other).owner and
                self.kind == (<IndexedSequence>other).kind and
                self.row == (<IndexedSequence>other).row and
                self.sub == (<IndexedSequence>other).sub and
                self.field == (<IndexedSequence>other).field)

    def __reduce_ex__(self, protocol):
        raise TypeError("Native sequences cannot be pickled")

    def count(self, value):
        cdef Py_ssize_t i, matches = 0
        for i in range(self.size):
            if read(self.owner, self.kind, self.row, self.sub, self.field, i) == value:
                matches += 1
        return matches

    def index(self, value, start=0, stop=None):
        cdef Py_ssize_t i, first, last, step, length
        PySlice_GetIndicesEx(
            slice(start, stop), self.size, &first, &last, &step, &length,
        )
        for i in range(first, last):
            if read(self.owner, self.kind, self.row, self.sub, self.field, i) == value:
                return i
        raise ValueError("value is not in sequence")

Sequence.register(IndexedSequence)

cdef object view(_Owner owner, uint32_t kind, uint32_t row, uint32_t sub):
    cdef _View result
    if kind == 1:
        result = osv_new_view(BatchResult, construction_args)
    elif kind == 2:
        result = osv_new_view(ImageResult, construction_args)
    elif kind == 3:
        result = osv_new_view(Package, construction_args)
    elif kind == 4:
        result = osv_new_view(Vulnerability, construction_args)
    elif kind == 5:
        result = osv_new_view(AdvisorySource, construction_args)
    elif kind == 6:
        result = osv_new_view(Occurrence, construction_args)
    elif kind == 7:
        result = osv_new_view(Finding, construction_args)
    elif kind == 8:
        result = osv_new_view(ReportContext, construction_args)
    elif kind == 9:
        result = osv_new_view(ReportAssessment, construction_args)
    elif kind == 10:
        result = osv_new_view(ReportLicense, construction_args)
    elif kind == 11:
        result = osv_new_view(ReportFix, construction_args)
    elif kind == 12:
        result = osv_new_view(ScanMetadata, construction_args)
    elif kind == 13:
        result = osv_new_view(NativeError, construction_args)
    elif kind == 14:
        result = osv_new_view(ReportSeverity, construction_args)
    elif kind == 15:
        result = osv_new_view(ReportReference, construction_args)
    elif kind == 16:
        result = osv_new_view(ReportSeverity, construction_args)
    else:
        raise NativeLibraryError("Invalid native record kind")
    result.owner, result.kind, result.row, result.sub = owner, kind, row, sub
    return result

cdef object read(_Owner owner, uint32_t kind, uint32_t row, uint32_t sub,
                 uint32_t field, int64_t index=-1):
    cdef char local[512]
    cdef char* buffer = local
    cdef osv_value value
    cdef IndexedSequence sequence
    cdef int status
    check(osv_result_get(
        owner.handle, kind, row, sub, field, index, local, 512, &value,
    ))
    if value.tag == 0:
        return None
    if value.tag == 1:
        if value.size > 512:
            buffer = <char*>malloc(value.size)
            if buffer == NULL:
                raise MemoryError()
            try:
                with nogil:
                    status = osv_result_get(owner.handle, kind, row, sub, field, index,
                                            buffer, value.size, &value)
                check(status)
                return PyUnicode_DecodeUTF8(buffer, value.size, "strict")
            finally:
                free(buffer)
        return PyUnicode_DecodeUTF8(local, value.size, "strict")
    if value.tag == 2:
        return bool(value.number)
    if value.tag == 3:
        return value.number
    if value.tag == 4:
        return view(owner, value.kind, value.row, value.sub)
    if value.tag == 5:
        sequence = osv_new_view(IndexedSequence, construction_args)
        sequence.owner = owner
        sequence.kind, sequence.row, sequence.sub, sequence.field = (
            kind, row, sub, field,
        )
        sequence.size = <Py_ssize_t>value.number
        return sequence
    raise NativeLibraryError("Invalid native value")

cdef class BatchResult(_View):
    @property
    def images(self):
        return read(self.owner, self.kind, self.row, self.sub, 1)

    @property
    def packages(self):
        return read(self.owner, self.kind, self.row, self.sub, 2)

    @property
    def vulnerabilities(self):
        return read(self.owner, self.kind, self.row, self.sub, 3)

    @property
    def advisory_sources(self):
        return read(self.owner, self.kind, self.row, self.sub, 4)

    @property
    def findings(self):
        return read(self.owner, self.kind, self.row, self.sub, 5)

    @property
    def complete(self):
        return all(im.complete for im in self.images)

    @property
    def errors(self):
        return tuple(
            (im.index, d)
            for im in self.images if not im.complete
            for d in im.diagnostics
        )

cdef class ImageResult(_View):
    @property
    def requested(self):
        return read(self.owner, self.kind, self.row, self.sub, 1)

    @property
    def os(self):
        return read(self.owner, self.kind, self.row, self.sub, 2)

    @property
    def status(self):
        return read(self.owner, self.kind, self.row, self.sub, 3)

    @property
    def metadata(self):
        return read(self.owner, self.kind, self.row, self.sub, 4)

    @property
    def diagnostics(self):
        return read(self.owner, self.kind, self.row, self.sub, 5)

    @property
    def occurrences(self):
        return read(self.owner, self.kind, self.row, self.sub, 6)

    @property
    def findings(self):
        return read(self.owner, self.kind, self.row, self.sub, 7)

    @property
    def packages(self):
        return read(self.owner, self.kind, self.row, self.sub, 8)

    @property
    def vulnerable_packages(self):
        return read(self.owner, self.kind, self.row, self.sub, 9)

    @property
    def noncompliant_packages(self):
        return read(self.owner, self.kind, self.row, self.sub, 10)

    @property
    def vulnerabilities(self):
        return read(self.owner, self.kind, self.row, self.sub, 11)

    @property
    def complete(self):
        return self.status == "complete"

cdef class Package(_View):
    @property
    def name(self):
        return read(self.owner, self.kind, self.row, self.sub, 1)

    @property
    def version(self):
        return read(self.owner, self.kind, self.row, self.sub, 2)

    @property
    def ecosystem(self):
        return read(self.owner, self.kind, self.row, self.sub, 3)

    @property
    def commit(self):
        return read(self.owner, self.kind, self.row, self.sub, 4)

    @property
    def os_package_name(self):
        return read(self.owner, self.kind, self.row, self.sub, 5)

    @property
    def purl(self):
        return read(self.owner, self.kind, self.row, self.sub, 6)

    @property
    def present_images(self):
        return read(self.owner, self.kind, self.row, self.sub, 7)

    @property
    def vulnerable_images(self):
        return read(self.owner, self.kind, self.row, self.sub, 8)

    @property
    def noncompliant_images(self):
        return read(self.owner, self.kind, self.row, self.sub, 9)

    @property
    def affected_images(self):
        return read(self.owner, self.kind, self.row, self.sub, 10)

    @property
    def findings(self):
        return read(self.owner, self.kind, self.row, self.sub, 11)

cdef class Vulnerability(_View):
    @property
    def id(self):
        return read(self.owner, self.kind, self.row, self.sub, 1)

    @property
    def aliases(self):
        return read(self.owner, self.kind, self.row, self.sub, 2)

    @property
    def affected_images(self):
        return read(self.owner, self.kind, self.row, self.sub, 3)

    @property
    def findings(self):
        return read(self.owner, self.kind, self.row, self.sub, 4)

cdef class AdvisorySource(_View):
    @property
    def id(self):
        return read(self.owner, self.kind, self.row, self.sub, 1)

    @property
    def aliases(self):
        return read(self.owner, self.kind, self.row, self.sub, 2)

    @property
    def summary(self):
        return read(self.owner, self.kind, self.row, self.sub, 3)

    @property
    def modified(self):
        return read(self.owner, self.kind, self.row, self.sub, 4)

    @property
    def published(self):
        return read(self.owner, self.kind, self.row, self.sub, 5)

    @property
    def withdrawn(self):
        return read(self.owner, self.kind, self.row, self.sub, 6)

    @property
    def database_severity(self):
        return read(self.owner, self.kind, self.row, self.sub, 7)

    @property
    def severities(self):
        return read(self.owner, self.kind, self.row, self.sub, 8)

    @property
    def references(self):
        return read(self.owner, self.kind, self.row, self.sub, 9)

    @property
    def affected_images(self):
        return read(self.owner, self.kind, self.row, self.sub, 10)

    @property
    def findings(self):
        return read(self.owner, self.kind, self.row, self.sub, 11)

cdef class Occurrence(_View):
    @property
    def image(self):
        return read(self.owner, self.kind, self.row, self.sub, 1)

    @property
    def package(self):
        return read(self.owner, self.kind, self.row, self.sub, 2)

    @property
    def context(self):
        return read(self.owner, self.kind, self.row, self.sub, 3)

    @property
    def license_assessment(self):
        return read(self.owner, self.kind, self.row, self.sub, 4)

    @property
    def findings(self):
        return read(self.owner, self.kind, self.row, self.sub, 5)

cdef class Finding(_View):
    @property
    def occurrence(self):
        return read(self.owner, self.kind, self.row, self.sub, 1)

    @property
    def advisory_source(self):
        return read(self.owner, self.kind, self.row, self.sub, 2)

    @property
    def fix_evidence(self):
        return read(self.owner, self.kind, self.row, self.sub, 3)

    @property
    def assessment(self):
        return read(self.owner, self.kind, self.row, self.sub, 4)

    @property
    def vulnerability(self):
        return read(self.owner, self.kind, self.row, self.sub, 5)

cdef class ReportContext(_View):
    @property
    def path(self):
        return read(self.owner, self.kind, self.row, self.sub, 1)

    @property
    def source_type(self):
        return read(self.owner, self.kind, self.row, self.sub, 2)

    @property
    def layer(self):
        return read(self.owner, self.kind, self.row, self.sub, 3)

    @property
    def dependency_groups(self):
        return read(self.owner, self.kind, self.row, self.sub, 4)

cdef class ReportAssessment(_View):
    @property
    def called(self):
        return read(self.owner, self.kind, self.row, self.sub, 1)

    @property
    def unimportant(self):
        return read(self.owner, self.kind, self.row, self.sub, 2)

    @property
    def max_severity(self):
        return read(self.owner, self.kind, self.row, self.sub, 3)

cdef class ReportLicense(_View):
    @property
    def licenses(self):
        return read(self.owner, self.kind, self.row, self.sub, 1)

    @property
    def policy(self):
        return read(self.owner, self.kind, self.row, self.sub, 2)

    @property
    def violations(self):
        return read(self.owner, self.kind, self.row, self.sub, 3)

    @property
    def status(self):
        return read(self.owner, self.kind, self.row, self.sub, 4)

cdef class ReportFix(_View):
    @property
    def versions(self):
        return read(self.owner, self.kind, self.row, self.sub, 1)

    @property
    def status(self):
        return read(self.owner, self.kind, self.row, self.sub, 2)

    @property
    def severities(self):
        return read(self.owner, self.kind, self.row, self.sub, 3)

    @property
    def urgencies(self):
        return read(self.owner, self.kind, self.row, self.sub, 4)

cdef class ScanMetadata(_View):
    @property
    def languages(self):
        return read(self.owner, self.kind, self.row, self.sub, 1)

    @property
    def scanner_version(self):
        return read(self.owner, self.kind, self.row, self.sub, 2)

    @property
    def all_packages(self):
        return read(self.owner, self.kind, self.row, self.sub, 3)

    @property
    def image_digest(self):
        return read(self.owner, self.kind, self.row, self.sub, 4)

    @property
    def image_platform(self):
        return read(self.owner, self.kind, self.row, self.sub, 5)

    @property
    def duration_seconds(self):
        return read(self.owner, self.kind, self.row, self.sub, 6)

    @property
    def no_packages(self):
        return read(self.owner, self.kind, self.row, self.sub, 7)

cdef class NativeError(_View):
    @property
    def code(self):
        return read(self.owner, self.kind, self.row, self.sub, 1)

    @property
    def message(self):
        return read(self.owner, self.kind, self.row, self.sub, 2)

cdef class ReportSeverity(_View):
    @property
    def type(self):
        return read(self.owner, self.kind, self.row, self.sub, 1)

    @property
    def source(self):
        return read(self.owner, self.kind, self.row, self.sub, 2)

    @property
    def vector(self):
        return read(self.owner, self.kind, self.row, self.sub, 3)

cdef class ReportReference(_View):
    @property
    def type(self):
        return read(self.owner, self.kind, self.row, self.sub, 1)

    @property
    def url(self):
        return read(self.owner, self.kind, self.row, self.sub, 2)


cdef class CancellationController:
    cdef object lock
    cdef bint was_cancelled
    cdef uintptr_t handle

    def __cinit__(self):
        self.lock = threading.Lock()

    def cancel(self):
        cdef int status = 0
        with self.lock:
            self.was_cancelled = True
            if self.handle:
                with nogil:
                    status = osv_batch_cancel(self.handle)
        check(status)

    cdef bint publish(self, uintptr_t handle):
        with self.lock:
            if self.was_cancelled:
                return False
            self.handle = handle
            return True

    cdef void detach(self):
        with self.lock:
            self.handle = 0

    cdef bint cancelled(self):
        with self.lock:
            return self.was_cancelled


def scan(bytes payload not None, CancellationController controller not None):
    cdef uintptr_t operation = 0
    cdef uintptr_t result = 0
    cdef _Owner owner = _Owner()
    cdef char* data = payload
    cdef size_t size = len(payload)
    cdef int status
    try:
        try:
            if controller.cancelled():
                check(4)
            with nogil:
                status = osv_batch_create(data, size, &operation)
            check(status)
            if not controller.publish(operation):
                check(4)
            with nogil:
                status = osv_batch_start(operation)
            check(status)
            with nogil:
                status = osv_batch_wait(operation)
            check(status)
            with nogil:
                status = osv_batch_finish(operation, &result)
            check(status)
            owner.handle = result
            result = 0
        finally:
            controller.detach()
            # A Python signal can interrupt re-entry after finish returned a handle.
            # Dispose of it unless ownership has already moved to the result owner.
            if result:
                with nogil:
                    status = osv_result_release(result)
                result = 0
            if operation:
                with nogil:
                    status = osv_batch_release(operation)
                check(status)
        if controller.cancelled():
            check(4)
        return view(owner, 1, 0, 0)
    finally:
        # Saved tracebacks must not retain abandoned reports, including on
        # cancellation, cleanup errors, and failed Python view allocation.
        # On success the returned view owns the same _Owner.
        owner = None
