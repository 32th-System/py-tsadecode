#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdint.h>
#include <vector>
#include <stdexcept>

static void
th06_decrypt_impl(uint8_t* buffer, const size_t length, uint8_t key, const size_t start) {
	for(size_t i = start; i < length; i++) {
		buffer[i] -= key;
		key += 7;
	}
}

static void
th_decrypt_impl(std::vector<uint8_t>& buffer, size_t block_size, uint8_t base, uint8_t add) {
	auto tbuf = buffer;
	size_t i, p = 0, tp1, tp2, hf, left = buffer.size();
	if ((left % block_size) < (block_size / 4))
		left -= left % block_size;
	if(left)
		left -= buffer.size() & 1;
	while (left) {
		if (left < block_size)
			block_size = left;
		tp1 = p + block_size - 1;
		tp2 = p + block_size - 2;
		hf = (block_size + (block_size & 0x1)) / 2;
		for (i = 0; i < hf; ++i, ++p) {
			buffer.at(tp1) = tbuf.at(p) ^ base;
			base += add;
			tp1 -= 2;
		}
		hf = block_size / 2;
		for (i = 0; i < hf; ++i, ++p) {
			buffer.at(tp2) = tbuf.at(p) ^ base;
			base += add;
			tp2 -= 2;
		}
		left -= block_size;
	}
}

struct lzss_params_t {
    size_t index_size;
    size_t length_size;
    size_t min_length;
    size_t initial_write_index;
};

lzss_params_t ZUN_LZSS_PARAMS = { 13, 4, 3, 1 };

std::vector<uint8_t>
th_unlzss_impl(const uint8_t* in, size_t len, lzss_params_t& params = ZUN_LZSS_PARAMS) {
    struct bit_iter_t {
        // Huge optimization potential: using `in` ànd performing bit
        // operations on it's bytes directly. This doesn't matter for now
        std::vector<bool> data;
        size_t idx;

        size_t take(size_t n) {
            size_t ret = 0;
            for (size_t i = 0; i < n; i++) {
                if (idx >= data.size())
                    return ret;
                if (data[idx]) {
                    ret |= 1 << (n - i - 1);
                }
                idx++;
            }
            return ret;
        }

        bit_iter_t(const uint8_t* in, size_t len) : idx(0), data() {
            for (size_t i = 0; i < len; i++) {
                data.push_back(in[i] & 0b10000000);
                data.push_back(in[i] & 0b01000000);
                data.push_back(in[i] & 0b00100000);
                data.push_back(in[i] & 0b00010000);
                data.push_back(in[i] & 0b00001000);
                data.push_back(in[i] & 0b00000100);
                data.push_back(in[i] & 0b00000010);
                data.push_back(in[i] & 0b00000001);
            }
        }
    };
    
    bit_iter_t input_bits(in, len);

    std::vector<uint8_t> history(1 << params.index_size);
    size_t history_write_index = params.initial_write_index;

    std::vector<uint8_t> output_bytes;

    auto put_output_byte = [&](uint8_t byte) {
        output_bytes.push_back(byte);
        history[history_write_index] = byte;
        history_write_index += 1;
        history_write_index %= history.size();
    };

    for (;;) {
        bool control_bit = input_bits.take(1);
        if (control_bit) {
            uint8_t data_byte = static_cast<uint8_t>(input_bits.take(8));
            put_output_byte(data_byte);
        } else {
            size_t read_from = input_bits.take(params.index_size);
            if (!read_from)
                break;
            size_t read_count = input_bits.take(params.length_size) + params.min_length;

            for (size_t i = 0; i < read_count; i++) {
                put_output_byte(history[read_from]);
                read_from += 1;
                read_from %= history.size();
            }
        }
    }

    if(input_bits.data.size() != input_bits.idx) {
		throw std::runtime_error("The provided LZSS data is invalid or the LZSS parameters are wrong");
	}

    return output_bytes;
}

char* kwlist[] = {strdup("buf"), strdup("key"), strdup("start"), nullptr};

static PyObject*
th06_decrypt(PyObject* self, PyObject* args, PyObject* kwargs) {
	Py_buffer buf;
	Py_ssize_t key;
	Py_ssize_t start = 0;

	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "y*n|n", kwlist, &buf, &key, &start) || buf.readonly)
		return NULL;

	th06_decrypt_impl(static_cast<uint8_t*>(buf.buf), buf.len, static_cast<uint8_t>(key), start);
	Py_RETURN_NONE;
}

static PyObject*
th_decrypt(PyObject* self, PyObject* args) {
	try {
		Py_buffer buf;
		Py_ssize_t block_size, base, add;
		if(!PyArg_ParseTuple(args, "y*nnn", &buf, &block_size, &base, &add) || buf.readonly)
			return NULL;

		std::vector<uint8_t> _buf((uint8_t*)buf.buf, (uint8_t*)buf.buf + buf.len);
		try {
			th_decrypt_impl(_buf, block_size, static_cast<uint8_t>(base), static_cast<uint8_t>(add));
		} catch(std::out_of_range& e) {
			PyErr_SetString(PyExc_IndexError, e.what());
			return NULL;
		}
		assert(buf.len == _buf.size());
		memcpy(buf.buf, _buf.data(), buf.len);
		Py_RETURN_NONE;
	} catch(std::bad_alloc& e) {
		PyErr_SetString(PyExc_MemoryError, e.what());
		return NULL;
	}
}

static PyObject *
th_unlzss(PyObject* self, PyObject* args) {
	try {
		Py_buffer data;

		if(!PyArg_ParseTuple(args, "y*", &data)) 
			return NULL;

		try {
			auto ret = th_unlzss_impl(static_cast<uint8_t*>(data.buf), data.len);
			return Py_BuildValue("y#", ret.data(), ret.size());
		} catch(std::runtime_error& e) {
			PyErr_SetString(PyExc_ValueError, e.what());
			return NULL;
		}

	} catch(std::bad_alloc& e) {
		PyErr_SetString(PyExc_MemoryError, e.what());
		return NULL;
	}	
}

static PyMethodDef thReplayMethods[] = {
	{ "decrypt06", (PyCFunction)th06_decrypt, METH_VARARGS | METH_KEYWORDS,
	"Perform a decryption using the encryption algorithm from TH06" },
	{ "decrypt", th_decrypt, METH_VARARGS,
	"Perform a decryption using ZUN's newer encryption algorithm introduced in TH08"},
	{ "unlzss", th_unlzss, METH_VARARGS,
	"Perform a decompression using the Lempel-Ziv-Storer-Szymanski algorithm (LZSS) with ZUN's LZSS parameters"},
	{}
};

static struct PyModuleDef thReplayModule = {
	PyModuleDef_HEAD_INIT,
	"tsadecode",
	NULL,
	-1,
	thReplayMethods
};

void free_kwlist() {
	for(size_t i = 0; kwlist[i]; i++) free(kwlist[i]);
}

PyMODINIT_FUNC
PyInit_tsadecode() {
	return PyModule_Create(&thReplayModule);
}
