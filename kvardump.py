#!/usr/bin/env python
from __future__ import print_function
from datetime import datetime
import os
import re
import sys
import time
import copy
import pickle
import codecs
import subprocess
import argparse
import platform
import struct
import functools
import traceback

DEFAULT_ARRAY_MAX = 5
DEFAULT_STRING_MAX = 64

verbose = False
log_nest_level = 0

try:
    from six import reraise
except ImportError:
    if sys.version_info[0] >= 3:
        def reraise(exc_type, exc_value, exc_traceback):
            raise exc_value.with_traceback(exc_traceback)
    else:
        exec("def reraise(exc_type, exc_value, exc_traceback):\n"
            "    raise exc_type, exc_value, exc_traceback\n")

def get_err_txt(err):
    return getattr(err, "show_txt", str(err))


def append_err_txt(err, txt_before='', txt_after=''):
    err.show_txt = "%s%s%s" % (txt_before, get_err_txt(err), txt_after)


def log_exception():
    if not verbose:
        return
    exc_type, exc_value, exc_traceback = sys.exc_info()
    print("Error: %s" % get_err_txt(exc_value), file=sys.stderr)
    traceback.print_exception(exc_type, exc_value, exc_traceback,
                              file=sys.stderr)


def pretty(value, htchar='\t', lfchar='\n', max_depth=0, indent=0):
    nlch = lfchar + htchar * (indent + 1)
    if isinstance(value, dict):
        if max_depth and indent >= max_depth:
            return '{...}'
        items = [
            nlch + str(key) + ': ' + pretty(
                value[key], htchar, lfchar, max_depth, indent + 1)
            for key in value
        ]
        return '{%s}' % (','.join(items) + lfchar + htchar * indent)
    elif isinstance(value, list):
        if max_depth and indent >= max_depth:
            return '[...]'
        items = [
            nlch + pretty(item, htchar, lfchar, max_depth, indent + 1)
            for item in value
        ]
        return '[%s]' % (','.join(items) + lfchar + htchar * indent)
    elif isinstance(value, tuple):
        if max_depth and indent >= max_depth:
            return '(...)'
        items = [
            nlch + pretty(item, htchar, lfchar, max_depth, indent + 1)
            for item in value
        ]
        return '(%s)' % (','.join(items) + lfchar + htchar * indent)
    else:
        return str(value)


def log_arg_ret(func):
    def show(var):
        return pretty(var, htchar='', lfchar=' ', max_depth=2)

    @functools.wraps(func)
    def _func(*args, **kwargs):
        global log_nest_level
        ret = 'Error'
        log_nest_level += 1

        try:
            ret = func(*args, **kwargs)
        finally:
            log_nest_level -= 1
            if verbose:
                args = args[1:]
                arg_str1 = ', '.join([show(i) for i in args])
                arg_str2 = ', '.join([show(k) + '=' + show(v)
                                      for k, v in kwargs.items()])
                if arg_str1 and arg_str2:
                    arg_str = arg_str1 + ', ' + arg_str2
                else:
                    arg_str = arg_str1 + arg_str2
                print("call[%d]: %s(%s) = '%s'" %
                      (log_nest_level, func.__name__, arg_str, show(ret)),
                      file=sys.stderr)
        return ret

    return _func


def cache_result(func):
    @functools.wraps(func)
    def _func(self, *args, **kwargs):
        param_tuple = (tuple(args), frozenset(kwargs))
        cache_name = '_%s_cache' % func.__name__
        cache_dict = getattr(self, cache_name, {})
        if not cache_dict:
            setattr(self, cache_name, cache_dict)

        cache_value = copy.deepcopy(cache_dict.get(param_tuple, None))
        if isinstance(cache_value, Exception):
            raise cache_value

        if cache_value is not None:
            return cache_value

        try:
            cache_value = func(self, *args, **kwargs)
        except Exception as e:
            cache_dict[param_tuple] = copy.deepcopy(e)
            reraise(*sys.exc_info())
        else:
            cache_dict[param_tuple] = copy.deepcopy(cache_value)
        return cache_value

    return _func


class BTF(object):
    KIND_INT = 1
    KIND_PTR = 2
    KIND_ARRAY = 3
    KIND_STRUCT = 4
    KIND_UNION = 5
    KIND_ENUM = 6
    KIND_FWD = 7
    KIND_TYPEDEF = 8
    KIND_VOLATILE = 9
    KIND_CONST = 10
    KIND_RESTRICT = 11
    KIND_FUNC = 12
    KIND_FUNC_PROTO = 13
    KIND_VAR = 14
    KIND_DATASEC = 15

    def __init__(self, path, cache_path='/tmp/kvardump.cache', mem_reader=None,
                 array_max=DEFAULT_ARRAY_MAX, string_max=DEFAULT_STRING_MAX,
                 array_max_force=False, string_max_force=False,
                 hex_string=False, blank='    '):
        self.arch_size = 8
        if platform.architecture()[0] == '32bit':
            self.arch_size = 4

        # if os.path.exists('/tmp/kvardump_cache.json'):
        #     with open('/tmp/kvardump_cache.json', 'r') as f:
        #         obj = json.load(f)
        #         self.types = obj['types']
        #         self.name_map = obj['name_map']
        #     return

        self.mem_reader = mem_reader
        self.array_max = array_max
        self.string_max = string_max
        self.array_max_force = array_max_force
        self.string_max_force = string_max_force
        self.hex_string = hex_string
        self.blank = blank

        # if cache_path and os.path.exists(cache_path):
        #     print("loading types from cache '%s'" % cache_path, file=sys.stderr)
        #     with open(cache_path, 'rb') as f:
        #         obj = pickle.load(f)
        #         self.types = obj.types
        #         self.name_map = obj.name_map
        #         return

        #         obj = json.load(f)
        #         self.types = obj['types']
        #         self.name_map = obj['name_map']

        # type ID start from 1
        self.types = [{}]
        self.name_map = {}

        print("parsing types from cache '%s'" % path, file=sys.stderr)
        self.parse(path)

        # if cache_path:
        #     print("writing types to cache '%s'" % cache_path, file=sys.stderr)
        #     with open('/tmp/kvardump_cache.json', 'w') as f:
        #         pickle.dump(self, f)

    def parse(self, path):
        with open(path, 'rb') as f:
            self.data = f.read()

        header = struct.unpack('HBBIIIII', self.data[0:24])
        self.magic = header[0]
        self.version = header[1]
        self.flags = header[2]
        self.hdr_len = header[3]
        self.type_off = header[4]
        self.type_len = header[5]
        self.str_off = header[6]
        self.str_len = header[7]
        self.data = self.data[self.hdr_len:]
        self.pos = 0

        if (self.type_off + self.type_len > len(self.data)):
            raise Exception("invalid BTF, may be truncated")

        if (self.str_off + self.str_len > len(self.data)):
            raise Exception("invalid BTF, may be truncated")

        if self.magic != 0xeb9f:
            raise Exception("invalid BTF file, wrong magic: 0x%x" % self.magic)

        self.str_data = self.data[self.str_off : self.str_off + self.str_len]
        self.type_data = self.data[self.type_off : self.type_off + self.type_len]

        type_map = {
            BTF.KIND_INT: Int,
            BTF.KIND_PTR: Ptr,
            BTF.KIND_ARRAY: Array,
            BTF.KIND_STRUCT: Struct,
            BTF.KIND_UNION: Union,
            BTF.KIND_ENUM: Enum,
            BTF.KIND_FWD: Fwd,
            BTF.KIND_TYPEDEF: TypeDef,
            BTF.KIND_VOLATILE: Volatile,
            BTF.KIND_CONST: Const,
            BTF.KIND_RESTRICT: Restrict,
            BTF.KIND_FUNC: Func,
            BTF.KIND_FUNC_PROTO: FuncProto,
            BTF.KIND_VAR: Var,
            BTF.KIND_DATASEC: DataSec,
        }

        while self.pos < len(self.type_data):
            data = self.eat(12)
            btf_type = struct.unpack("III", data)
            name_off = btf_type[0]
            info = btf_type[1]
            size = type = btf_type[2]
            vlen = info & 0xffff
            kind = (info >> 24) & 0xf
            kind_flag = info >> 31
            name = self.get_name(name_off)

            cls = type_map[kind]
            obj = cls.from_btf(self, name, size, type, vlen, kind_flag)

            #self.name_map['%d.%s' % (kind, name)] = len(self.types)
            self.name_map[(kind, name)] = len(self.types)
            self.types.append(obj)

        ###############
        # pos = 0
        # while pos + self.TYPE_LEN < len(self.type_data):
        #     btf_type = struct.unpack(
        #         "III", self.type_data[pos:pos+self.TYPE_LEN])
        #     pos += self.TYPE_LEN

        #     name_off = btf_type[0]
        #     info = btf_type[1]
        #     size = type = btf_type[2]
        #     vlen = info & 0xffff
        #     kind = (info >> 24) & 0xf
        #     kind_flag = info >> 31
        #     name = self.get_name(name_off)
        #     decoded = {"name": name, "kind": kind}

        #     if kind == self.KIND_INT:
        #         if pos + 4 >= len(self.type_data):
        #             raise Exception(
        #                 "invalid BTF, 0x%x reaches the end of type data" % pos)

        #         info = struct.unpack("I", self.type_data[pos:pos+4])[0]
        #         pos += 4

        #         decoded.update({
        #             'kind': kind,
        #             'size': size,
        #             'signed': (info & 0x01000000) != 0,
        #             'char': (info & 0x02000000) != 0,
        #             'bool': (info & 0x04000000) != 0,
        #             'offset': (info >> 16) & 0xff,
        #             'bits': info >> 16,
        #         })
        #     elif kind in {
        #         self.KIND_PTR,
        #         self.KIND_TYPEDEF,
        #         self.KIND_VOLATILE,
        #         self.KIND_CONST,
        #         self.KIND_RESTRICT,
        #         }:
        #         decoded.update({
        #             'kind': kind,
        #             'type': type,
        #         })
        #     elif kind == self.KIND_ARRAY:
        #         if pos + self.ARRAY_LEN >= len(self.type_data):
        #             raise Exception(
        #                 "invalid BTF, 0x%x reaches the end of type data" % pos)

        #         info = struct.unpack(
        #             "III", self.type_data[pos:pos+self.ARRAY_LEN])
        #         pos += self.ARRAY_LEN
        #         decoded.update({
        #             'kind': kind,
        #             'type': info[0],
        #             'nelems': info[2],
        #         })
        #     elif kind == self.KIND_STRUCT or kind == self.KIND_UNION:
        #         if pos + vlen * self.MEMBER_LEN >= len(self.type_data):
        #             raise Exception(
        #                 "invalid BTF, 0x%x reaches the end of type data" % pos)

        #         decoded.update({
        #             'kind': kind,
        #             'vlen': vlen,
        #             'size': size,
        #             'members': [],
        #         })

        #         for i in range(vlen):
        #             info = struct.unpack(
        #                 "III", self.type_data[pos:pos+self.MEMBER_LEN])
        #             pos += self.MEMBER_LEN
        #             decoded['members'].append({
        #                 'name': self.get_name(info[0]),
        #                 'type': info[1],
        #                 'offset': info[2] & 0xffffff,
        #                 'size': info[2] >> 24,
        #             })
        #     elif kind == self.KIND_ENUM:
        #         if pos + vlen * self.ENUM_LEN >= len(self.type_data):
        #             raise Exception(
        #                 "invalid BTF, 0x%x reaches the end of type data" % pos)

        #         decoded.update({
        #             'kind': kind,
        #             'vlen': vlen,
        #             'size': size,
        #             'members': [],
        #         })

        #         for i in range(vlen):
        #             info = struct.unpack(
        #                 "Ii", self.type_data[pos:pos+self.ENUM_LEN])
        #             pos += self.ENUM_LEN
        #             decoded['members'].append({
        #                 'name': self.get_name(info[0]),
        #                 'val': info[1],
        #             })
        #     elif kind == self.KIND_FWD:
        #         decoded.update({
        #             'kind': self.KIND_UNION \
        #                 if kind_flag else self.KIND_STRUCT,
        #             'vlen': 0,
        #             'size': 0,
        #             'members': [],
        #         })
        #     elif kind == self.KIND_FUNC_PROTO:
        #         if pos + vlen * self.ARG_LEN >= len(self.type_data):
        #             raise Exception(
        #                 "invalid BTF, 0x%x reaches the end of type data" % pos)

        #         decoded.update({
        #             'kind': kind,
        #             'vlen': vlen,
        #             'type': type,
        #             'args': [],
        #         })

        #         pos += self.ARG_LEN * vlen
        #         # for i in range(vlen):
        #         #     info = struct.unpack(
        #         #         "II", self.type_data[pos:pos+self.ARG_LEN])
        #         #     pos += self.ARG_LEN
        #         #     decoded['args'].append({
        #         #         'name': self.get_name(info[0]),
        #         #         'type': info[1],
        #         #     })
        #     elif kind == self.KIND_FUNC:
        #         pass
        #     elif kind == self.KIND_VAR:
        #         pos += 4
        #         # import pdb
        #         # pdb.set_trace()
        #     elif kind == self.KIND_DATASEC:
        #         pos += 12 * vlen

    def get_name(self, offset):
        if offset >= len(self.str_data):
            raise Exception("invalid BTF file, invalid name offset: 0x%x" % offset)

        end = self.str_data[offset:].find(b'\x00')
        if end < 0:
            raise Exception("invalid BTF file, invalid string at 0x%x" % offset)

        return self.str_data[offset : offset + end].decode('ascii')

    # @log_arg_ret
    def assemble_type(self, type_info):
        if type_info.get('kind', None) == self.KIND_PTR:
            return type_info

        if 'type' in type_info and 'type_obj' not in type_info:
            type = type_info.pop('type')
            type_info['type_obj'] = \
                self.assemble_type(self.types[type])
            type_info['type'] = type

        members = type_info.get('members', [])
        for m in members:
            self.assemble_type(m)

        return type_info

    def get_type(self, kind, name):
        type_id = self.name_map[(kind, name)]
        return self.types[type_id]
        # type_id = self.name_map['%d.%s' % (kind, name)]
        # type_info = self.types[type_id]
        # return self.assemble_type(type_info)

    def dereference_type(self, type_info):
        if 'type_obj' not in type_info:
            ref_type_id = type_info['type']
            ref_type_info = self.types[ref_type_id]
            type_info['type_obj'] = self.assemble_type(ref_type_info)

        return type_info['type_obj']

    # @log_arg_ret
    # def get_type_size(self, type_info):
    #     if type_info['kind'] in {self.KIND_PTR, self.KIND_FUNC_PROTO}:
    #         return self.arch_size
    #     elif type_info['kind'] == self.KIND_ARRAY:
    #         return type_info['nelems'] * self.get_type_size(type_info['type_obj'])
    #     elif type_info['kind'] in {
    #         self.KIND_INT,
    #         self.KIND_STRUCT,
    #         self.KIND_UNION,
    #         self.KIND_ENUM,
    #         }:
    #         return type_info['size']
    #     elif type_info['kind'] in {
    #         self.KIND_TYPEDEF,
    #         self.KIND_VOLATILE,
    #         self.KIND_CONST,
    #         self.KIND_RESTRICT
    #         }:
    #         return self.get_type_size(type_info['type_obj'])
    #     else:
    #         return 0

    # def get_type_str(self, type_info):
    #     self.assemble_type(type_info)

    #     if type_info['kind'] == self.KIND_PTR:
    #         return "%s *" % self.get_type_str(self.types[type_info['type']])
    #     elif type_info['kind'] == self.KIND_STRUCT:
    #         return "struct %s" % type_info['name']
    #     elif type_info['kind'] == self.KIND_UNION:
    #         return "union %s" % type_info['name']
    #     elif type_info['kind'] == self.KIND_ENUM:
    #         return "enum %s" % type_info['name']
    #     elif type_info['kind'] == self.KIND_VOLATILE:
    #         return "volatile %s" % self.get_type_str(type_info['type_obj'])
    #     elif type_info['kind'] == self.KIND_CONST:
    #         return "const %s" % self.get_type_str(type_info['type_obj'])
    #     elif type_info['kind'] == self.KIND_RESTRICT:
    #         return "restrict %s" % self.get_type_str(type_info['type_obj'])
    #     elif type_info['kind'] == self.KIND_FUNC_PROTO:
    #         return "void *"
    #     elif type_info['kind'] == self.KIND_ARRAY:
    #         # TODO priority
    #         return "%s[%d]" % (self.get_type_str(type_info['type_obj']), type_info['nelems'])
    #     elif 'name' in type_info:
    #         return type_info['name']
    #     else:
    #         raise Exception("unsupported type: %s" % type_info)

    def eat(self, size):
        if self.pos + size > len(self.type_data):
             raise Exception(
                "invalid BTF, 0x%x reaches the end of data" % (self.pos + size))
        data = self.type_data[self.pos : self.pos + size]
        self.pos += size
        return data

class BaseValue(object):
    def __init__(self, type, data=None, addr=None):
        if not data and not addr:
            raise Exception("both data add addr are not specified")

        self.type = type
        self.btf = type.btf
        self._data = data
        self.addr = addr

    def __str__(self):
        return self.to_str()

    @property
    def data(self):
        if self._data:
            return self._data
        try:
            self._data = self.btf.mem_reader.read(self.addr, self.type.size)
        except AttributeError:
            msg = "read data 0x%x~0x%x failed: %s" % (
                self.addr, self.addr + self.type.size, str(sys.exc_info()[1]))
            reraise(Exception, msg, sys.exc_info()[2])
        return self._data

    def to_str(self, indent=0):
        import pdb
        pdb.set_trace()
        raise NotImplementedError()

    def cast(self, type):
        if not self.addr:
            raise Exception("address of '%s' has not been set" % repr(self))
        return type(addr=self.addr)

class BTFType(object):
    @classmethod
    def from_btf(cls, btf, name, size, type, vlen, kind_flag):
        raise NotImplementedError()

    def __str__(self):
        if not self.name:
            return "%s-%s" % (self.__class__.__name__, id(self))

        return self.name

    def __call__(self, data=None, addr=None):
        if isinstance(data, BaseValue):
            return self.Value(self, addr=data.addr)

        return self.Value(self, data, addr)

    @property
    def ref(self):
        if not hasattr(self, 'type'):
            raise NotImplementedError()
        
        if isinstance(self.type, int):
            if self.type >= len(self.btf.types) or self.type <= 0:
                raise Exception("invalid btf type %d" % self.type)
            self.type = self.btf.types[self.type]

        return self.type

    def is_kind(self, kind):
        return self.KIND == kind

class Int(BTFType):
    KIND = BTF.KIND_INT

    def __init__(self, btf, name, size, signed=False, char=False,
                 bool=False, offset=0, bits=0):
        self.btf = btf
        self.name = name
        self.size = size
        self.signed = signed
        self.char = char
        self.bool = bool
        self.offset = offset
        self.bits = bits

    @classmethod
    def from_btf(cls, btf, name, size, type, vlen, kind_flag):
        data = btf.eat(4)
        info = struct.unpack("I", data)[0]
        return cls(btf, name, size,
                    signed=(info & 0x01000000) != 0,
                    char=(info & 0x02000000) != 0,
                    bool=(info & 0x04000000) != 0,
                    offset=(info >> 16) & 0xff,
                    bits=(info & 0xff))

    class Value(BaseValue):
        def __int__(self):
            if self.type.size == 1:
                if self.type.signed:
                    val = struct.unpack('b', self.data)[0]
                else:
                    val = struct.unpack('B', self.data)[0]
            elif self.type.size == 2:
                if self.type.signed:
                    val = struct.unpack('h', self.data)[0]
                else:
                    val = struct.unpack('H', self.data)[0]
            elif self.type.size == 4:
                if self.type.signed:
                    val = struct.unpack('i', self.data)[0]
                else:
                    val = struct.unpack('I', self.data)[0]
            elif self.type.size == 8:
                if self.type.signed:
                    val = struct.unpack('l', self.data)[0]
                else:
                    val = struct.unpack('L', self.data)[0]
            else:
                raise Exception("invalid int size: %s", self.type.size)

            # TODO bitfield
            return val

        def to_str(self, indent=0):
            if self.type.bool:
                return str(bool(int(self)))
            return str(int(self))

class Ref(BTFType):
    def __init__(self, btf, name, type):
        self.btf = btf
        self.name = name
        self.type = type

    @classmethod
    def from_btf(cls, btf, name, size, type, vlen, kind_flag):
        return cls(btf, name, type)

class Ptr(Ref):
    KIND = BTF.KIND_PTR

    def __str__(self):
        return "%s *" % str(self.ref)

    @property
    def size(self):
        return self.btf.arch_size

    class Value(BaseValue):
        def __int__(self):
            # try:
            return struct.unpack('P', self.data)[0]
            # except:
            #     import pdb
            #     pdb.set_trace()

        def to_str(self, indent):
            return '0x%x' % int(self)

        def __getitem__(self, idx):
            addr = int(self) + idx * self.type.ref.size
            return self.type.ref(addr=addr)

        def __getattr__(self, name):
            return getattr(self.eval(), name)

        # @property
        # def addr(self):
        #     return struct.unpack('P', self.data)[0]

        @property
        def eval(self):
            # data = self.btf.mem_reader.read(self.addr, self.type.ref.size)
            try:
                return self.type.ref(addr=int(self))
            except AttributeError:
                msg = "dereference value failed: %s" % (
                    str(sys.exc_info()[1]))
                reraise(Exception, msg, sys.exc_info()[2])

class Bedeck(Ref):
    def __setstate__(self, d):
        self.__dict__ = d

    def __getstate__(self):
        return self.__dict__

    def __getattr__(self, name):
        return getattr(self.ref, name)
        # return self.ref.get(name)

    def __getitem__(self, idx):
        return self.ref[idx]

    def __len__(self):
        return len(self.ref)

    def is_kind(self, kind):
        if self.KIND == kind:
            return True
        return self.ref.is_kind(kind)

    # def __iter__(self):
    #     return iter(self.ref)

    # def get(self, member):
    #     return self.ref.get(member)

    # @property
    # def size(self):
    #     return self.ref.size

    class Value(BaseValue):
        @property
        def ref(self):
            try:
                return self.type.ref(data=self.data, addr=self.addr)
            except AttributeError:
                msg = "ref failed: %s" % (str(sys.exc_info()[1]))
                reraise(Exception, msg, sys.exc_info()[2])

        def __getattr__(self, name):
            return getattr(self.ref, name)

        # @property
        # def addr(self):
        #     return self.ref.addr

        # @property
        # def eval(self):
        #     return self.ref.eval

        def __int__(self):
            return int(self.ref)

        def __str__(self):
            return str(self.ref)

        def __getitem__(self, idx):
            return self.ref[idx]
        # def __iter__(self):
        #     return iter(self.ref)

        def __len__(self):
            return len(self.ref)

        def to_str(self, indent=0):
            return self.ref.to_str(indent)

class TypeDef(Bedeck):
    KIND = BTF.KIND_TYPEDEF

class Volatile(Bedeck):
    KIND = BTF.KIND_VOLATILE

    def __str__(self):
        return "volatile %s" % str(self.ref)

class Const(Bedeck):
    KIND = BTF.KIND_CONST

    def __str__(self):
        return "const %s" % str(self.ref)

class Restrict(Bedeck):
    KIND = BTF.KIND_RESTRICT

    def __str__(self):
        return "restrict %s" % str(self.ref)

class Array(BTFType):
    KIND = BTF.KIND_ARRAY
    def __init__(self, btf, name, type, nelems):
        self.btf = btf
        self.name = name
        self.type = type
        self.nelems = nelems

    def __str__(self):
        return "%s[%d]" % (str(self.ref), self.nelems)

    @classmethod
    def from_btf(cls, btf, name, size, type, vlen, kind_flag):
        data = btf.eat(12)
        info = struct.unpack("III", data)
        return cls(btf, name, info[0], info[2])

    @property
    def size(self):
        try:
            return self.nelems * self.ref.size
        except AttributeError:
            msg = "get size failed: %s" % (str(sys.exc_info()[1]))
            reraise(Exception, msg, sys.exc_info()[2])

    class Value(BaseValue):
        def __len__(self):
            return self.type.nelems

        def __getitem__(self, idx):
            elem_size = self.type.ref.size
            addr = self.addr + idx * elem_size if self.addr else None
            data = self.data[idx * elem_size : (idx + 1) * elem_size]
            return self.type.ref(data=data, addr=addr)

        # def __iter__(self):
        #     elem_size = self.type.ref.size
        #     for i in range(self.type.nelems):
        #         addr = None
        #         data = self.data[i * elem_size : (i + 1) * elem_size]
        #         if self.addr:
        #             addr = self.addr + i * elem_size
        #         yield self.type.ref(data=data, addr=addr)

        def dump_byte_array(self, indent):
            omit_tip = ''
            if (indent > 0 or self.btf.string_max_force) and \
                    self.type.nelems > self.btf.string_max:
                data = self.data[:self.btf.string_max]
                omit_tip = '...'

            if not self.btf.hex_string:
                try:
                    # dump as string if there is no unprintable character
                    str_val = self.data.decode('ascii')
                    end = str_val.find('\x00')
                    if end >= 0:
                        str_val = str_val[:end]
                    if not re.search(r'[^\t-\r\x20-\x7e]', str_val):
                        return '"%s"' % (str_val + (omit_tip if end < 0 else ''))
                except Exception:
                    pass

            # dump as hex
            return '"<binary>" /* hex: %s */' % \
                (codecs.encode(data, 'hex').decode() + omit_tip)

        def to_str(self, indent):
            elem_type = self.type.ref
            elem_size = elem_type.size
            array_len = self.type.nelems
            omit_count = 0
            # if elem_size == 1:
            if elem_type.is_kind(BTF.KIND_INT) and elem_size == 1:
            # if element_type['kind'] == self.btf.KIND_INT and \
            #         element_type['size'] == 1:
                return self.dump_byte_array(indent)

            # dump array in each line
            if (indent > 0 or self.btf.array_max_force) and \
                    array_len > self.btf.array_max:
                omit_count = array_len - self.btf.array_max
                array_len = self.btf.array_max

            indent += 1
            if elem_type.is_kind(BTF.KIND_INT):
                txt = '{'
                sep = ' '
                before = ''
            else:
                txt = '{\n'
                sep = '\n'
                before = indent * self.btf.blank

            for i in range(array_len):
                txt += before + self[i].to_str(indent) + ',' + sep
                # self.dump_type(
                #     data[elem_size * i: elem_size * i + elem_size],
                #     element_type, indent) + ',' + sep

            if omit_count:
                txt += before + '/* other %s elements are omitted */%s' % (
                                omit_count, sep)
            indent -= 1
            if sep == '\n':
                txt += indent * self.btf.blank + '}'
            else:
                txt += '}'
            return txt

class StructUnion(BTFType):
    class Member(BTFType):
        def __init__(self, parent, btf, name, type, offset, size):
            self.parent = parent
            self.btf = btf
            self.name = name
            self.type = type
            self.offset_bits = offset
            self.offset = offset / 8
            self.size = size

    def __init__(self, btf, name, vlen, size):
        self.btf = btf
        self.name = name
        self.vlen = vlen
        self.size = size
        self.members = []
        self.member_map = {}
        self.anonymous_members = []

    def __len__(self):
        return len(self.members)

    def __getitem__(self, idx):
        return self.members[idx]
    # def __iter__(self):
    #     return iter(self.members)

    def __setstate__(self, d):
        self.__dict__ = d

    def __getstate__(self):
        return self.__dict__

    def __getattr__(self, name):
        # print("%s get %s" % (repr(self), name))
        return self.get(name)

    def get(self, member):
        member = str(member)
        ret = self.member_map.get(member, None)
        if ret:
            return ret

        for m in self.anonymous_members:
            if isinstance(m.ref, StructUnion):
                try:
                    return m.ref.get(member)
                except KeyError:
                    pass

        # import pdb
        # pdb.set_trace()
        raise KeyError("'%s' has no member '%s'" % (str(self), member))

    def add_member(self, name, type, offset, size):
        self.members.append(
            self.Member(self, self.btf, name, type, offset, size))
        if not name:
            self.anonymous_members.append(self.members[-1])
        else:
            self.member_map[name] = self.members[-1]

    @classmethod
    def from_btf(cls, btf, name, size, type, vlen, kind_flag):
        obj = cls(btf, name, vlen, size)
        for _ in range(vlen):
            data = btf.eat(12)
            info = struct.unpack("III", data)
            obj.add_member(
                btf.get_name(info[0]), info[1], info[2] & 0xffffff, info[2] >> 24)
        return obj

    class Value(BaseValue):
        def __len__(self):
            return len(self.type.members)

        def __getitem__(self, idx):
            # TODO offset_bits
            member = self.type.members[idx]
            return self._get(member)

        def __getattr__(self, name):
            print("call __getattr__")
            return self.get(name)

        def _get(self, member):
            addr = self.addr + member.offset if self.addr else None
            # TODO member.ref.size or member.size ?
            try:    
                data = self.data[member.offset : member.offset + member.ref.size]
            except Exception:
                import pdb
                pdb.set_trace()
            return member.ref(data=data, addr=addr)

        def get(self, name):
            member = self.type.get(name)
            return self._get(member)

        def to_str(self, indent=0):
            txt = '{\n'
            indent += 1
            for m in self.type.members:
                # m_name = m['name']
                # m_off, m_type = self.get_member_offset_and_type(type_info, m_name)
                # m_size = self.btf.get_type_size(m_type)
                if m.name:
                    txt += indent * self.btf.blank + '.' + m.name + ' = '
                elif m.ref.is_kind(BTF.KIND_STRUCT):
                    txt += indent * self.btf.blank  + '/* nested anonymous struct */ '
                else:
                    txt += indent * self.btf.blank  + '/* nested anonymous union */ '
                txt += self._get(m).to_str(indent)
                # self.dump_type(data[m_off: m_off + m_size], m_type, indent)
                txt += ',\n'

            indent -= 1
            txt += indent * self.btf.blank  + '}'
            return txt

        # def __iter__(self):
        #     elem_size = self.type.ref.size
        #     for i in self.type.nelems:
        #         data = data[i * elem_size : (i + 1) * elem_size]
        #         yield self.type.ref(data)

class Struct(StructUnion):
    KIND = BTF.KIND_STRUCT

    def __str__(self):
        return "struct %s" % str(self.name)

class Union(StructUnion):
    KIND = BTF.KIND_UNION

    def __str__(self):
        return "union %s" % str(self.name)

class Enum(Int):
    KIND = BTF.KIND_ENUM
    class Member(BTFType):
        def __init__(self, parent, btf, name, val):
            self.parent = parent
            self.btf = btf
            self.name = name
            self.val = val

    def __init__(self, btf, name, vlen, size):
        self.vlen = vlen
        self.members = []
        self.member_map = {}
        self.value_map = {}
        super(self.__class__, self).__init__(btf, name, size)

    def __str__(self):
        return "enum %s" % str(self.name)

    def add_member(self, name, val):
        self.members.append(self.Member(self, self.btf, name, val))
        self.member_map[name] = self.members[-1]
        self.value_map[val] = self.members[-1]

    @classmethod
    def from_btf(cls, btf, name, size, type, vlen, kind_flag):
        obj = cls(btf, name, vlen, size)
        for _ in range(vlen):
            data = btf.eat(8)
            info = struct.unpack("Ii", data)
            obj.add_member(btf.get_name(info[0]), info[1])
        return obj

    class Value(Int.Value):
        def __int__(self):
            if isinstance(self.data, Int):
                return self.data
            return super(self.__class__, self).__int__()

        def to_str(self, indent=0):
            val = int(self)
            if val in self.type.value_map:
                return self.type.value_map[val].name

            return super().to_str(indent)

class Fwd(BTFType):
    KIND = BTF.KIND_FWD
    def __init__(self, btf, name, kind_flag):
        self.btf = btf
        self.name = name
        self.kind_flag = kind_flag

    def __str__(self):
        if self.kind_flag:
            return "union %s" % self.name
        else:
            return "struct %s" % self.name

    @classmethod
    def from_btf(cls, btf, name, size, type, vlen, kind_flag):
        return cls(btf, name, kind_flag)

class FuncProto(BTFType):
    KIND = BTF.KIND_FUNC_PROTO
    def __init__(self, btf, name, vlen, type):
        self.btf = btf
        self.name = name
        self.vlen = vlen
        self.type = type

    def __str__(self):
        return "%s (*%s)(...)" % str(self.ref, self.name)

    @classmethod
    def from_btf(cls, btf, name, size, type, vlen, kind_flag):
        btf.eat(vlen * 8)
        return cls(btf, name, vlen, type)

    @property
    def size(self):
        return self.btf.arch_size

    class Value(BaseValue):
        def __int__(self):
            return struct.unpack('P', self.data)[0]

        def to_str(self, indent):
            return '0x%x' % int(self)

class Func(Ref):
    KIND = BTF.KIND_FUNC

class Var(BTFType):
    KIND = BTF.KIND_VAR

    def __init__(self, btf, name, type):
        self.btf = btf
        self.name = name
        self.type = type

    @classmethod
    def from_btf(cls, btf, name, size, type, vlen, kind_flag):
        btf.eat(4)
        return cls(btf, name, type)

class DataSec(BTFType):
    KIND = BTF.KIND_DATASEC

    def __init__(self, btf, name, vlen, size):
        self.btf = btf
        self.vlen = vlen
        self.size = size

    @classmethod
    def from_btf(cls, btf, name, size, type, vlen, kind_flag):
        btf.eat(12 * vlen)
        return cls(btf, name, vlen, size)

def get_symbol_addr(name):
    output = subprocess.check_output(
        "cat /proc/kallsyms | grep -w %s | awk '{print $1}'" % name,
        shell=True).decode()
    return int('0x' + output, base=0)

class KernelMem(object):
    def __init__(self):
        self.segs = []
        self.kcore = open('/proc/kcore', 'rb')

        output = subprocess.check_output(
            "objdump -h /proc/kcore  | grep load | awk '{print $3,$4,$6}'",
            shell=True).decode()

        if verbose:
            print("memory segments: ", file=sys.stderr)

        for l in output.splitlines():
            tokens = l.split()
            self.segs.append({
                'vma': int('0x' + tokens[1], base=0),
                'len': int('0x' + tokens[0], base=0),
                'off': int('0x' + tokens[2], base=0),
            })

            if verbose:
                print("     0x%x ~ 0x%x @ 0x%x" % (
                        self.segs[-1]['vma'],
                        self.segs[-1]['vma'] + self.segs[-1]['len'],
                        self.segs[-1]['off']),
                        file=sys.stderr)

    def read(self, addr, size):
        off = None
        for s in self.segs:
            if addr >= s['vma'] and (addr + size) <= s['vma'] + s['len']:
                off = s['off'] + (addr - s['vma'])
                break

        if not off:
            raise Exception(
                "invalid virtual address 0x%x~0x%x" % (addr, addr + size))

        self.kcore.seek(off)
        return self.kcore.read(size)

class Token(object):
    pass


class AST(object):
    pass


class Symbol(Token, AST):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


class Number(Token, AST):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return str('0x%x' % self.value)


class Rarrow(Token):
    def __str__(self):
        return '->'


class Dot(Token):
    def __str__(self):
        return '.'


class Asterisk(Token):
    def __str__(self):
        return '*'


class Lparen(Token):
    def __str__(self):
        return '('


class Rparen(Token):
    def __str__(self):
        return ')'


class Lsquare(Token):
    def __str__(self):
        return '['


class Rsquare(Token):
    def __str__(self):
        return ']'


class Keyword(Token):
    def __init__(self, value):
        self.value = value

    def __str__(self, ):
        return self.value


class Lexer(object):
    def __init__(self, text):
        self.text = text
        self.pos = 0
        self.pos_history = []

    def backward(self):
        self.pos = self.pos_history.pop()

    def next_token(self):
        old_pos = self.pos
        try:
            token = self._next_token()
        except:
            self.pos = old_pos
            raise
        else:
            self.pos_history.append(old_pos)
        return token

    def _next_token(self):
        while self.pos < len(self.text) and self.text[self.pos].isspace():
            self.pos += 1

        if self.pos >= len(self.text):
            return None

        value = self.text[self.pos]
        if value == '(':
            self.pos += 1
            return Lparen()
        elif value == ')':
            self.pos += 1
            return Rparen()
        elif value == '.':
            self.pos += 1
            return Dot()
        elif value == '*':
            self.pos += 1
            return Asterisk()
        elif value == '[':
            self.pos += 1
            return Lsquare()
        elif value == ']':
            self.pos += 1
            return Rsquare()
        elif self.pos < len(self.text) - 1 and \
                self.text[self.pos: self.pos + 2] == '->':
            self.pos += 2
            return Rarrow()
        elif value.isdigit():
            num_str = ''
            while self.pos < len(self.text) and self.text[self.pos].isalnum():
                num_str += self.text[self.pos]
                self.pos += 1
            return Number(int(num_str, 0))
        elif value.isalpha() or value == '_':
            symbol_str = ''
            while self.pos < len(self.text) and \
                    (self.text[self.pos].isalnum() or
                     self.text[self.pos] == '_'):
                symbol_str += self.text[self.pos]
                self.pos += 1
            if symbol_str == 'struct':
                return Keyword(symbol_str)
            else:
                return Symbol(symbol_str)
        else:
            raise Exception("unsupported token at column %d: %s" %
                            (self.pos + 1, self.get_pos_tip(self.pos)))

    def next_token_expect(self, expect_cls):
        token = self.next_token()
        if not isinstance(token, expect_cls):
            self.backward()
            expect_name = expect_cls.__name__.upper()
            try:
                expect_name = "'%s'" % str(expect_cls())
            except Exception:
                pass
            raise Exception("expect %s at column %d, but get '%s' %s" %
                            (expect_name, self.pos + 1, token,
                             self.get_pos_tip(self.pos)))
        return token

    def get_pos_tip(self, pos):
        while pos < len(self.text) and self.text[pos].isspace():
            pos += 1
        return '\n' + self.text + '\n' + ' ' * pos + '^' + '\n'

    def error_with_last_pos(self, message):
        if self.pos_history:
            column = self.pos_history[-1]
            message = 'error at column %d: ' % (column + 1) + \
                self.get_pos_tip(column) + message
        return Exception(message)

    def __enter__(self):
        self.archived_pos = self.pos
        self.archived_pos_history = self.pos_history[:]

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_val:
            self.pos = self.archived_pos
            self.pos_history = self.archived_pos_history


class Dereference(AST):
    def __init__(self, variable, member=None):
        self.variable = variable
        self.member = member

    def __str__(self):
        if self.member:
            return '(%s)->%s' % (self.variable, self.member)
        else:
            return '*%s' % self.variable


class Access(AST):
    def __init__(self, variable, member):
        self.variable = variable
        self.member = member

    def __str__(self):
        return '(%s).%s' % (self.variable, self.member)


class Typecast(AST):
    def __init__(self, variable, new_type, ref_level, keyword, indexes):
        self.variable = variable
        self.new_type = new_type
        self.ref_level = ref_level
        self.keyword = keyword
        self.indexes = indexes

    @property
    def type_str(self):
        ret = (self.keyword + ' ') if self.keyword else ''
        ret += self.new_type + ' '
        ret += '*' * self.ref_level
        ret += ''.join(['[%d]' % i for i in self.indexes])
        return ret.strip()

    # def btf_type(self, btf):
    #     if self.keyword == 'struct':
    #         try:
    #             type = btf.get_type(btf.KIND_STRUCT, self.new_type)
    #         except KeyError:
    #             raise Exception("can't find struct '%s'" % self.new_type)
    #     else:
    #         try:
    #             type = btf.get_type(btf.KIND_INT, self.new_type)
    #         except KeyError:
    #             try:
    #                 type = btf.get_type(btf.KIND_TYPEDEF, self.new_type)
    #             except KeyError:
    #                 raise Exception("can't find symbol '%s'" % self.new_type)

    #     for idx in self.indexes:
    #         type = {'kind': btf.KIND_ARRAY, 'nelems': idx, 'type_obj': type}

    #     for i in range(self.ref_level):
    #         type = {'kind': btf.KIND_PTR, 'type_obj': type}

    #     return type

    def __str__(self):
        return '((%s)%s)' % (self.type_str, self.variable)


class Index(AST):
    def __init__(self, variable, index):
        self.variable = variable
        self.index = index

    def __str__(self):
        return '%s[%d]' % (self.variable, self.index)


class Parser(object):
    """
    expr: (LPAREN (STRUCT)? SYMBOL (ASTERISK)* (LSQUARE NUMBER RSQUARE)* RPAREN)? term
    term: (ASTERISK expr) | variable (LSQUARE NUMBER RSQUARE | DOT SYMBOL | RARROW SYMBOL)*
    variable: SYMBOL | NUMBER | LPAREN expr RPAREN
    """
    def __init__(self, lexer):
        self.lexer = lexer

    def parse(self):
        expr = self.parse_expr()
        token = self.lexer.next_token()
        if token:
            raise self.lexer.error_with_last_pos(
                "unexpected token '%s' after expression '%s'" % (token, expr))
        return expr

    @log_arg_ret
    def parse_expr(self):
        # try to parse with typecast first
        try:
            with self.lexer:
                keyword = ''
                indexes = []
                ref_level = 0
                self.lexer.next_token_expect(Lparen)
                token = self.lexer.next_token()
                if isinstance(token, Keyword):
                    keyword = str(token)
                    symbol = self.lexer.next_token_expect(Symbol)
                elif isinstance(token, Symbol):
                    symbol = token
                else:
                    raise self.lexer.error_with_last_pos(
                        "expect 'struct' or symbol, but get '%s'" % token)

                token = self.lexer.next_token()
                while token:
                    if isinstance(token, Rparen):
                        break
                    elif isinstance(token, Asterisk):
                        ref_level += 1
                    elif isinstance(token, Lsquare):
                        indexes.append(
                            self.lexer.next_token_expect(Number).value)
                        self.lexer.next_token_expect(Rsquare)
                    else:
                        raise self.lexer.error_with_last_pos(
                            "expect '*' or ')', but get '%s'", token)
                    token = self.lexer.next_token()
                if not isinstance(token, Rparen):
                    raise self.lexer.error_with_last_pos(
                        "typecast missing ')'")
                term = self.parse_term()
                return Typecast(term, str(symbol), ref_level, keyword, indexes)
        except Exception:
            pass

        # then try to parse without typecast
        return self.parse_term()

    @log_arg_ret
    def parse_term(self):
        token = self.lexer.next_token()
        if isinstance(token, Asterisk):
            return Dereference(self.parse_expr())

        self.lexer.backward()
        term = self.parse_variable()
        token = self.lexer.next_token()
        while token:
            if isinstance(token, Dot):
                term = Access(term, self.lexer.next_token_expect(Symbol))
            elif isinstance(token, Rarrow):
                term = Dereference(term, self.lexer.next_token_expect(Symbol))
            elif isinstance(token, Lsquare):
                number = self.lexer.next_token_expect(Number)
                self.lexer.next_token_expect(Rsquare)
                term = Index(term, number.value)
            else:
                self.lexer.backward()
                break
            token = self.lexer.next_token()

        return term

    @log_arg_ret
    def parse_variable(self):
        token = self.lexer.next_token()
        if isinstance(token, Symbol) or isinstance(token, Number):
            return token
        elif isinstance(token, Lparen):
            expr = self.parse_expr()
            self.lexer.next_token_expect(Rparen)
            return expr
        else:
            raise self.lexer.error_with_last_pos(
                "expect symbol, number or expression, but get '%s'" % token)

class Dumper(object):
    BLANK = '    '

    def __init__(self,
                 array_max=DEFAULT_ARRAY_MAX, string_max=DEFAULT_STRING_MAX,
                 array_max_force=False, string_max_force=False,
                 hex_string=False, btf_path='/sys/kernel/btf/vmlinux'):

        self.array_max = array_max
        self.string_max = string_max
        self.array_max_force = array_max_force
        self.string_max_force = string_max_force
        self.hex_string = hex_string
        self.kernel_mem = KernelMem()
        self.btf = BTF(btf_path, mem_reader=self.kernel_mem)
        self.arch_size = 8
        if platform.architecture()[0] == '32bit':
            self.arch_size = 4

    # @log_arg_ret
    # def get_member_offset_and_type(self, type_info, member):
    #     # TODO delete
    #     # import pdb
    #     # pdb.set_trace()
    #     try:
    #         for m in type_info['members']:
    #             if m['name'] == str(member):
    #                 # TODO bitfield
    #                 return int(m['offset']/8), m['type_obj']
    #     except Exception as e:
    #         append_err_txt(e, "failed to get offset(%s, %s): " %
    #                        (type_info, member))
    #         reraise(*sys.exc_info())

    #     raise Exception("type '%s' has no member '%s'" % (type_info['name'], member))

    @log_arg_ret
    def get_symbol_address_and_type(self, symbol_str):
        try:
            return get_symbol_addr(symbol_str), None
        except Exception as e:
            append_err_txt(e, "failed to get address of symbol '%s': " %
                           symbol_str)
            reraise(*sys.exc_info())

    @log_arg_ret
    def dereference_addr(self, address):
        try:
            data = self.kernel_mem.read(address, self.arch_size)
        except Exception:
            raise Exception("read at address 0x%x failed" % address)

        return struct.unpack('P', data)[0]

    # def simplify_type(self, type_info):
    #     if type_info['kind'] in {
    #         self.btf.KIND_TYPEDEF,
    #         self.btf.KIND_VOLATILE,
    #         self.btf.KIND_CONST,
    #         self.btf.KIND_RESTRICT
    #         }:
    #         return self.simplify_type(type_info['type_obj'])
    #     return type_info

    def get_btf_type(self, typecast):
        if typecast.keyword == 'struct':
            try:
                type = self.btf.get_type(BTF.KIND_STRUCT, typecast.new_type)
            except KeyError:
                raise Exception("can't find struct '%s'" % typecast.new_type)
        else:
            try:
                type = self.btf.get_type(BTF.KIND_INT, typecast.new_type)
            except KeyError:
                try:
                    type = self.btf.get_type(BTF.KIND_TYPEDEF, typecast.new_type)
                except KeyError:
                    raise Exception("can't find symbol '%s'" % typecast.new_type)

        for idx in typecast.indexes:
            type = Array(self.btf, '', type, idx)
            # type = {'kind': BTF.KIND_ARRAY, 'nelems': idx, 'type_obj': type}

        for i in range(typecast.ref_level):
            type = Ptr(self.btf, '', type)
            # type = {'kind': BTF.KIND_PTR, 'type_obj': type}

        return type

    @log_arg_ret
    def get_addr_and_type(self, expr):
        if isinstance(expr, Typecast):
            addr, _ = self.get_addr_and_type(expr.variable)
            return addr, self.get_btf_type(expr)
            # return addr, self.simplify_type(expr.btf_type(self.btf))

        elif isinstance(expr, Access):
            addr, type_info = self.get_addr_and_type(expr.variable)
            if not type_info:
                raise Exception("type of '%s' is not specified" %
                                expr.variable)

            if not type_info.is_kind(BTF.KIND_STRUCT) and \
                not type_info.is_kind(BTF.KIND_UNION):
                raise Exception("type of '%s' is '%s', neither struct nor union, "
                                "'.' is not allowed" %
                                (expr.variable, type_info))

            member = type_info.get(expr.member)
            return addr + (member.offset), member.ref
            # offset, type_info = self.get_member_offset_and_type(
            #     type_info, expr.member)
            # return addr + offset, self.simplify_type(type_info)

        elif isinstance(expr, Dereference):
            addr, type_info = self.get_addr_and_type(expr.variable)
            if not type_info:
                raise Exception("type of '%s' is not specified" %
                                expr.variable)
            if type_info.is_kind(BTF.KIND_ARRAY):
                raise Exception("type of '%s' is '%s', which is an array, "
                                "not a pointer, '%s' is not allowed" %
                                (expr.variable, type_info,
                                 '->' if expr.member else '*'))
            if type_info.is_kind(BTF.KIND_STRUCT) or type_info.is_kind(BTF.KIND_UNION):
                if expr.member:
                    raise Exception("type of '%s' is '%s', '.' "
                                    "should be used instead of '->'" %
                                    (expr.variable, type_info))
            if not type_info.is_kind(BTF.KIND_PTR):
                raise Exception("type of '%s' is '%s', not a pointer, "
                                "'%s' is not allowed" %
                                (expr.variable, type_info,
                                '->' if expr.member else '*'))
            # type_info = self.btf.dereference_type(type_info)
            # type_info = self.simplify_type(type_info)
            type_info = type_info.ref
            addr = self.dereference_addr(addr)
            offset = 0
            if expr.member:
                if not type_info.is_kind(BTF.KIND_STRUCT) and \
                    not type_info.is_kind(BTF.KIND_UNION):
                    raise Exception("type of '*%s' is '%s', neither struct nor union, "
                                    "'->' is not allowed" %
                                    (expr.variable, type_info))
                type_info = type_info.get(expr.member)
                offset = type_info.offset
                type_info = type_info.ref
            return addr + offset, type_info
            # return addr + offset, self.simplify_type(type_info)

        elif isinstance(expr, Index):
            addr, type_info = self.get_addr_and_type(expr.variable)
            if not type_info:
                raise Exception("type of '%s' is not specified" %
                                expr.variable)
            if not type_info.is_kind(BTF.KIND_ARRAY) and \
                not type_info.is_kind(BTF.KIND_PTR):
                raise Exception("type of '%s' is '%s', neither pointer "
                                "nor array, index is not allowed" %
                                (expr.variable, type_info))

            # type_info = self.btf.dereference_type(type_info)
            # type_info = self.simplify_type(type_info)
            type_info = type_info.ref
            if type_info.is_kind(BTF.KIND_PTR):
                # index a pointer instead of array
                addr = self.dereference_addr(addr)

            # type_size = self.btf.get_type_size(type_info)
            # return addr + type_size * expr.index, self.simplify_type(type_info)
            return addr + type_info.size * expr.index, type_info

        elif isinstance(expr, Symbol):
            return self.get_symbol_address_and_type(expr.value)

        elif isinstance(expr, Number):
            return expr.value, ''
        
        raise Exception("unsupported expression: %s" % expr)

    # def dump_byte_array(self, data, array_len, indent):
    #     omit_tip = ''
    #     if (indent > 0 or self.string_max_force) and \
    #             array_len > self.string_max:
    #         data = data[:self.string_max]
    #         omit_tip = '...'

    #     if not self.hex_string:
    #         try:
    #             # dump as string if there is no unprintable character
    #             str_val = data.decode('ascii')
    #             end = str_val.find('\x00')
    #             if end >= 0:
    #                 str_val = str_val[:end]
    #             if not re.search(r'[^\t-\r\x20-\x7e]', str_val):
    #                 return '"%s"' % (str_val + (omit_tip if end < 0 else ''))
    #         except Exception:
    #             pass

    #     # dump as hex
    #     return '"<binary>" /* hex: %s */' % \
    #            (codecs.encode(data, 'hex').decode() + omit_tip)

    # def dump_array(self, data, element_type, array_len, indent):
    #     element_type = self.simplify_type(element_type)
    #     type_size = self.btf.get_type_size(element_type)
    #     omit_count = 0
    #     # if type_size == 1:
    #     if element_type['kind'] == self.btf.KIND_INT and \
    #             element_type['size'] == 1:
    #         return self.dump_byte_array(data, array_len, indent)

    #     # dump array in each line
    #     if (indent > 0 or self.array_max_force) and array_len > self.array_max:
    #         omit_count = array_len - self.array_max
    #         array_len = self.array_max

    #     indent += 1
    #     if element_type['kind'] == self.btf.KIND_INT:
    #         dump_txt = '{'
    #         sep = ' '
    #         before = ''
    #     else:
    #         dump_txt = '{\n'
    #         sep = '\n'
    #         before = indent * self.BLANK

    #     for i in range(array_len):
    #         dump_txt += before + self.dump_type(
    #             data[type_size * i: type_size * i + type_size],
    #             element_type, indent) + ',' + sep

    #     if omit_count:
    #         dump_txt += before + '/* other %s elements are omitted */%s' % (
    #                         omit_count, sep)
    #     indent -= 1
    #     if sep == '\n':
    #         dump_txt += indent * self.BLANK + '}'
    #     else:
    #         dump_txt += '}'
    #     return dump_txt

    # def dump_basic_type(self, data, type_info):
    #     if type_info['size'] == 1:
    #         if type_info.get('bool', False):
    #             return 'true' if struct.unpack('B', data)[0] else 'false'
    #         elif type_info.get('signed', False):
    #             val = struct.unpack('b', data)[0]
    #         else:
    #             val = struct.unpack('B', data)[0]

    #     elif type_info['size'] == 2:
    #         if type_info.get('signed', False):
    #             val = struct.unpack('h', data)[0]
    #         else:
    #             val = struct.unpack('H', data)[0]

    #     elif type_info['size'] == 4:
    #         if type_info.get('signed', False):
    #             val = struct.unpack('i', data)[0]
    #         else:
    #             val = struct.unpack('I', data)[0]

    #     elif type_info['size'] == 8:
    #         if type_info.get('signed', False):
    #             val = struct.unpack('l', data)[0]
    #         else:
    #             val = struct.unpack('L', data)[0]

    #     else:
    #         return "ERROR /* invalid int size: %d */" % type_info['size']

    #     # TODO bitfield
    #     return str(val)

    # def dump_struct(self, data, type_info, indent):
    #     dump_txt = '{\n'
    #     indent += 1
    #     for m in type_info['members']:
    #         m_name = m['name']
    #         try:
    #             m_off, m_type = self.get_member_offset_and_type(type_info, m_name)
    #             m_size = self.btf.get_type_size(m_type)
    #             if m_name:
    #                 dump_txt += indent * self.BLANK + '.' + m_name + ' = '
    #             elif m_type['kind'] == self.btf.KIND_STRUCT:
    #                 dump_txt += indent * self.BLANK + '/* nested anonymous struct */ '
    #             else:
    #                 dump_txt += indent * self.BLANK + '/* nested anonymous union */ '
    #             dump_txt += self.dump_type(data[m_off: m_off + m_size], m_type, indent)
    #             dump_txt += ',\n'
    #         except Exception:
    #             dump_txt += \
    #                 indent * self.BLANK + \
    #                 "// parse member '%s' of type '%s' failed\n" % \
    #                 (m_name, type_info['name'])
    #             log_exception()

    #     indent -= 1
    #     dump_txt += indent * self.BLANK + '}'
    #     return dump_txt

    # def dump_type(self, data, type_info, indent=0):
    #     type_info = self.simplify_type(type_info)
    #     if type_info['kind'] in {
    #         self.btf.KIND_PTR, self.btf.KIND_FUNC_PROTO}:
    #         # dump pointer
    #         return '0x%x' % struct.unpack('P', data[:self.arch_size])[0]

    #     if type_info['kind'] == self.btf.KIND_ARRAY:
    #         return self.dump_array(
    #             data, type_info['type_obj'], type_info['nelems'], indent)

    #     if type_info['kind'] in {self.btf.KIND_INT, self.btf.KIND_ENUM}:
    #         return self.dump_basic_type(data, type_info)

    #     # dump struct
    #     if type_info['kind'] in {self.btf.KIND_STRUCT, self.btf.KIND_UNION}:
    #         return self.dump_struct(data, type_info, indent)

    #     return "ERROR /* unsupported type: '%d-%s' */" % \
    #         (type_info['kind'], type_info['name'])

    # def get_data_and_type(self, expr):
    #     addr, type_info = self.get_addr_and_type(expr)
    #     if not type_info:
    #         raise Exception("type of '%s' is not specified" % expr)

    #     type_size = self.btf.get_type_size(type_info)
    #     try:
    #         data = self.kernel_mem.read(addr, type_size)
    #     except Exception as e:
    #         append_err_txt(e, "read memory failed: ")
    #         reraise(*sys.exc_info())
    #     return data, type_info

    def get_value(self, expr):
        addr, type = self.get_addr_and_type(expr)
        if not type:
            raise Exception("type of '%s' is not specified" % expr)

        return type(addr=addr)

    def dump(self, expr):
        value = self.get_value(expr)
        return "%s = %s;" % (expr, str(value))


def do_dump(dumper, expression_list, watch_interval=None):
    expr_list = []
    for expression in expression_list:
        try:
            lexer = Lexer(expression)
            parser = Parser(lexer)
            info = {
                'expr': parser.parse(),
                'last_data': None,
            }
            expr_list.append(info)
        except Exception as e:
            append_err_txt(e, "parse '%s' failed: " % expression)
            reraise(*sys.exc_info())

    while True:
        txt = ''
        for info in expr_list:
            try:
                value = dumper.get_value(info['expr'])
                # import pdb
                # pdb.set_trace()
                # data, type_info = dumper.get_data_and_type(info['expr'])
                if value.data != info['last_data']:
                    txt += ("%s = %s;\n" % (info['expr'], str(value)))
                    info['last_data'] = value.data
            except Exception as e:
                if len(expression_list) == 1 and watch_interval is None:
                    append_err_txt(e, "dump '%s' failed: " % info['expr'])
                    reraise(*sys.exc_info())
                else:
                    log_exception()

                if info['last_data'] != '':
                    txt += ("Error: %s: %s\n" % (info['expr'], get_err_txt(e)))
                    info['last_data'] = ''

        if watch_interval is None:
            txt = txt.strip()
            print(txt)
            return

        if not txt:
            time.sleep(watch_interval)
            continue

        print('%s ------------------------' %
              datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'))
        print(txt)
        sys.stdout.flush()
        time.sleep(watch_interval)


# def show_netdev():
#     dumper = Dumper()
#     expr = Parser(Lexer('((struct net) init_net).dev_base_head.next')).parse()
#     value = dumper.get_value(expr)
#     next_type = type
#     next = int(value)

#     netdev_type = dumper.btf.get_type(BTF.KIND_STRUCT, "net_device")
#     offset = dumper.get_member_offset_and_type(netdev_type, 'dev_list')[0]

#     while next:
#         dev_addr = next - offset
#         expr = Parser(Lexer('((struct net_device) %d).name' % dev_addr)).parse()
#         data, type = dumper.get_data_and_type(expr)
#         dev_name = dumper.dump_type(data, type)
#         print("%s 0x%x" % (dev_name, dev_addr))

#         expr = Parser(Lexer('((struct list_head) %d).prev' % next)).parse()
#         data, type = dumper.get_data_and_type(expr)
#         next = int(dumper.dump_type(data, type), base=0)

if __name__ == '__main__':
    epilog = """examples:
    * dump the kernel init_net structure:
        %(prog)s '(struct net) init_net'
    * 
    """ % {'prog': sys.argv[0]}
    parser = argparse.ArgumentParser(
        description='Dump global variables of kernel.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog)
    parser.add_argument('expression', type=str, nargs='+',
                        help='rvalue expression in C style with typecast')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='show debug information')
    parser.add_argument('-x', '--hex-string', action='store_true',
                        help='dump byte array in hex instead of string')
    parser.add_argument('-a', '--array-max', type=int, default=0,
                        help='maximum number of array elements to display')
    parser.add_argument('-s', '--string-max', type=int, default=0,
                        help='maximum string length to display')
    parser.add_argument('-w', '--watch-interval', type=float,
                        help='check the expression value every WATCH_INTERVAL '
                             'seconds and dump it when it changes')
    parser.add_argument('-t', '--btf', type=str,
                        help='BTF file path', default='/sys/kernel/btf/vmlinux')
    args = parser.parse_args()

    verbose = args.verbose
    array_max = args.array_max if args.array_max > 0 else DEFAULT_ARRAY_MAX
    string_max = args.string_max if args.string_max > 0 else DEFAULT_STRING_MAX
    array_max_force = bool(args.array_max > 0)
    string_max_force = bool(args.string_max > 0)

    try:
        dumper = Dumper(array_max=array_max, array_max_force=array_max_force,
                        hex_string=args.hex_string, string_max=string_max,
                        string_max_force=string_max_force, btf_path=args.btf)
        # try:
        do_dump(dumper, args.expression, args.watch_interval)
        # except Exception:
        #     import pdb
        #     pdb.set_trace()
    except Exception as e:
        print("Error: %s" % get_err_txt(e), file=sys.stderr)
        if verbose:
            reraise(*sys.exc_info())
        exit(1)
