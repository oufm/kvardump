#!/usr/bin/env python
from __future__ import print_function
from datetime import datetime
import os
import re
import sys
import time
import copy
import json
import codecs
import hashlib
import subprocess
import argparse
import platform
import struct
import functools
import traceback

DEFAULT_ARRAY_MAX = 5
DEFAULT_STRING_MAX = 64
DEFAULT_BTF_PATH = '/sys/kernel/btf/vmlinux'
DEFAULT_CACHE_DIR = '/tmp/kvardump'

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


# def cache_result(func):
#     @functools.wraps(func)
#     def _func(self, *args, **kwargs):
#         param_tuple = (tuple(args), frozenset(kwargs))
#         cache_name = '_%s_cache' % func.__name__
#         cache_dict = getattr(self, cache_name, {})
#         if not cache_dict:
#             setattr(self, cache_name, cache_dict)

#         cache_value = copy.deepcopy(cache_dict.get(param_tuple, None))
#         if isinstance(cache_value, Exception):
#             raise cache_value

#         if cache_value is not None:
#             return cache_value

#         try:
#             cache_value = func(self, *args, **kwargs)
#         except Exception as e:
#             cache_dict[param_tuple] = copy.deepcopy(e)
#             reraise(*sys.exc_info())
#         else:
#             cache_dict[param_tuple] = copy.deepcopy(cache_value)
#         return cache_value

#     return _func

class FormatOpt(object):
    def __init__(self,
                 array_max=DEFAULT_ARRAY_MAX,
                 string_max=DEFAULT_STRING_MAX,
                 array_max_force=False,
                 string_max_force=False,
                 hex_string=False,
                 blank='    '):
        self.array_max = array_max
        self.string_max = string_max
        self.array_max_force = array_max_force
        self.string_max_force = string_max_force
        self.hex_string = hex_string
        self.blank = blank

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
    TYPE_MAP = {}

    def __init__(self,
                 btf_path=DEFAULT_BTF_PATH,
                 cache_dir=DEFAULT_CACHE_DIR,
                 mem_reader=None, fmt=FormatOpt()):
        self.arch_size = 8
        if platform.architecture()[0] == '32bit':
            self.arch_size = 4

        self.btf_path = btf_path
        self.mem_reader = mem_reader
        self.fmt = fmt

        self.open_btf()

        cache_path = os.path.join(
            cache_dir, os.path.basename(btf_path)) if cache_dir else None
        if cache_path:
            try:
                if os.path.exists(cache_path):
                    self.load_cache(cache_path)
                    return
            except Exception as e:
                print("load cache from %s failed: %s" % (cache_path, e),
                        file=sys.stderr)
                log_exception()

        self.parse()

        if cache_path:
            try:
                self.save_cache(cache_path)
            except Exception as e:
                print("save cache to %s failed: %s" % (cache_path, e),
                        file=sys.stderr)
                log_exception()

    def __getitem__(self, kind_name):
        return self.get(kind_name)

    def __len__(self):
        return len(self.offsets)

    @classmethod
    def register_type(cls, kind):
        def _decorator(target):
            target.KIND = kind
            cls.TYPE_MAP[kind] = target
            return target
        return _decorator

    def load_cache(self, path):
        print("loading cache from '%s'" % path, file=sys.stderr)

        with open(path, 'r') as f:
            cache = json.load(f)
            if cache['md5'] != self.md5:
                raise Exception("checksum of '%s' changed" % self.btf_path)
            self.name2id = cache['name2id']
            self.offsets = cache['offsets']
            self.id2type = {}

    def save_cache(self, path):
        print("writing cache to '%s'" % path, file=sys.stderr)

        dir = os.path.dirname(path)
        if not os.path.exists(dir):
            os.mkdir(dir)

        with open(path, 'w') as f:
            cache = {
                'name2id': self.name2id,
                'offsets': self.offsets,
                'md5': self.md5,
            }
            json.dump(cache, f)

    def open_btf(self):
        with open(self.btf_path, 'rb') as f:
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
        self.md5 = hashlib.md5(self.data).hexdigest()
        self.pos = 0

        if (self.type_off + self.type_len > len(self.data)):
            raise Exception("invalid BTF, may be truncated")

        if (self.str_off + self.str_len > len(self.data)):
            raise Exception("invalid BTF, may be truncated")

        if self.magic != 0xeb9f:
            raise Exception("invalid BTF file, wrong magic: 0x%x" % self.magic)

        self.str_data = self.data[self.str_off : self.str_off + self.str_len]
        self.type_data = self.data[self.type_off : self.type_off + self.type_len]

    def eat(self, size):
        if self.pos + size > len(self.type_data):
             raise Exception(
                "invalid BTF, 0x%x reaches the end of data" % (self.pos + size))
        data = self.type_data[self.pos : self.pos + size]
        self.pos += size
        return data

    def parse_one(self):
        data = self.eat(12)
        btf_type = struct.unpack("III", data)
        name_off = btf_type[0]
        info = btf_type[1]
        size = type = btf_type[2]
        vlen = info & 0xffff
        kind = (info >> 24) & 0xf
        kind_flag = info >> 31
        name = self.offset2name(name_off)
        cls = self.TYPE_MAP[kind]
        type = cls.from_btf(self, name, size, type, vlen, kind_flag)
        return type

    def parse(self):
        print("parsing types in '%s'" % self.btf_path, file=sys.stderr)
        self.name2id = {}
        # type ID start from 1
        self.offsets = [None]
        self.id2type = {}

        while self.pos < len(self.type_data):
            id = len(self.offsets)
            self.offsets.append(self.pos)
            type = self.parse_one()
            self.name2id["%s.%s" % (type.KIND, type.name)] = id
            self.id2type[id] = type

    def offset2name(self, offset):
        if offset >= len(self.str_data):
            raise Exception("invalid BTF file, invalid name offset: 0x%x" % offset)

        end = self.str_data[offset:].find(b'\x00')
        if end < 0:
            raise Exception("invalid BTF file, invalid string at 0x%x" % offset)

        return self.str_data[offset : offset + end].decode('ascii')

    def get(self, item, *args):
        if isinstance(item, int):
            id = item
            if id >= len(self) or id <= 0:
                if args:
                    return args[0]
                raise IndexError("invalid type id %s" % id)
        else:
            key = '%s.%s' % item
            # key = str(item[0]) + '.' + item[1]
            if key not in self.name2id:
                if args:
                    return args[0]
                raise KeyError("no type name '%s' with kind %s" %
                    (item[1], item[0]))
            id = self.name2id[key]

        if id in self.id2type:
            return self.id2type[id]

        self.pos = self.offsets[id]
        self.id2type[id] = self.parse_one()
        return self.id2type[id]

class BaseValue(object):
    def __init__(self, type, data=None, addr=None):
        if not data and not addr:
            raise Exception("both data add addr are not specified")

        self.type = type
        self.btf = type.btf
        self.fmt = type.btf.fmt
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
            return repr(self)

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
            self.type = self.btf[self.type]

        return self.type

    def is_kind(self, kind):
        return self.KIND == kind

@BTF.register_type(BTF.KIND_INT)
class Int(BTFType):
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

@BTF.register_type(BTF.KIND_PTR)
class Ptr(Ref):
    def __str__(self):
        return "%s *" % str(self.ref)

    @property
    def size(self):
        return self.btf.arch_size

    class Value(BaseValue):
        def __int__(self):
            return struct.unpack('P', self.data)[0]

        def to_str(self, indent):
            return '0x%x' % int(self)

        def __getitem__(self, idx):
            addr = int(self) + idx * self.type.ref.size
            return self.type.ref(addr=addr)

        def __getattr__(self, name):
            return getattr(self.eval(), name)

        @property
        def eval(self):
            try:
                return self.type.ref(addr=int(self))
            except AttributeError:
                msg = "dereference value failed: %s" % (
                    str(sys.exc_info()[1]))
                reraise(Exception, msg, sys.exc_info()[2])

class Bedeck(Ref):
    def __getattr__(self, name):
        return getattr(self.ref, name)

    def __getitem__(self, idx):
        return self.ref[idx]

    def __len__(self):
        return len(self.ref)

    def is_kind(self, kind):
        if self.KIND == kind:
            return True
        return self.ref.is_kind(kind)

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

        def __int__(self):
            return int(self.ref)

        def __str__(self):
            return str(self.ref)

        def __getitem__(self, idx):
            return self.ref[idx]

        def __len__(self):
            return len(self.ref)

        def to_str(self, indent=0):
            return self.ref.to_str(indent)

@BTF.register_type(BTF.KIND_TYPEDEF)
class TypeDef(Bedeck):
    pass

@BTF.register_type(BTF.KIND_VOLATILE)
class Volatile(Bedeck):
    def __str__(self):
        return "volatile %s" % str(self.ref)

@BTF.register_type(BTF.KIND_CONST)
class Const(Bedeck):
    def __str__(self):
        return "const %s" % str(self.ref)

@BTF.register_type(BTF.KIND_RESTRICT)
class Restrict(Bedeck):
    def __str__(self):
        return "restrict %s" % str(self.ref)

@BTF.register_type(BTF.KIND_ARRAY)
class Array(BTFType):
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

        def dump_byte_array(self, indent):
            omit_tip = ''
            if (indent > 0 or self.fmt.string_max_force) and \
                    self.type.nelems > self.fmt.string_max:
                data = self.data[:self.fmt.string_max]
                omit_tip = '...'

            if not self.fmt.hex_string:
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
            if elem_type.is_kind(BTF.KIND_INT) and elem_size == 1:
                return self.dump_byte_array(indent)

            # dump array in each line
            if (indent > 0 or self.fmt.array_max_force) and \
                    array_len > self.fmt.array_max:
                omit_count = array_len - self.fmt.array_max
                array_len = self.fmt.array_max

            indent += 1
            if elem_type.is_kind(BTF.KIND_INT):
                txt = '{'
                sep = ' '
                before = ''
            else:
                txt = '{\n'
                sep = '\n'
                before = indent * self.fmt.blank

            for i in range(array_len):
                txt += before + self[i].to_str(indent) + ',' + sep

            if omit_count:
                txt += before + '/* other %s elements are omitted */%s' % (
                                omit_count, sep)
            indent -= 1
            if sep == '\n':
                txt += indent * self.fmt.blank + '}'
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

        def __call__(self, *args, **kwargs):
            return NotImplementedError()

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

    def __getattr__(self, name):
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
                btf.offset2name(info[0]), info[1], info[2] & 0xffffff, info[2] >> 24)
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
            data = self.data[member.offset : member.offset + member.ref.size]
            return member.ref(data=data, addr=addr)

        def get(self, name):
            member = self.type.get(name)
            return self._get(member)

        def to_str(self, indent=0):
            txt = '{\n'
            indent += 1
            for m in self.type.members:
                if m.name:
                    txt += indent * self.fmt.blank + '.' + m.name + ' = '
                elif m.ref.is_kind(BTF.KIND_STRUCT):
                    txt += indent * self.fmt.blank  + '/* nested anonymous struct */ '
                else:
                    txt += indent * self.fmt.blank  + '/* nested anonymous union */ '
                txt += self._get(m).to_str(indent)
                txt += ',\n'

            indent -= 1
            txt += indent * self.fmt.blank  + '}'
            return txt

@BTF.register_type(BTF.KIND_STRUCT)
class Struct(StructUnion):
    def __str__(self):
        return "struct %s" % str(self.name)

@BTF.register_type(BTF.KIND_UNION)
class Union(StructUnion):
    def __str__(self):
        return "union %s" % str(self.name)

@BTF.register_type(BTF.KIND_ENUM)
class Enum(Int):
    class Member(BTFType):
        def __init__(self, parent, btf, name, val):
            self.parent = parent
            self.btf = btf
            self.name = name
            self.val = val

        def __call__(self, *args, **kwargs):
            return NotImplementedError()

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
            obj.add_member(btf.offset2name(info[0]), info[1])
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

@BTF.register_type(BTF.KIND_FWD)
class Fwd(BTFType):
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

@BTF.register_type(BTF.KIND_FUNC_PROTO)
class FuncProto(BTFType):
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

@BTF.register_type(BTF.KIND_FUNC)
class Func(Ref):
    pass

@BTF.register_type(BTF.KIND_VAR)
class Var(BTFType):
    def __init__(self, btf, name, type):
        self.btf = btf
        self.name = name
        self.type = type

    @classmethod
    def from_btf(cls, btf, name, size, type, vlen, kind_flag):
        btf.eat(4)
        return cls(btf, name, type)

@BTF.register_type(BTF.KIND_DATASEC)
class DataSec(BTFType):
    def __init__(self, btf, name, vlen, size):
        self.btf = btf
        self.name = name
        self.vlen = vlen
        self.size = size

    @classmethod
    def from_btf(cls, btf, name, size, type, vlen, kind_flag):
        btf.eat(12 * vlen)
        return cls(btf, name, vlen, size)

def get_symbol_addr(name):
    try:
        output = subprocess.check_output(
            "cat /proc/kallsyms | grep -w %s | awk '{print $1}'" % name,
            shell=True).decode()
        return int('0x' + output, base=0)
    except Exception as e:
        append_err_txt(e, "failed to get address of symbol '%s': " % name)
        reraise(*sys.exc_info())

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

    def __init__(self, fmt=FormatOpt(),
                 btf_path=DEFAULT_BTF_PATH, cache_dir=DEFAULT_CACHE_DIR):
        self.kernel_mem = KernelMem()
        self.arch_size = 8
        if platform.architecture()[0] == '32bit':
            self.arch_size = 4

        path_list = btf_path if isinstance(btf_path, list) else [btf_path]
        self.btfs = [BTF(path, mem_reader=self.kernel_mem,
                         fmt=fmt, cache_dir=cache_dir) for path in path_list]
        # self.btf = BTF(btf_path, mem_reader=self.kernel_mem,
        #         fmt=fmt, cache_dir=cache_dir)

    @log_arg_ret
    def dereference_addr(self, address):
        try:
            data = self.kernel_mem.read(address, self.arch_size)
        except Exception:
            raise Exception("read at address 0x%x failed" % address)

        return struct.unpack('P', data)[0]

    def get_btf_type(self, typecast):
        type = None
        for btf in self.btfs:
            if typecast.keyword == 'struct':
                try:
                    type = btf[(BTF.KIND_STRUCT, typecast.new_type)]
                except KeyError:
                    continue
            else:
                try:
                    type = btf[(BTF.KIND_INT, typecast.new_type)]
                except KeyError:
                    try:
                        type = btf[(BTF.KIND_TYPEDEF, typecast.new_type)]
                    except KeyError:
                        continue
            break

        if not type:
            raise Exception(
                "can't find symbol %s%s" % (typecast.keyword, typecast.new_type))

        for idx in typecast.indexes:
            type = Array(type.btf, '', type, idx)

        for i in range(typecast.ref_level):
            type = Ptr(type.btf, '', type)

        return type

    @log_arg_ret
    def get_addr_type(self, expr):
        if isinstance(expr, Typecast):
            addr, _ = self.get_addr_type(expr.variable)
            return addr, self.get_btf_type(expr)

        elif isinstance(expr, Access):
            addr, type = self.get_addr_type(expr.variable)
            if not type:
                raise Exception("type of '%s' is unknown" % expr.variable)

            if not type.is_kind(BTF.KIND_STRUCT) and \
                not type.is_kind(BTF.KIND_UNION):
                raise Exception("type of '%s' is '%s', neither struct nor union, "
                                "'.' is not allowed" % (expr.variable, type))

            member = type.get(expr.member)
            return addr + (member.offset), member.ref

        elif isinstance(expr, Dereference):
            addr, type = self.get_addr_type(expr.variable)
            if not type:
                raise Exception("type of '%s' is unknown" % expr.variable)
            if type.is_kind(BTF.KIND_ARRAY):
                raise Exception("type of '%s' is '%s', which is an array, "
                                "not a pointer, '%s' is not allowed" %
                                (expr.variable, type,
                                 '->' if expr.member else '*'))
            if type.is_kind(BTF.KIND_STRUCT) or type.is_kind(BTF.KIND_UNION):
                if expr.member:
                    raise Exception("type of '%s' is '%s', '.' "
                                    "should be used instead of '->'" %
                                    (expr.variable, type))
            if not type.is_kind(BTF.KIND_PTR):
                raise Exception("type of '%s' is '%s', not a pointer, "
                                "'%s' is not allowed" %
                                (expr.variable, type,
                                '->' if expr.member else '*'))
            type = type.ref
            addr = self.dereference_addr(addr)
            offset = 0
            if expr.member:
                if not type.is_kind(BTF.KIND_STRUCT) and \
                    not type.is_kind(BTF.KIND_UNION):
                    raise Exception("type of '*%s' is '%s', neither struct nor union, "
                                    "'->' is not allowed" %
                                    (expr.variable, type))
                type = type.get(expr.member)
                offset = type.offset
                type = type.ref
            return addr + offset, type

        elif isinstance(expr, Index):
            addr, type = self.get_addr_type(expr.variable)
            if not type:
                raise Exception("type of '%s' is not specified" %
                                expr.variable)
            if not type.is_kind(BTF.KIND_ARRAY) and \
                not type.is_kind(BTF.KIND_PTR):
                raise Exception("type of '%s' is '%s', neither pointer "
                                "nor array, index is not allowed" %
                                (expr.variable, type))

            type = type.ref
            if type.is_kind(BTF.KIND_PTR):
                # index a pointer instead of array
                addr = self.dereference_addr(addr)

            return addr + type.size * expr.index, type

        elif isinstance(expr, Symbol):
            return get_symbol_addr(expr.value), None

        elif isinstance(expr, Number):
            return expr.value, None

        raise Exception("unsupported expression: %s" % expr)

    def get_value(self, expr):
        addr, type = self.get_addr_type(expr)
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
    parser.add_argument('-t', '--btf-paths', type=str,
                        help='BTF paths, separated by ","',
                        default=DEFAULT_BTF_PATH)
    parser.add_argument('-c', '--cache-dir', type=str,
                        help='directory to save cache, set empty to disable cache',
                        default=DEFAULT_CACHE_DIR)
    args = parser.parse_args()

    verbose = args.verbose
    array_max = args.array_max if args.array_max > 0 else DEFAULT_ARRAY_MAX
    string_max = args.string_max if args.string_max > 0 else DEFAULT_STRING_MAX
    array_max_force = bool(args.array_max > 0)
    string_max_force = bool(args.string_max > 0)
    fmt = FormatOpt(array_max=array_max, array_max_force=array_max_force,
                    hex_string=args.hex_string, string_max=string_max,
                    string_max_force=string_max_force)

    try:
        dumper = Dumper(btf_path=args.btf_paths.split(','),
                        fmt=fmt, cache_dir=args.cache_dir)
        do_dump(dumper, args.expression, args.watch_interval)
    except Exception as e:
        print("Error: %s" % get_err_txt(e), file=sys.stderr)
        if verbose:
            reraise(*sys.exc_info())
        exit(1)
