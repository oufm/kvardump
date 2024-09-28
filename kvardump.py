#!/usr/bin/env python
from __future__ import print_function
from datetime import datetime
import os
import re
import sys
import time
import json
import copy
import codecs
import hashlib
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
quiet = False
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


def err_txt(err):
    return getattr(err, "show_txt", str(err))


def append_err(err, txt_before='', txt_after=''):
    err.show_txt = "%s%s%s" % (txt_before, err_txt(err), txt_after)


def log_info(txt):
    if not quiet:
        print(txt, file=sys.stderr)


def log_debug(txt):
    if verbose:
        print(txt, file=sys.stderr)


def log_error(txt):
    print("Error: %s" % txt, file=sys.stderr)


def log_exception():
    if not verbose:
        return

    exc_type, exc_value, exc_traceback = sys.exc_info()
    log_error(err_txt(exc_value))
    traceback.print_exception(exc_type, exc_value, exc_traceback,
                              file=sys.stderr)


def log_call(func):
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
                arg_str1 = ', '.join([repr(i) for i in args])
                arg_str2 = ', '.join([repr(k) + '=' + repr(v)
                                      for k, v in kwargs.items()])
                if arg_str1 and arg_str2:
                    arg_str = arg_str1 + ', ' + arg_str2
                else:
                    arg_str = arg_str1 + arg_str2
                print("call[%d]: %s(%s) = %s" %
                      (log_nest_level, func.__name__, arg_str, repr(ret)),
                      file=sys.stderr)
        return ret
    return _func


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
    KIND_VOID = 0
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
                 mem_reader=None,
                 fmt=FormatOpt(),
                 value_init_hook=None):
        self.arch_size = 8
        if platform.architecture()[0] == '32bit':
            self.arch_size = 4

        self.btf_path = btf_path
        self.mem_reader = mem_reader
        self.value_init_hook = value_init_hook
        self.fmt = fmt

        self.id2type = {}
        self.open_btf()

        cache_path = (os.path.join(cache_dir, os.path.basename(btf_path)) +
                        '.btfcache') if cache_dir else None
        if cache_path:
            try:
                if os.path.exists(cache_path):
                    self.load_cache(cache_path)
                    return
            except Exception as e:
                log_error("load cache from %s failed: %s" % (cache_path, e))
                log_exception()

        self.parse()

        if cache_path:
            try:
                self.save_cache(cache_path)
            except Exception as e:
                log_error("save cache to %s failed: %s" % (cache_path, e))
                log_exception()

    def __getitem__(self, kind_name):
        return self.get(kind_name)

    def __len__(self):
        return len(self.offsets)

    @classmethod
    def register_kind(cls, kind):
        def _decorator(target):
            target.KIND = kind
            cls.TYPE_MAP[kind] = target
            return target
        return _decorator

    def load_cache(self, path):
        log_info("loading cache from '%s'" % path)

        with open(path, 'r') as f:
            cache = json.load(f)
            if cache['md5'] != self.md5:
                raise Exception("checksum of '%s' changed" % self.btf_path)
            self.name2id = cache['name2id']
            self.offsets = cache['offsets']

    def save_cache(self, path):
        log_info("writing cache to '%s'" % path)

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
        ext_size = cls.btf_ext_size(vlen)
        bpf_type = cls.from_btf(
            self, name, size, type, vlen, kind_flag, self.eat(ext_size))
        return bpf_type

    def parse(self):
        log_info("parsing types in '%s'" % self.btf_path)
        self.name2id = {}
        # type ID start from 1
        self.offsets = [None]

        while self.pos < len(self.type_data):
            id = len(self.offsets)
            self.offsets.append(self.pos)
            data = self.eat(8)
            name_off, info = struct.unpack("II", data)
            vlen = info & 0xffff
            kind = (info >> 24) & 0xf
            name = self.offset2name(name_off)
            cls = self.TYPE_MAP[kind]
            ext_size = cls.btf_ext_size(vlen)
            self.pos += (4 + ext_size)
            self.name2id["%s.%s" % (cls.KIND, name)] = id

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
            raise Exception("both data and addr are not specified")

        self.type = type
        self.btf = type.btf
        self.fmt = type.btf.fmt
        self._data = data
        self.addr = addr

        if self.btf.value_init_hook:
            self.btf.value_init_hook(self)

    def __str__(self):
        return self.to_str()

    def __repr__(self):
        if self.addr is None:
            addr_str = 'None'
        else:
            addr_str = "0x%x" % self.addr

        if self._data is None:
            data_str = 'None'
        else:
            data_str = codecs.encode(self._data[:8], 'hex').decode()
            if len(self._data) > 8:
                data_str += '...'
        return "%s(type='%s', addr=%s, data=%s)" % (
            self.type.__class__.__name__,
            str(self.type), addr_str, data_str)

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

    @property
    def pointer(self):
        if self.addr is None:
            raise Exception("unknown address of %s" % repr(self))

        type = Ptr(self.btf, '', self.type)
        return type(data=struct.pack('P', self.addr))

    def to_str(self, indent=0):
        raise NotImplementedError()

    def to_int(self):
        return int(self)

    def _cast(self, type):
        if self.addr:
            return type(addr=self.addr)
        elif type.size <= len(self.data):
            return type(data=self.data[:type.size])

        raise Exception("unknown address of '%s'" % repr(self))


class BTFType(object):
    @classmethod
    def from_btf(cls, btf, name, size, type, vlen, kind_flag, ext_data):
        raise NotImplementedError()

    @staticmethod
    def btf_ext_size(vlen):
        return 0

    def __str__(self):
        if not self.name:
            return 'NO_NAME'
        return self.name

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, str(self))

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


@BTF.register_kind(BTF.KIND_VOID)
class Void(BTFType):
    def __init__(self, btf, name):
        self.btf = btf
        self.name = name
        self.size = 0

    @classmethod
    def from_btf(cls, btf, name, size, type, vlen, kind_flag, ext_data):
        return cls(btf, name)

    def __str__(self):
        return self.name or "void"

    class Value(BaseValue):
        pass

@BTF.register_kind(BTF.KIND_INT)
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

    @staticmethod
    def btf_ext_size(vlen):
        return 4

    @classmethod
    def from_btf(cls, btf, name, size, type, vlen, kind_flag, ext_data):
        info = struct.unpack("I", ext_data)[0]
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
                    val = struct.unpack('q', self.data)[0]
                else:
                    val = struct.unpack('Q', self.data)[0]
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
    def from_btf(cls, btf, name, size, type, vlen, kind_flag, ext_data):
        return cls(btf, name, type)


@BTF.register_kind(BTF.KIND_PTR)
class Ptr(Ref):
    def __str__(self):
        return "%s *" % str(self.ref)

    @property
    def size(self):
        return self.btf.arch_size

    class Value(BaseValue):
        def __int__(self):
            return struct.unpack('P', self.data)[0]

        def to_str(self, indent=0):
            return '0x%x' % int(self)

        def __getitem__(self, idx):
            addr = int(self) + idx * self.type.ref.size
            return self.type.ref(addr=addr)

        def __getattr__(self, name):
            return getattr(self.value, name)

        def __add__(self, num):
            addr = int(self)
            addr += (int(num) * self.type.ref.size)
            return self.type(data=struct.pack('P', addr))

        def __sub__(self, num):
            addr = int(self)
            addr -= (int(num) * self.type.ref.size)
            return self.type(data=struct.pack('P', addr))

        @property
        def value(self):
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


@BTF.register_kind(BTF.KIND_TYPEDEF)
class TypeDef(Bedeck):
    pass


@BTF.register_kind(BTF.KIND_VOLATILE)
class Volatile(Bedeck):
    def __str__(self):
        return "volatile %s" % str(self.ref)


@BTF.register_kind(BTF.KIND_CONST)
class Const(Bedeck):
    def __str__(self):
        return "const %s" % str(self.ref)


@BTF.register_kind(BTF.KIND_RESTRICT)
class Restrict(Bedeck):
    def __str__(self):
        return "restrict %s" % str(self.ref)


@BTF.register_kind(BTF.KIND_ARRAY)
class Array(BTFType):
    def __init__(self, btf, name, type, nelems):
        self.btf = btf
        self.name = name
        self.type = type
        self.nelems = nelems

    def __str__(self):
        return "%s[%d]" % (str(self.ref), self.nelems)

    @staticmethod
    def btf_ext_size(vlen):
        return 12

    @classmethod
    def from_btf(cls, btf, name, size, type, vlen, kind_flag, ext_data):
        info = struct.unpack("III", ext_data)
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
            data = self.data
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
                        return ('"%s"' if indent > 0 else '%s') % (
                            str_val + (omit_tip if end < 0 else ''))
                except Exception:
                    pass

            # dump as hex
            return '"<binary>" /* hex: %s */' % \
                (codecs.encode(data, 'hex').decode() + omit_tip)

        def to_str(self, indent=0):
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
            self.offset = offset // 8
            self.size = size

        def __repr__(self):
            try:
                return '%s:%s' % (self.name, repr(self.ref))
            except Exception:
                return '%s:%s' % (self.name, repr(self.type))

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
                    dup = copy.copy(m.ref.get(member))
                    dup.offset += m.offset
                    dup.offset_bits += m.offset_bits
                    return dup
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

    @staticmethod
    def btf_ext_size(vlen):
        return 12 * vlen

    @classmethod
    def from_btf(cls, btf, name, size, type, vlen, kind_flag, ext_data):
        obj = cls(btf, name, vlen, size)
        for i in range(vlen):
            info = struct.unpack("III", ext_data[12 * i : 12 * (i + 1)])
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
            return self.get(name)

        def _get(self, member):
            addr = self.addr + member.offset if self.addr else None
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


@BTF.register_kind(BTF.KIND_STRUCT)
class Struct(StructUnion):
    def __str__(self):
        return "struct %s" % str(self.name)


@BTF.register_kind(BTF.KIND_UNION)
class Union(StructUnion):
    def __str__(self):
        return "union %s" % str(self.name)


@BTF.register_kind(BTF.KIND_ENUM)
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

    @staticmethod
    def btf_ext_size(vlen):
        return 8 * vlen

    @classmethod
    def from_btf(cls, btf, name, size, type, vlen, kind_flag, ext_data):
        obj = cls(btf, name, vlen, size)
        for i in range(vlen):
            info = struct.unpack("Ii", ext_data[8 * i : 8 * (i + 1)])
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

            return super(self.__class__, self).to_str(indent)


@BTF.register_kind(BTF.KIND_FWD)
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
    def from_btf(cls, btf, name, size, type, vlen, kind_flag, ext_data):
        return cls(btf, name, kind_flag)


@BTF.register_kind(BTF.KIND_FUNC_PROTO)
class FuncProto(BTFType):
    def __init__(self, btf, name, vlen, type):
        self.btf = btf
        self.name = name
        self.vlen = vlen
        self.type = type

    def __str__(self):
        return "%s (*%s)(...)" % (str(self.ref), self.name)

    @staticmethod
    def btf_ext_size(vlen):
        return 8 * vlen

    @classmethod
    def from_btf(cls, btf, name, size, type, vlen, kind_flag, ext_data):
        return cls(btf, name, vlen, type)

    @property
    def size(self):
        return self.btf.arch_size

    class Value(BaseValue):
        def __int__(self):
            return struct.unpack('P', self.data)[0]

        def to_str(self, indent=0):
            return '0x%x' % int(self)


@BTF.register_kind(BTF.KIND_FUNC)
class Func(Ref):
    pass


@BTF.register_kind(BTF.KIND_VAR)
class Var(BTFType):
    def __init__(self, btf, name, type):
        self.btf = btf
        self.name = name
        self.type = type

    @staticmethod
    def btf_ext_size(vlen):
        return 4

    @classmethod
    def from_btf(cls, btf, name, size, type, vlen, kind_flag, ext_data):
        return cls(btf, name, type)


@BTF.register_kind(BTF.KIND_DATASEC)
class DataSec(BTFType):
    def __init__(self, btf, name, vlen, size):
        self.btf = btf
        self.name = name
        self.vlen = vlen
        self.size = size

    @staticmethod
    def btf_ext_size(vlen):
        return 12 * vlen

    @classmethod
    def from_btf(cls, btf, name, size, type, vlen, kind_flag, ext_data):
        return cls(btf, name, vlen, size)


class Token(object):
    def __repr__(self):
        return str(self)


class AST(object):
    def __repr__(self):
        return str(self)


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

    @log_call
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

    @log_call
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

    @log_call
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


class CoreMem(object):
    def __init__(self, path='/proc/kcore'):
        self.segs = []
        self.kcore = open(path, 'rb')
        self.load_segs()

    def load_segs(self):
        self.kcore.seek(0x20)
        first = struct.unpack('Q', self.kcore.read(8))[0]

        self.kcore.seek(0x36)
        ent_size = struct.unpack('H', self.kcore.read(2))[0]

        self.kcore.seek(0x38)
        count = struct.unpack('H', self.kcore.read(2))[0]

        log_debug("memory segments: ")

        for i in range(count):
            self.kcore.seek(first + ent_size * i + 0)
            type = struct.unpack('I', self.kcore.read(4))[0]
            if type != 1:
                continue

            self.kcore.seek(first + ent_size * i + 0x8)
            off = struct.unpack('Q', self.kcore.read(8))[0]

            self.kcore.seek(first + ent_size * i + 0x10)
            vma = struct.unpack('Q', self.kcore.read(8))[0]

            self.kcore.seek(first + ent_size * i + 0x20)
            len = struct.unpack('Q', self.kcore.read(8))[0]

            self.segs.append({
                'off': off,
                'vma': vma,
                'len': len,
            })
            log_debug("     0x%x ~ 0x%x @ 0x%x" % (vma, vma + len, off))


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


class KernelSym(object):
    def __init__(self):
        with open('/proc/kallsyms', 'r') as f:
            self.data = f.read()

    def __call__(self, name):
        try:
            addr = re.search(
                r'(^|\n)(\w+)\s+\w+\s+' + name + r'($|\s|\n)',
                self.data).group(2)
            return int('0x' + addr, base=0)
        except Exception as e:
            append_err(e, "failed to get address of symbol '%s': " % name)
            reraise(*sys.exc_info())


class ElfSym(object):
    def __init__(self, pid, elf_path=None):
        elf_path = elf_path or os.readlink(os.path.join('/proc', str(pid), 'exe'))
        if not os.access(elf_path, os.R_OK):
            raise Exception("can't read '%s'")

        maps = open(os.path.join('/proc', str(pid), 'maps')).read()
        self.base_addr = int([line for line in maps.splitlines()
                              if elf_path in line][0].split('-')[0], base=16)
        # for non-PIE executable, see: https://stackoverflow.com/a/73189318/18251455
        if self.base_addr == 0x400000:
            self.base_addr = 0

        self.read_symbols(elf_path)

    def read_symbols(self, path):
        self.symbols = {}

        log_info("reading symbols in '%s'" % path)
        # Open the ELF file
        with open(path, "rb") as f:
            # Read the ELF file header
            f.seek(40)
            elf_shoff = struct.unpack("Q", f.read(8))[0]
            f.seek(60)
            elf_shnum = struct.unpack("H", f.read(2))[0]
            f.seek(62)
            elf_shstrndx = struct.unpack("H", f.read(2))[0]

            # Find the symbol table and string table
            symtab_offset = 0
            symtab_size = 0
            strtab_offset = 0
            strtab_size = 0
            f.seek(elf_shoff)

            for i in range(elf_shnum):
                shdr = f.read(64)
                sh_type = struct.unpack("I", shdr[4:8])[0]
                if sh_type == 2:
                    symtab_offset = struct.unpack("Q", shdr[24:32])[0]
                    symtab_size = struct.unpack("Q", shdr[32:40])[0]
                elif sh_type == 3 and i != elf_shstrndx:
                    strtab_offset = struct.unpack("Q", shdr[24:32])[0]
                    strtab_size = struct.unpack("Q", shdr[32:40])[0]

            # Read the symbol table
            f.seek(symtab_offset)
            symtab = f.read(symtab_size)

            # Read the string table
            f.seek(strtab_offset)
            strtab = f.read(strtab_size)

        for i in range(symtab_size // 24):
            sym_data = symtab[i*24 : (i+1)*24]
            sym = struct.unpack("IBBHQQ", sym_data)
            if sym[1] & 0xf != 1: # STT_OBJECT
                continue

            name = strtab[sym[0]:]
            name = name[:name.find(b'\0')].decode('ascii')
            self.symbols[name] = sym[4] + self.base_addr

    def __call__(self, name):
        try:
            return self.symbols[name]
        except Exception as e:
            raise Exception("failed to get address of symbol '%s': " % name)


class ProcMem(object):
    def __init__(self, pid):
        mem_path = os.path.join('/proc', str(pid), 'mem')
        self.mem_fp = open(mem_path, 'rb')

    def read(self, addr, size):
        try:
            self.mem_fp.seek(addr)
            data = self.mem_fp.read(size)
            return data
        except Exception:
            raise Exception("read memory 0x%x-0x%x failed" %
                            (addr, addr + size))


class Dumper(object):
    HELP = """
    value = dumper.eval(expression)
        Evaluate the expression, and return the value.

        expression: expression in C style. '.', '->', '[]', '()' and typecast are supported.
                    e.g.: '((struct net)init_net).ipv4.fib_main->tb_data'
        value: a variable instance, could be a number, array, pointer, struct, or their complexes.

    print(value)
        Pretty print the value.

    addr = value.addr
        Get the address of the value.

    type = value.type
        Get the type of the value.

    size = value.type.size
        Get the size of the value.

    type = dumper.get_type(type_str)
        Get the type from string.
        type_str: a string to descript the type.
                  e.g.: 'struct net_device*'

    value = type(addr=addr)
        Get the value with specified type and address.

    value2 = value.cast(new_type_str)
    assert value.addr == value2.addr
        Transform value to another type

    number = int(value) if isintance(value, Int.Value) else None
        Get the number from the Int value.

    address = int(value) if isintance(value, Ptr.Value) else None
        Get the address where the pointer refers to.

    value = value.value if isintance(value, Ptr.Value) else None
        Get the value where the pointer refers to.

    ptr = value.pointer
    assert isinstance(ptr, Ptr.Value)
    assert ptr.value.addr == value.addr
        Get a pointer which refers to the value.

    value = value[0] if isintance(value, Array.Value) else None
        Get the first element of the array.

    value = value.member_name if insintance(value, Struct.Value) else None
    assert value == (value.get('member_name') if insintance(value, Struct.Value) else None)
        Get the member of the struct.

    values = [ m for m in value ] if insintance(value, Struct.Value) else []
        Get all the members of the struct.

    offset = value.type.member_name.offset if insintance(value, Struct.Value) else None
    assert offset == (value.type.get('member_name').offset if insintance(value, Struct.Value) else None)
        Get the offset of the member.

    values = [ v for v in dumper.list(first_ptr_or_str, container_type_or_str, list_member_str) ]
        Iterate a list or hlist.
        e.g.:
            [ str(dev.name) for dev in dumper.list('((struct net) init_net).dev_base_head.next', 'struct net_device', 'dev_list') ]
    """

    def __init__(self, fmt=None, mem_reader=None, sym_searcher=None,
                 btf_path=DEFAULT_BTF_PATH, cache_dir=DEFAULT_CACHE_DIR):
        def value_init_handle(value):
            def cast(type):
                if isinstance(type, str):
                    type = self.get_type(type)
                return value._cast(type)
            value.cast = cast

            def container_of(type, member):
                return self.container_of(value, type, member)
            value.container_of = container_of

        self.sym_searcher = sym_searcher or KernelSym()
        mem_reader = mem_reader or CoreMem()
        self.arch_size = 8
        if platform.architecture()[0] == '32bit':
            self.arch_size = 4

        path_list = btf_path if isinstance(btf_path, list) else [btf_path]
        self.btfs = [BTF(btf_path=path,
                         mem_reader=mem_reader,
                         fmt=(fmt or FormatOpt()),
                         cache_dir=cache_dir,
                         value_init_hook=value_init_handle
                        ) for path in path_list]

    @log_call
    def get_type(self, typecast):
        type = None
        if isinstance(typecast, str):
            typecast = Parser(Lexer('(%s)a' % typecast)).parse()

        for btf in self.btfs:
            if typecast.new_type == 'void':
                type = Void(type.btf, '')
                break

            if typecast.keyword == 'struct':
                try:
                    type = btf[(BTF.KIND_STRUCT, typecast.new_type)]
                except KeyError:
                    continue
            elif typecast.keyword == 'union':
                try:
                    type = btf[(BTF.KIND_UNION, typecast.new_type)]
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

        if type is None:
            raise Exception(
                "can't find type %s %s" % (typecast.keyword, typecast.new_type))

        for idx in typecast.indexes:
            type = Array(type.btf, '', type, idx)

        for _ in range(typecast.ref_level):
            type = Ptr(type.btf, '', type)

        return type

    @log_call
    def _eval(self, expr):
        if isinstance(expr, Typecast):
            return self._eval(expr.variable)._cast(self.get_type(expr))

        elif isinstance(expr, Access):
            val = self._eval(expr.variable)
            if not val.type.is_kind(BTF.KIND_STRUCT) and \
                not val.type.is_kind(BTF.KIND_UNION):
                raise Exception("type of '%s' is '%s', neither struct nor union, "
                                "'.' is not allowed" % (expr.variable, val.type))
            return val.get(expr.member)

        elif isinstance(expr, Dereference):
            val = self._eval(expr.variable)
            if not val.type.is_kind(BTF.KIND_PTR):
                raise Exception("type of '%s' is '%s', not a pointer, "
                                "'%s' is not allowed" %
                                (expr.variable, val.type,
                                '->' if expr.member else '*'))
            val = val.value
            if expr.member:
                if not val.type.is_kind(BTF.KIND_STRUCT) and \
                    not val.type.is_kind(BTF.KIND_UNION):
                    raise Exception("type of '*(%s)' is '%s', "
                                    "neither struct nor union, "
                                    "'->' is not allowed" %
                                    (expr.variable, val.type))
                val = val.get(expr.member)
            return val

        elif isinstance(expr, Index):
            val = self._eval(expr.variable)
            if not val.type.is_kind(BTF.KIND_ARRAY) and \
                not val.type.is_kind(BTF.KIND_PTR):
                raise Exception("type of '%s' is '%s', neither pointer "
                                "nor array, index is not allowed" %
                                (expr.variable, val.type))
            if val.type.is_kind(BTF.KIND_PTR):
                val = val.value._cast(
                    Array(val.btf, '', val.type.ref, expr.index + 1))
            return val[expr.index]

        elif isinstance(expr, Symbol):
            addr = self.sym_searcher(expr.value)
            type = Void(self.btfs[0], 'unknown')
            return type(addr=addr)

        elif isinstance(expr, Number):
            if expr.value < 0:
                type = Int(self.btfs[0], 'long', 8, signed=True)
                return type(data=struct.pack('q', expr.value))
            else:
                type = Int(self.btfs[0], 'unsigned long', 8, signed=False)
                return type(data=struct.pack('Q', expr.value))

        raise Exception("unsupported expression: %s" % expr)

    def eval(self, expr):
        if isinstance(expr, str):
            expr = Parser(Lexer(expr)).parse()

        val = self._eval(expr)
        if val.type.is_kind(BTF.KIND_VOID):
            raise Exception("type of '%s' is not unknown" % expr)

        return val

    def dump(self, expr):
        value = self.eval(expr)
        return "%s = %s;" % (expr, str(value))

    def container_of(self, value, type, member):
        if isinstance(value, str):
            value = self.eval(value)

        if isinstance(type, str):
            type = self.get_type(type)

        if value.addr is None:
            raise Exception("unknown address of %s" % repr(value))

        addr = value.addr - type.get(member).offset
        return type(addr=addr)

    def list(self, first_ptr, type, member):
        if isinstance(first_ptr, str):
            first_ptr = self.eval(first_ptr)

        if isinstance(type, str):
            type = self.get_type(type)

        pos = first_ptr
        while int(pos) and int(pos) != first_ptr.addr:
            value = self.container_of(pos.value, type, member)
            pos = pos.next
            yield value

    def show_netdev(self):
        for dev in self.list('((struct net) init_net).dev_base_head.next',
                'struct net_device', 'dev_list'):
            print("%s @ 0x%x" % (dev.name, dev.addr))


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
            append_err(e, "parse '%s' failed: " % expression)
            reraise(*sys.exc_info())

    while True:
        txt = ''
        for info in expr_list:
            try:
                value = dumper.eval(info['expr'])
                if value.data != info['last_data']:
                    txt += ("%s = %s;\n" % (info['expr'], str(value)))
                    info['last_data'] = value.data
            except Exception as e:
                if len(expression_list) == 1 and watch_interval is None:
                    append_err(e, "dump '%s' failed: " % info['expr'])
                    reraise(*sys.exc_info())
                else:
                    log_exception()

                if info['last_data'] != '':
                    txt += ("Error: %s: %s\n" % (info['expr'], err_txt(e)))
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


if __name__ == '__main__':
    epilog = """examples:
    * dump the structure in process 'prog' which 'var' refers to:
        %(prog)s -p `pidof prog` -t ./prog.btf '*(struct foo *)var'
    * dump the header of kernel route table:
        %(prog)s '*((struct net)init_net).ipv4.route_hdr'
    * list net devices:
        %(prog)s netdev
    * dump the net device at specified address:
        %(prog)s '*(struct net_device*)0xffff8d4260214000'
    * enter interactive shell:
        python -i %(prog)s -t ./vmlinux.btf
    * list net namespaces:
        python -c "from kvardump import *; print([str(net.ns.inum) for net in Dumper().list('((struct list_head)net_namespace_list).next', 'struct net', 'list')])"
    """ % {'prog': sys.argv[0]}
    parser = argparse.ArgumentParser(
        description='Dump global variables in kernel or a process.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog)
    parser.add_argument('expression', type=str, nargs='*',
                        help='expression in C style with typecast')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='show debug information')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='suppress log')
    parser.add_argument('-p', '--pid', type=int,
                        help='target process ID, '
                            'dump variables in kernel if pid is not specified')
    parser.add_argument('-e', '--elf-path',
                        help='elf path to read symbols, '
                             '`readlink /proc/$pid/exe` by default')
    parser.add_argument('-t', '--btf-paths', type=str,
                        help='BTF paths, separated by ",", '
                        '%s by default.' % DEFAULT_BTF_PATH)
    parser.add_argument('-c', '--cache-dir', type=str,
                        help='directory to save cache, set empty to disable cache',
                        default=DEFAULT_CACHE_DIR)
    parser.add_argument('-x', '--hex-string', action='store_true',
                        help='dump byte array in hex instead of string')
    parser.add_argument('-a', '--array-max', type=int, default=0,
                        help='maximum number of array elements to display')
    parser.add_argument('-s', '--string-max', type=int, default=0,
                        help='maximum string length to display')
    parser.add_argument('-w', '--watch-interval', type=float,
                        help='check the expression value every WATCH_INTERVAL '
                             'seconds and dump it when it changes')
    args = parser.parse_args()

    verbose = args.verbose
    quiet = args.quiet
    array_max = args.array_max if args.array_max > 0 else DEFAULT_ARRAY_MAX
    string_max = args.string_max if args.string_max > 0 else DEFAULT_STRING_MAX
    array_max_force = bool(args.array_max > 0)
    string_max_force = bool(args.string_max > 0)
    fmt = FormatOpt(array_max=array_max, array_max_force=array_max_force,
                    hex_string=args.hex_string, string_max=string_max,
                    string_max_force=string_max_force)

    try:
        if args.pid:
            sym_searcher = ElfSym(args.pid, elf_path=args.elf_path)
            mem_reader = ProcMem(args.pid)
            if not args.btf_paths:
                raise Exception("BTF path must be specified")
        else:
            sym_searcher = KernelSym()
            mem_reader = CoreMem()
            args.btf_paths = args.btf_paths or DEFAULT_BTF_PATH

        dumper = Dumper(btf_path=args.btf_paths.split(','),
                        fmt=fmt, cache_dir=args.cache_dir,
                        sym_searcher=sym_searcher, mem_reader=mem_reader)

        if sys.flags.interactive:
            print("type 'print(dumper.HELP)' to see help message")

        if not args.expression and not sys.flags.interactive:
            parser.print_help()
            raise Exception("expression must be specified")
        elif len(args.expression) == 1 and args.expression[0] in ('netdev', 'net'):
            dumper.show_netdev()
        else:
            do_dump(dumper, args.expression, args.watch_interval)
    except Exception as e:
        log_error("%s" % err_txt(e))
        if verbose:
            reraise(*sys.exc_info())
        exit(1)
