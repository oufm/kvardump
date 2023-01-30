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
import subprocess
import argparse
import select
import platform
import struct
import functools
import traceback

DEFAULT_ARRAY_MAX = 5
DEFAULT_STRING_MAX = 64

verbose = False
# verbose = True
log_nest_level = 0


if sys.version_info[0] >= 3:
    def reraise():
        exc_info = sys.exc_info()
        raise exc_info[1].with_traceback(exc_info[2])
else:
    exec("def reraise():\n"
         "    exc_info = sys.exc_info()\n"
         "    raise exc_info[0], exc_info[1], exc_info[2]\n")


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
    # v = str(value)
    # if len(v) > 50:
    #     v = v[:50]
    # print("indent %d, value: %s" % (indent, v))
    # if max_depth and indent >= max_depth:
    #     return '...'
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
            reraise()
        else:
            cache_dict[param_tuple] = copy.deepcopy(cache_value)
        return cache_value

    return _func


class BTF(object):
    BTF_HEADER_LEN = 24
    BTF_TYPE_LEN = 12
    BTF_ARRAY_LEN = 12
    BTF_MEMBER_LEN = 12
    BTF_ENUM_LEN = 8
    BTF_ARG_LEN = 8

    BTF_KIND_INT = 1
    BTF_KIND_PTR = 2
    BTF_KIND_ARRAY = 3
    BTF_KIND_STRUCT = 4
    BTF_KIND_UNION = 5
    BTF_KIND_ENUM = 6
    BTF_KIND_FWD = 7
    BTF_KIND_TYPEDEF = 8
    BTF_KIND_VOLATILE = 9
    BTF_KIND_CONST = 10
    BTF_KIND_RESTRICT = 11
    BTF_KIND_FUNC = 12
    BTF_KIND_FUNC_PROTO = 13
    BTF_KIND_VAR = 14
    BTF_KIND_DATASEC = 15

    def __init__(self, path):
        self.arch_size = 8
        if platform.architecture()[0] == '32bit':
            self.arch_size = 4

        if os.path.exists('/tmp/kvardump_cache.json'):
            with open('/tmp/kvardump_cache.json', 'r') as f:
                obj = json.load(f)
                self.decoded_types = obj['decoded_types']
                self.name_map = obj['name_map']
            return

        with open(path, 'rb') as f:
            self.data = f.read()

        header = struct.unpack('HBBIIIII', self.data[0:self.BTF_HEADER_LEN])
        self.magic = header[0]
        self.version = header[1]
        self.flags = header[2]
        self.hdr_len = header[3]
        self.type_off = header[4]
        self.type_len = header[5]
        self.str_off = header[6]
        self.str_len = header[7]
        self.data = self.data[self.hdr_len:]

        if (self.type_off + self.type_len > len(self.data)):
            raise Exception("invalid BTF, may be truncated")

        if (self.str_off + self.str_len > len(self.data)):
            raise Exception("invalid BTF, may be truncated")

        if self.magic != 0xeb9f:
            raise Exception("invalid BTF file, wrong magic: 0x%x" % self.magic)

        self.str_data = self.data[self.str_off:self.str_off+self.str_len]
        self.type_data = self.data[self.type_off:self.type_off+self.type_len]
        # type ID start from 1
        self.decoded_types = [{}]
        self.name_map = {}

        pos = 0
        while pos + self.BTF_TYPE_LEN < len(self.type_data):
            btf_type = struct.unpack(
                "III", self.type_data[pos:pos+self.BTF_TYPE_LEN])
            pos += self.BTF_TYPE_LEN

            name_off = btf_type[0]
            info = btf_type[1]
            size = type = btf_type[2]
            vlen = info & 0xffff
            kind = (info >> 24) & 0xf
            kind_flag = info >> 31
            name = self.get_name(name_off)
            decoded = {"name": name, "kind": kind}

            if kind == self.BTF_KIND_INT:
                if pos + 4 >= len(self.type_data):
                    raise Exception(
                        "invalid BTF, 0x%x reaches the end of type data" % pos)

                info = struct.unpack("I", self.type_data[pos:pos+4])[0]
                pos += 4

                decoded.update({
                    'kind': kind,
                    'size': size,
                    'signed': (info & 0x01000000) != 0,
                    'char': (info & 0x02000000) != 0,
                    'bool': (info & 0x04000000) != 0,
                    'offset': (info >> 16) & 0xff,
                    'bits': info >> 16,
                })
            elif kind in {
                self.BTF_KIND_PTR,
                self.BTF_KIND_TYPEDEF,
                self.BTF_KIND_VOLATILE,
                self.BTF_KIND_CONST,
                self.BTF_KIND_RESTRICT,
                }:
                decoded.update({
                    'kind': kind,
                    'type': type,
                })
            elif kind == self.BTF_KIND_ARRAY:
                if pos + self.BTF_ARRAY_LEN >= len(self.type_data):
                    raise Exception(
                        "invalid BTF, 0x%x reaches the end of type data" % pos)

                info = struct.unpack(
                    "III", self.type_data[pos:pos+self.BTF_ARRAY_LEN])
                pos += self.BTF_ARRAY_LEN
                decoded.update({
                    'kind': kind,
                    'type': info[0],
                    'nelems': info[2],
                })
            elif kind == self.BTF_KIND_STRUCT or kind == self.BTF_KIND_UNION:
                if pos + vlen * self.BTF_MEMBER_LEN >= len(self.type_data):
                    raise Exception(
                        "invalid BTF, 0x%x reaches the end of type data" % pos)

                decoded.update({
                    'kind': kind,
                    'vlen': vlen,
                    'size': size,
                    'members': [],
                })

                for i in range(vlen):
                    info = struct.unpack(
                        "III", self.type_data[pos:pos+self.BTF_MEMBER_LEN])
                    pos += self.BTF_MEMBER_LEN
                    decoded['members'].append({
                        'name': self.get_name(info[0]),
                        'type': info[1],
                        'offset': info[2] & 0xffffff,
                        'size': info[2] >> 24,
                    })
            elif kind == self.BTF_KIND_ENUM:
                if pos + vlen * self.BTF_ENUM_LEN >= len(self.type_data):
                    raise Exception(
                        "invalid BTF, 0x%x reaches the end of type data" % pos)

                decoded.update({
                    'kind': kind,
                    'vlen': vlen,
                    'size': size,
                    'members': [],
                })

                for i in range(vlen):
                    info = struct.unpack(
                        "Ii", self.type_data[pos:pos+self.BTF_ENUM_LEN])
                    pos += self.BTF_ENUM_LEN
                    decoded['members'].append({
                        'name': self.get_name(info[0]),
                        'val': info[1],
                    })
            elif kind == self.BTF_KIND_FWD:
                decoded.update({
                    'kind': self.BTF_KIND_UNION \
                        if kind_flag else self.BTF_KIND_STRUCT,
                    'vlen': 0,
                    'size': 0,
                    'members': [],
                })
            elif kind == self.BTF_KIND_FUNC_PROTO:
                if pos + vlen * self.BTF_ARG_LEN >= len(self.type_data):
                    raise Exception(
                        "invalid BTF, 0x%x reaches the end of type data" % pos)

                decoded.update({
                    'kind': kind,
                    'vlen': vlen,
                    'type': type,
                    'args': [],
                })

                pos += self.BTF_ARG_LEN * vlen
                # for i in range(vlen):
                #     info = struct.unpack(
                #         "II", self.type_data[pos:pos+self.BTF_ARG_LEN])
                #     pos += self.BTF_ARG_LEN
                #     decoded['args'].append({
                #         'name': self.get_name(info[0]),
                #         'type': info[1],
                #     })
            elif kind == self.BTF_KIND_FUNC:
                pass
            elif kind == self.BTF_KIND_VAR:
                pos += 4
                # import pdb
                # pdb.set_trace()
            elif kind == self.BTF_KIND_DATASEC:
                pos += 12 * vlen

            self.name_map['%d.%s' % (kind, name)] = len(self.decoded_types)
            self.decoded_types.append(decoded)

        with open('/tmp/kvardump_cache.json', 'w') as f:
            json.dump({'name_map': self.name_map,
                'decoded_types': self.decoded_types}, f)

    def get_name(self, off):
        if off >= len(self.str_data):
            raise Exception("invalid BTF file, invalid name offset: 0x%x" % off)

        end = self.str_data[off:].find(b'\x00')
        if end < 0:
            raise Exception("invalid BTF file, invalid string at 0x%x" % off)

        return self.str_data[off:off+end].decode('ascii')

    # @log_arg_ret
    def assemble_type(self, type_info):
        if type_info.get('kind', None) == self.BTF_KIND_PTR:
            return type_info

        # type = type_info.get('type', None)
        # if type is not None and :
        if 'type' in type_info and 'type_obj' not in type_info:
            type = type_info.pop('type')
            type_info['type_obj'] = \
                self.assemble_type(self.decoded_types[type])
            type_info['type'] = type

        members = type_info.get('members', [])
        for m in members:
            self.assemble_type(m)
        # if members is not None:
        #     members_objs = []
        #     for m in members: 
        #         members_objs.append(self.assemble_type(m))
        #     type_info['members'] = members_objs

        return type_info

    def get_type(self, kind, name):
        type_id = self.name_map['%d.%s' % (kind, name)]
        type_info = self.decoded_types[type_id]
        return self.assemble_type(type_info)

    def dereference_type(self, type_info):
        # if type_info['kind'] != self.BTF_KIND_PTR:
        #     raise Exception("type of '%s' is not pointer", type_info)
        if 'type_obj' not in type_info:
            ref_type_id = type_info['type']
            ref_type_info = self.decoded_types[ref_type_id]
            type_info['type_obj'] = self.assemble_type(ref_type_info)

        return type_info['type_obj']

    @log_arg_ret
    def get_type_size(self, type_info):
        if type_info['kind'] in {self.BTF_KIND_PTR, self.BTF_KIND_FUNC_PROTO}:
            return self.arch_size
        elif type_info['kind'] == self.BTF_KIND_ARRAY:
            return type_info['nelems'] * self.get_type_size(type_info['type_obj'])
        elif type_info['kind'] in {
            self.BTF_KIND_INT,
            self.BTF_KIND_STRUCT,
            self.BTF_KIND_UNION,
            self.BTF_KIND_ENUM,
            }:
            return type_info['size']
        elif type_info['kind'] in {
            self.BTF_KIND_TYPEDEF,
            self.BTF_KIND_VOLATILE,
            self.BTF_KIND_CONST,
            self.BTF_KIND_RESTRICT
            }:
            return self.get_type_size(type_info['type_obj'])
        else:
            return 0

def get_symbol_addr(name):
    output = subprocess.check_output(
        "cat /proc/kallsyms | grep -w %s | awk '{print $1}'" % name,
        shell=True)
    return int('0x' + output, base=0)

class KernelMem(object):
    def __init__(self):
        self.segs = []
        self.kcore = open('/proc/kcore', 'rb')

        output = subprocess.check_output(
            "objdump -h /proc/kcore  | grep load | awk '{print $3,$4,$6}'",
            shell=True)

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
                print(
                    "     0x%x ~ 0x%x @ 0x%x" % (
                        self.segs[-1]['vma'],
                        self.segs[-1]['vma'] + self.segs[-1]['len'],
                        self.segs[-1]['off']),
                        file=sys.stderr)

    def read(self, addr, len):
        off = None
        for s in self.segs:
            if addr >= s['vma'] and (addr + len) <= s['vma'] + s['len']:
                off = s['off'] + (addr - s['vma'])
                break

        if not off:
            raise Exception(
                "invalid virtual address 0x%x~0x%x" % (addr, addr + len))

        self.kcore.seek(off)
        return self.kcore.read(len)

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


class Struct(Token):
    def __str__(self):
        return 'struct'


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
                return Struct()
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

    def btf_type(self, btf):
        if self.keyword == 'struct':
            try:
                type = btf.get_type(btf.BTF_KIND_STRUCT, self.new_type)
            except KeyError:
                raise Exception("can't find struct '%s'" % self.new_type)
        else:
            try:
                type = btf.get_type(btf.BTF_KIND_INT, self.new_type)
            except KeyError:
                try:
                    type = btf.get_type(btf.BTF_KIND_TYPEDEF, self.new_type)
                except KeyError:
                    raise Exception("can't find symbol '%s'" % self.new_type)

        for idx in self.indexes:
            type = {'kind': btf.BTF_KIND_ARRAY, 'nelems': idx, 'type_obj': type}

        for i in range(self.ref_level):
            type = {'kind': btf.BTF_KIND_PTR, 'type_obj': type}

        return type

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
                if isinstance(token, Struct):
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


# def read_timeout(fp, timeout, size=1024*1024):
#     r, _, _ = select.select([fp], [], [], timeout)
#     if fp not in r:
#         return b''

#     return os.read(fp.fileno(), size)


# class GdbShell(object):
#     PROMPT = '(gdb)'

#     def __init__(self, elf_path):
#         self.gdb = subprocess.Popen('gdb ' + elf_path, shell=True,
#                                     stdin=subprocess.PIPE,
#                                     stdout=subprocess.PIPE,
#                                     stderr=subprocess.PIPE, bufsize=1)

#         output, err = self._read_output(timeout=5)
#         if self.PROMPT not in output:
#             raise Exception('gdb init failed, path: %s\n'
#                             '----- stdout -----\n%s\n'
#                             '----- stderr -----\n%s' %
#                             (elf_path, output, err))
#         self.run_cmd('print "hello"')

#     def __del__(self):
#         gdb = getattr(self, 'gdb', None)
#         if not gdb:
#             return

#         gdb.kill()
#         gdb.wait()

#     def _read_output(self, timeout=1):
#         output = read_timeout(self.gdb.stdout, timeout).decode()
#         output_all = ''
#         while output:
#             output_all += output
#             if self.PROMPT in output:
#                 break
#             output = read_timeout(self.gdb.stdout, timeout).decode()

#         err_str = read_timeout(self.gdb.stderr, 0).decode()

#         return output_all, err_str

#     @cache_result
#     @log_arg_ret
#     def run_cmd(self, cmd):
#         self.gdb.stdin.write((cmd + '\n').encode())
#         self.gdb.stdin.flush()
#         output, err = self._read_output()
#         lines = output.splitlines()
#         if self.PROMPT not in output or err or len(lines) <= 1:
#             raise Exception('run gdb command "%s" failed\n'
#                             '----- stdout -----\n%s\n'
#                             '----- stderr -----\n%s' %
#                             (cmd, output, err))

#         return '\n'.join(lines[:-1])


class Dumper(object):
    BLANK = '    '

    def __init__(self, # pid,
                 array_max=DEFAULT_ARRAY_MAX, string_max=DEFAULT_STRING_MAX,
                 array_max_force=False, string_max_force=False,
                 hex_string=False, elf_path=None):
        # exe = os.readlink(
        #         os.path.join('/proc', str(pid), 'exe'))
        self.array_max = array_max
        self.string_max = string_max
        self.array_max_force = array_max_force
        self.string_max_force = string_max_force
        self.hex_string = hex_string
        # self.elf_path = exe
        # if elf_path:
        #     self.elf_path = elf_path
        # if not os.access(self.elf_path, os.R_OK):
        #     raise Exception("can't read '%s', "
        #                     "you can pass '-e ELF_PATH' to solve it" %
        #                     self.elf_path)

        # mem_path = os.path.join('/proc', str(pid), 'mem')
        # self.mem_fp = open(mem_path, 'rb')
        # maps = open(os.path.join('/proc', str(pid), 'maps')).read()
        # self.base_addr = int([line for line in maps.splitlines()
        #                       if exe in line][0].split('-')[0], base=16)
        # # for non-PIE executable, see: https://stackoverflow.com/a/73189318/18251455
        # if self.base_addr == 0x400000:
        #     self.base_addr = 0

        # self.gdb_shell = GdbShell(self.elf_path)
        self.kernel_mem = KernelMem()
        self.btf = BTF('/home/u/sysak/source/tools/combine/btf/vmlinux-btf/vmlinux-5.19.0-1.1.an23.x86_64')
        self.arch_size = 8
        if platform.architecture()[0] == '32bit':
            self.arch_size = 4

    # @log_arg_ret
    # def simplify_type(self, type_info):
    #     simplified_str = type_info.strip()
    #     if simplified_str[0] == '(':
    #         if simplified_str[-1] != ')':
    #             raise Exception("parentheses not enclosed: '%s'" % type_info)
    #         simplified_str = simplified_str[1:-1]

    #     match = re.match(r'^\s*(static\s|const\s)+', simplified_str)
    #     if match:
    #         group1, = match.groups()
    #         if group1:
    #             simplified_str = simplified_str.replace(group1, '')

    #     return simplified_str

    # @cache_result
    @log_arg_ret
    def get_member_offset_and_type(self, type_info, member):
        # output = self.gdb_shell.run_cmd('ptype ' + type_info)
        # # example: '   struct _43rdewd ** _4rmem[43][5]'
        # pattern = r'^\s*((\w+\s)?\w+(\s*\*+)?)\s*' + member + r'((\[\d+\])*);'
        # match = re.match(pattern, output)
        # if not match or not match.group(1):
        #     raise Exception("type '%s' has no member '%s', ptype: %s" %
        #                     (type_info, member, output))
        # member_type = match.group(1) + (match.group(4) if match.group(4) else '')
        # TODO delete
        try:
            for m in type_info['members']:
                if m['name'] == member:
                    # TODO bitfield
                    return m['offset']/8, m['type_obj']
            # output = self.gdb_shell.run_cmd('p &((%s *)0)->%s' %
            #                                 (type_info, member))
            # pos1 = output.index('=')
            # pos2 = output.index('0x')
            # member_type = self.simplify_type(output[pos1 + 1:pos2])
            # offset_str = output[pos2:].strip().split()[0]
            # member_offset = int(offset_str, 0)
            # return member_offset, self.dereference_type(member_type)[0]
        except Exception as e:
            append_err_txt(e, "failed to get offset(%s, %s): " %
                           (type_info, member))
            reraise()

    # @cache_result
    @log_arg_ret
    def get_symbol_address_and_type(self, symbol_str):
        try:
            return get_symbol_addr(symbol_str), None
            # output = self.gdb_shell.run_cmd('p &%s' % symbol_str)
            # pos1 = output.index('=')
            # pos2 = output.index('0x')
            # symbol_type = self.simplify_type(output[pos1 + 1:pos2])
            # symbol_offset = int(output[pos2:].strip().split()[0], 0)
            # return symbol_offset + self.base_addr, \
            #     self.dereference_type(symbol_type)[0]
        except Exception as e:
            append_err_txt(e, "failed to get address of symbol '%s': " %
                           symbol_str)
            reraise()

    # @cache_result
    # @log_arg_ret
    # def get_type_size(self, type_info):
    #     try:
    #         output = self.gdb_shell.run_cmd('p sizeof(%s)' % type_info)
    #         pos = output.index('=')
    #         return int(output[pos + 1:].strip().split()[0], 0)
    #     except Exception as e:
    #         append_err_txt(e, "failed to get size of '%s': " % type_info)
    #         reraise()

    @log_arg_ret
    def dereference_addr(self, address):
        # self.mem_fp.seek(address)
        try:
            data = self.kernel_mem.read(address, self.arch_size)
            # data = self.mem_fp.read(self.arch_size)
        except Exception:
            raise Exception("read at address 0x%x failed" % address)

        return struct.unpack('P', data)[0]

    # @cache_result
    # @log_arg_ret
    # def dereference_type(self, type_info):

    #     # remove a '(*)' or '[\d+]' or '*'
    #     if '(*)' in type_info:
    #         return type_info.replace('(*)', '', 1).strip(), '(*)'

    #     # example: 'struct _43rdewd ** [43] [5]'
    #     match = re.match(r'^(\w+\s+)?\w+\s*(\*)*\s*(\[\d*\])?', type_info)
    #     if match:
    #         _, group2, group3 = match.groups()
    #         if group3:
    #             return type_info.replace(group3, '', 1).strip(), group3
    #         elif group2:
    #             return type_info.replace(group2, '', 1).strip(), group2
    #     raise Exception("type '%s' is neither array nor pointer, "
    #                     "can't dereference it" % type_info)

    def simplify_type(self, type_info):
        if type_info['kind'] in {
            self.btf.BTF_KIND_TYPEDEF,
            self.btf.BTF_KIND_VOLATILE,
            self.btf.BTF_KIND_CONST,
            self.btf.BTF_KIND_RESTRICT
            }:
            return self.simplify_type(type_info['type_obj'])
        return type_info

    @log_arg_ret
    def get_addr_and_type(self, expr):
        if isinstance(expr, Typecast):
            addr, _ = self.get_addr_and_type(expr.variable)
            return addr, self.simplify_type(expr.btf_type(self.btf))

        elif isinstance(expr, Access):
            addr, type_info = self.get_addr_and_type(expr.variable)
            if not type_info:
                raise Exception("type of '%s' is not specified" %
                                expr.variable)

            if type_info['kind'] not in {
                self.btf.BTF_KIND_STRUCT, self.btf.BTF_KIND_UNION}:
                raise Exception("type of '%s' is '%s', neither struct nor union, "
                                "'.' is not allowed" %
                                (expr.variable, type_info))

            offset, type_info = self.get_member_offset_and_type(
                type_info, expr.member)
            return addr + offset, self.simplify_type(type_info)

        elif isinstance(expr, Dereference):
            addr, type_info = self.get_addr_and_type(expr.variable)
            if not type_info:
                raise Exception("type of '%s' is not specified" %
                                expr.variable)
            if type_info['kind'] == self.btf.BTF_KIND_ARRAY:
                raise Exception("type of '%s' is '%s', which is an array, "
                                "not a pointer, '%s' is not allowed" %
                                (expr.variable, type_info,
                                 '->' if expr.member else '*'))
            if type_info['kind'] == self.btf.BTF_KIND_PTR:
                if expr.member:
                    raise Exception("type of '%s' is '%s', '.' "
                                    "should be used instead of '->'" %
                                    (expr.variable, type_info))
                else:
                    raise Exception("type of '%s' is '%s', not a pointer, "
                                    "'*' is not allowed" %
                                    (expr.variable, type_info))
            type_info = self.btf.dereference_type(type_info)
            type_info = self.simplify_type(type_info)
            addr = self.dereference_addr(addr)
            offset = 0
            if expr.member:
                offset, type_info = self.get_member_offset_and_type(
                    type_info, expr.member)
            return addr + offset, self.simplify_type(type_info)

        elif isinstance(expr, Index):
            addr, type_info = self.get_addr_and_type(expr.variable)
            if not type_info:
                raise Exception("type of '%s' is not specified" %
                                expr.variable)
            if type_info['kind'] not in {
                self.btf.BTF_KIND_ARRAY, self.btf.BTF_KIND_PTR}:
            # if '*' not in type_info and '[' not in type_info:
                raise Exception("type of '%s' is '%s', neither pointer "
                                "nor array, index is not allowed" %
                                (expr.variable, type_info))

            # if type_info['kind'] == self.btf.BTF_KIND_PTR:
            #     addr = self.dereference_addr(addr)
            #     # ele_size = self.btf.get_type_size(type_info['type_obj'])

            type_info = self.btf.dereference_type(type_info)
            type_info = self.simplify_type(type_info)
            if type_info['kind'] == self.btf.BTF_KIND_PTR:
                # index a pointer instead of array
                addr = self.dereference_addr(addr)

            type_size = self.btf.get_type_size(type_info)
            return addr + type_size * expr.index, self.simplify_type(type_info)

        elif isinstance(expr, Symbol):
            return self.get_symbol_address_and_type(expr.value)

        elif isinstance(expr, Number):
            return expr.value, ''

    def dump_byte_array(self, data, array_len, indent):
        omit_tip = ''
        if (indent > 0 or self.string_max_force) and \
                array_len > self.string_max:
            data = data[:self.string_max]
            omit_tip = '...'

        if not self.hex_string:
            try:
                # dump as string if there is no unprintable character
                str_val = data.decode('ascii')
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

    def dump_array(self, data, element_type, array_len, indent):
        element_type = self.simplify_type(element_type)
        type_size = self.btf.get_type_size(element_type)
        omit_count = 0
        # if type_size == 1:
        if element_type['kind'] == self.btf.BTF_KIND_INT and \
                element_type['size'] == 1:
            return self.dump_byte_array(data, array_len, indent)

        # dump array in each line
        if (indent > 0 or self.array_max_force) and array_len > self.array_max:
            omit_count = array_len - self.array_max
            array_len = self.array_max

        indent += 1
        if element_type['kind'] == self.btf.BTF_KIND_INT:
            dump_txt = '{'
            sep = ' '
            before = ''
        else:
            dump_txt = '{\n'
            sep = '\n'
            before = indent * self.BLANK

        for i in range(array_len):
            dump_txt += before + self.dump_type(
                data[type_size * i: type_size * i + type_size],
                element_type, indent) + ',' + sep

        if omit_count:
            dump_txt += before + '/* other %s elements are omitted */%s' % (
                            omit_count, sep)
        indent -= 1
        if sep == '\n':
            dump_txt += indent * self.BLANK + '}'
        else:
            dump_txt += '}'
        return dump_txt

    def dump_basic_type(self, data, type_info):
        # data = data[0:type_info['size']]
        # print("dump basic, len %d, '%s', type: %s" % (len(data), data, type_info))

        if type_info['size'] == 1:
            if type_info['bool']:
                return 'true' if struct.unpack('B', data)[0] else 'false'
            elif type_info['signed']:
                val = struct.unpack('b', data)[0]
            else:
                val = struct.unpack('B', data)[0]

        elif type_info['size'] == 2:
            if type_info['signed']:
                val = struct.unpack('h', data)[0]
            else:
                val = struct.unpack('H', data)[0]

        elif type_info['size'] == 4:
            if type_info['signed']:
                val = struct.unpack('i', data)[0]
            else:
                val = struct.unpack('I', data)[0]

        elif type_info['size'] == 8:
            if type_info['signed']:
                val = struct.unpack('l', data)[0]
            else:
                val = struct.unpack('L', data)[0]

        else:
            return "ERROR /* invalid int size: %d */" % type_info['size']

        # TODO bitfield
        return str(val)
        # if 'char' in type_desc or '_Bool' in type_desc:
        #     if 'unsigned' in type_desc:
        #         return str(struct.unpack('B', data[0])[0])
        #     else:
        #         return str(struct.unpack('b', data[0])[0])
        # elif 'short' in type_desc:
        #     if 'unsigned' in type_desc:
        #         return str(struct.unpack('H', data[0:2])[0])
        #     else:
        #         return str(struct.unpack('h', data[0:2])[0])
        # elif 'int' in type_desc:
        #     if 'unsigned' in type_desc:
        #         return str(struct.unpack('I', data[0:4])[0])
        #     else:
        #         return str(struct.unpack('i', data[0:4])[0])
        # elif 'long' in type_desc:
        #     if 'unsigned' in type_desc:
        #         return str(struct.unpack('L', data[0:self.arch_size])[0])
        #     else:
        #         return str(struct.unpack('l', data[0:self.arch_size])[0])
        # else:
        #     return "ERROR /* unsupported type: '%s' */" % type_desc.strip()

    def dump_struct(self, data, type_info, indent):
        dump_txt = '{\n'
        indent += 1
        for m in type_info['members']:
            # if not line or '{' in line or '}' in line:
            #     continue
            m_name = m['name']
            try:
                m_off, m_type = self.get_member_offset_and_type(type_info, m_name)
                m_size = self.btf.get_type_size(m_type)
                if m_name:
                    dump_txt += indent * self.BLANK + '.' + m_name + ' = '
                elif m_type['kind'] == self.btf.BTF_KIND_STRUCT:
                    dump_txt += indent * self.BLANK + '/* nested anonymous struct */ '
                else:
                    dump_txt += indent * self.BLANK + '/* nested anonymous union */ '
                dump_txt += self.dump_type(data[m_off: m_off + m_size], m_type, indent)
                dump_txt += ',\n'
            except Exception:
                dump_txt += \
                    indent * self.BLANK + \
                    "// parse member '%s' of type '%s' failed\n" % \
                    (m_name, type_info['name'])
                log_exception()

            # line = self.simplify_type(line)
            # # example: '  struct _43rdewd *foo [43] [5];'
            # match = re.match(
            #     r'^\s*((\w+\s+)?\w+\s+\**)\s*(\w+)((\s*\[\d+\])*);', line)
            # if not match or not match.group(3):
            #     dump_txt += indent * self.BLANK + \
            #                 "// parse definition '%s' failed\n" % line.strip()
            # else:
            #     # member_type = (match.group(1) + match.group(4)).strip()
            #     member = match.group(3).strip()
            #     try:
            #         offset, member_type = self.get_member_offset_and_type(
            #             type_info, member)
            #         member_size = self.btf.get_type_size(member_type)
            #         dump_txt += indent * self.BLANK + '.' + member + ' = ' + \
            #             self.dump_type(data[offset: offset + member_size],
            #                            member_type, indent) + ',\n'
            #     except Exception:
            #         dump_txt += \
            #             indent * self.BLANK + \
            #             "// parse member '%s' of type '%s' failed\n" % \
            #             (member, type_info)
            #         log_exception()
        indent -= 1
        dump_txt += indent * self.BLANK + '}'
        return dump_txt

    def dump_type(self, data, type_info, indent=0):
        type_info = self.simplify_type(type_info)
        if type_info['kind'] in {
            self.btf.BTF_KIND_PTR, self.btf.BTF_KIND_FUNC_PROTO}:
            # print("dump pointer, len %d, '%s'" % (len(data[:self.arch_size]), data[:self.arch_size]))
            # dump pointer
            return '0x%x' % struct.unpack('P', data[:self.arch_size])[0]

        if type_info['kind'] == self.btf.BTF_KIND_ARRAY:
        # # example: 'struct _43rdewd ** [43] [5]'
        # match = re.match(r'^(\w+\s+)?\w+\s*(\*)*\s*\[(\d+)\]', type_info)
        # if match:
        #     # dump array
        #     type_info = type_info.replace('[%s]' % match.group(3), '')
            return self.dump_array(
                data, type_info['type_obj'], type_info['nelems'], indent)

        # if '*' in type_info:
        #     # dump pointer
        #     return '0x%x' % struct.unpack('P', data[:self.arch_size])[0]

        if type_info['kind'] == self.btf.BTF_KIND_INT:
            return self.dump_basic_type(data, type_info)
        # try:
        #     ptype = self.gdb_shell.run_cmd('ptype %s' % type_info)
        #     pos = ptype.index('=')
        #     ptype_lines = ptype[pos + 1:].strip().splitlines()
        # except Exception as e:
        #     append_err_txt(e, "failed to get type of '%s': " % type_info)
        #     reraise()

        # if len(ptype_lines) == 1:
        #     # dump basic type
        #     return self.dump_basic_type(data, ptype_lines[0])

        # dump struct
        if type_info['kind'] in {self.btf.BTF_KIND_STRUCT, self.btf.BTF_KIND_UNION}:
            return self.dump_struct(data, type_info, indent)

        return "ERROR /* unsupported type: '%d-%s' */" % \
            (type_info['kind'], type_info['name'])

    def get_data_and_type(self, expr):
        addr, type_info = self.get_addr_and_type(expr)
        if not type_info:
            raise Exception("type of '%s' is not specified" % expr)

        type_size = self.btf.get_type_size(type_info)
        # self.mem_fp.seek(addr)
        try:
            data = self.kernel_mem.read(addr, type_size)
            # data = self.mem_fp.read(type_size)
        except Exception as e:
            append_err_txt(e, "read memory failed: ")
            reraise()
        return data, type_info

    def dump(self, expr):
        data, type_info = self.get_data_and_type(expr)
        return "%s = %s;" % (expr, self.dump_type(data, type_info, indent=0))


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
            reraise()

    while True:
        txt = ''
        for info in expr_list:
            try:
                data, type_info = dumper.get_data_and_type(info['expr'])
                if data != info['last_data']:
                    txt += ("%s = %s;\n" %
                          (info['expr'], dumper.dump_type(data, type_info)))
                    info['last_data'] = data
            except Exception as e:
                if len(expression_list) == 1 and watch_interval is None:
                    append_err_txt(e, "dump '%s' failed: " % info['expr'])
                    reraise()
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


if __name__ == '__main__':
    epilog = """examples:
    * type of g_var1 is 'struct foo**', dump the third struct:
        %(prog)s `pidof prog` '*g_var1[2]'
    * type of g_var2 is 'struct foo*', dump the first 5 elements:
        %(prog)s `pidof prog` '(struct foo[5])*g_var2'
    * g_var3 points to a nested struct, dump the member:
        %(prog)s `pidof prog` 'g_var3->val.data'
    * there is a 'struct foo' at address 0x556159b32020, dump it:
        %(prog)s `pidof prog` '(struct foo)0x556159b32020'
    * check the expression values every 0.1s, dump them when the values change:
        %(prog)s -w 0.1 `pidof prog` '*g_var1[2]' '(struct foo[5])*g_var2'
    """ % {'prog': sys.argv[0]}
    parser = argparse.ArgumentParser(
        description='dump global variables of a living process without interrupting it',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog)
    parser.add_argument('pid', type=int, help='target process ID')
    parser.add_argument('expression', type=str, nargs='+',
                        help='rvalue expression in C style')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='show debug information')
    parser.add_argument('-x', '--hex-string', action='store_true',
                        help='dump byte array in hex instead of string')
    parser.add_argument('-e', '--elf-path',
                        help='elf path to read symbols, '
                             '`readlink /proc/$pid/exe` by default')
    parser.add_argument('-a', '--array-max', type=int, default=0,
                        help='maximum number of array elements to display')
    parser.add_argument('-s', '--string-max', type=int, default=0,
                        help='maximum string length to display')
    parser.add_argument('-w', '--watch-interval', type=float,
                        help='check the expression value every WATCH_INTERVAL '
                             'seconds and dump it when it changes')
    args = parser.parse_args()

    verbose = args.verbose
    array_max = args.array_max if args.array_max > 0 else DEFAULT_ARRAY_MAX
    string_max = args.string_max if args.string_max > 0 else DEFAULT_STRING_MAX
    array_max_force = bool(args.array_max > 0)
    string_max_force = bool(args.string_max > 0)

    try:
        dumper = Dumper(#pid=args.pid,
                        elf_path=args.elf_path,
                        array_max=array_max, array_max_force=array_max_force,
                        hex_string=args.hex_string, string_max=string_max,
                        string_max_force=string_max_force)
        do_dump(dumper, args.expression, args.watch_interval)
    except Exception as e:
        print("Error: %s" % get_err_txt(e), file=sys.stderr)
        if verbose:
            reraise()
        exit(1)
