module Wasm

using Printf

INFO  = true   # informational logging
TRACE = false   # trace instructions/stacks
DEBUG = true   # verbose logging
#INFO  = true    # informational logging
#TRACE = true    # trace instructions/stacks
#DEBUG = true    # verbose logging
VALIDATE= false

#import sys, os, time
#import traceback
#import struct

#IS_RPYTHON = sys.argv[1].endswith('rpython')
IS_RPYTHON = false


function elidable(f) return f end
function unroll_safe(f) return f end
function promote(x) pass end

function do_sort(a)
    #sort(a)
    a
end

# function unpack_f32(i32)
#     return struct.unpack('f', struct.pack('i', i32))[0]
# end

# function unpack_f64(i64)
#     return struct.unpack('d', struct.pack('q', i64))[0]
# end

# function pack_f32(f32)
#     return struct.unpack('i', struct.pack('f', f32))[0]
# end

# function pack_f64(f64)
#     return struct.unpack('q', struct.pack('d', f64))[0]
# end

function intmask(i) return i
end


function string_to_int(s, base=10) return int(s, base)
end


function fround(val, digits)
    return round(val, digits)
end


function float_fromhex(s)
    return float.fromhex(s)
end

mutable struct Type
    index::Int
    form
    params
    results
    mask
end

function Type(index, form, params, results)
    ntype = Type(index, form, params, results, 0x80)
end

struct WAException
    message
end

struct ExitException
    code
end

mutable struct Block
    kind
    value_type
    locals
    start
    finish
    else_addr
    br_addr
    Block(kind, value_type, start) = new(
        kind,
        value_type,
        [],
        start,
        0,
        0,
        0
    )
end

function update(bl::Block, finish, br_addr)
    bl.finish = finish
    bl.br_addr = br_addr
end



mutable struct Function
    value_type
    index
    locals
    start
    finish
    else_addr
    br_addr
    Function(value_type, index)= new(
        value_type,
        index,
        [],
        0,
        0,
        0,
        0
    )
end

function update(f::Function, locals, start, finish)
    f.locals = locals
    f.start = start
    f.finish = finish
    f.br_addr = finish
end




mutable struct FunctionImport
    value_type
    mod
    field
    fname
end

function FunctionImport(value_type, mod, field)
    fname = @sprintf("%s.%s" , mod, field)
    if !(fname in ["spectest.print", "spectest.print_i32",
                "env.printline", "env.readline", "env.read_file",
                "env.get_time_ms", "env.exit"])
            raise("function import %s not found" , (fname))
    end
    ft = FunctionImport(
        value_type,
        mod,
        field,
        fname
    )
end

BlockOrFunc = Union{Block, FunctionImport}

######################################
# WebAssembly spec data
######################################

MAGIC =  0x6d736100

VERSION = 0x01  # MVP

STACK_SIZE     = 500  #65536  vvv
CALLSTACK_SIZE = 819 #8192

I32     = 0x7f  # -0x01
I64     = 0x7e  # -0x02
F32     = 0x7d  # -0x03
F64     = 0x7c  # -0x04
ANYFUNC = 0x70  # -0x10
FUNC    = 0x60  # -0x20
BLOCK   = 0x40  # -0x40

VALUE_TYPE = Dict(
               I32     => "i32",
               I64     => "i64",
               F32     => "f32",
               F64     => "f64",
               ANYFUNC => "anyfunc",
               FUNC    => "func",
               BLOCK   => "block_type" )

# Block types/signatures for blocks, loops, ifs
BLOCK_TYPE = Dict(
               I32   => Type(-1, BLOCK, [], [I32]),
               I64   => Type(-1, BLOCK, [], [I64]),
               F32   => Type(-1, BLOCK, [], [F32]),
               F64   => Type(-1, BLOCK, [], [F64]),
               BLOCK => Type(-1, BLOCK, [], []) )


BLOCK_NAMES = Dict( 0x00 => "fn",  # TODO=> something else?
                0x02 => "block",
                0x03 => "loop",
                0x04 => "if",
                0x05 => "else" )


EXTERNAL_KIND_NAMES = Dict( 0x0 => "Function",
                        0x1 => "Table",
                        0x2 => "Memory",
                        0x3 => "Global" )

#                 ID =>  section name
SECTION_NAMES = Dict( 0  => "Custom",
                  1  => "Type",
                  2  => "Import",
                  3  => "Function",
                  4  => "Table",
                  5  => "Memory",
                  6  => "Global",
                  7  => "Export",
                  8  => "Start",
                  9  => "Element",
                  10 => "Code",
                  11 => "Data" )

#      opcode  name              immediate(s)
OPERATOR_INFO = Dict(
        # Control flow operators
        0x00 => ["unreachable",    ""],
        0x01 => ["nop",            ""],
        0x02 => ["block",          "block_type"],
        0x03 => ["loop",           "block_type"],
        0x04 => ["if",             "block_type"],
        0x05 => ["else",           ""],
        0x06 => ["RESERVED",       ""],
        0x07 => ["RESERVED",       ""],
        0x08 => ["RESERVED",       ""],
        0x09 => ["RESERVED",       ""],
        0x0a => ["RESERVED",       ""],
        0x0b => ["end",            ""],
        0x0c => ["br",             "varuint32"],
        0x0d => ["br_if",          "varuint32"],
        0x0e => ["br_table",       "br_table"],
        0x0f => ["return",         ""],

        # Call operators
        0x10 => ["call",           "varuint32"],
        0x11 => ["call_indirect",  "varuint32+varuint1"],

        0x12 => ["RESERVED",       ""],
        0x13 => ["RESERVED",       ""],
        0x14 => ["RESERVED",       ""],
        0x15 => ["RESERVED",       ""],
        0x16 => ["RESERVED",       ""],
        0x17 => ["RESERVED",       ""],
        0x18 => ["RESERVED",       ""],
        0x19 => ["RESERVED",       ""],

        # Parametric operators
        0x1a => ["drop",           ""],
        0x1b => ["select",         ""],

        0x1c => ["RESERVED",       ""],
        0x1d => ["RESERVED",       ""],
        0x1e => ["RESERVED",       ""],
        0x1f => ["RESERVED",       ""],

        # Variable access
        0x20 => ["get_local",      "varuint32"],
        0x21 => ["set_local",      "varuint32"],
        0x22 => ["tee_local",      "varuint32"],
        0x23 => ["get_global",     "varuint32"],
        0x24 => ["set_global",     "varuint32"],

        0x25 => ["RESERVED",       ""],
        0x26 => ["RESERVED",       ""],
        0x27 => ["RESERVED",       ""],

        # Memory-related operators
        0x28 => ["i32.load",       "memory_immediate"],
        0x29 => ["i64.load",       "memory_immediate"],
        0x2a => ["f32.load",       "memory_immediate"],
        0x2b => ["f64.load",       "memory_immediate"],
        0x2c => ["i32.load8_s",    "memory_immediate"],
        0x2d => ["i32.load8_u",    "memory_immediate"],
        0x2e => ["i32.load16_s",   "memory_immediate"],
        0x2f => ["i32.load16_u",   "memory_immediate"],
        0x30 => ["i64.load8_s",    "memory_immediate"],
        0x31 => ["i64.load8_u",    "memory_immediate"],
        0x32 => ["i64.load16_s",   "memory_immediate"],
        0x33 => ["i64.load16_u",   "memory_immediate"],
        0x34 => ["i64.load32_s",   "memory_immediate"],
        0x35 => ["i64.load32_u",   "memory_immediate"],
        0x36 => ["i32.store",      "memory_immediate"],
        0x37 => ["i64.store",      "memory_immediate"],
        0x38 => ["f32.store",      "memory_immediate"],
        0x39 => ["f64.store",      "memory_immediate"],
        0x3a => ["i32.store8",     "memory_immediate"],
        0x3b => ["i32.store16",    "memory_immediate"],
        0x3c => ["i64.store8",     "memory_immediate"],
        0x3d => ["i64.store16",    "memory_immediate"],
        0x3e => ["i64.store32",    "memory_immediate"],
        0x3f => ["current_memory", "varuint1"],
        0x40 => ["grow_memory",    "varuint1"],

        # Constants
        0x41 => ["i32.const",      "varint32"],
        0x42 => ["i64.const",      "varint64"],
        0x43 => ["f32.const",      "uint32"],
        0x44 => ["f64.const",      "uint64"],

        # Comparison operators
        0x45 => ["i32.eqz",        ""],
        0x46 => ["i32.eq",         ""],
        0x47 => ["i32.ne",         ""],
        0x48 => ["i32.lt_s",       ""],
        0x49 => ["i32.lt_u",       ""],
        0x4a => ["i32.gt_s",       ""],
        0x4b => ["i32.gt_u",       ""],
        0x4c => ["i32.le_s",       ""],
        0x4d => ["i32.le_u",       ""],
        0x4e => ["i32.ge_s",       ""],
        0x4f => ["i32.ge_u",       ""],

        0x50 => ["i64.eqz",        ""],
        0x51 => ["i64.eq",         ""],
        0x52 => ["i64.ne",         ""],
        0x53 => ["i64.lt_s",       ""],
        0x54 => ["i64.lt_u",       ""],
        0x55 => ["i64.gt_s",       ""],
        0x56 => ["i64.gt_u",       ""],
        0x57 => ["i64.le_s",       ""],
        0x58 => ["i64.le_u",       ""],
        0x59 => ["i64.ge_s",       ""],
        0x5a => ["i64.ge_u",       ""],

        0x5b => ["f32.eq",         ""],
        0x5c => ["f32.ne",         ""],
        0x5d => ["f32.lt",         ""],
        0x5e => ["f32.gt",         ""],
        0x5f => ["f32.le",         ""],
        0x60 => ["f32.ge",         ""],

        0x61 => ["f64.eq",         ""],
        0x62 => ["f64.ne",         ""],
        0x63 => ["f64.lt",         ""],
        0x64 => ["f64.gt",         ""],
        0x65 => ["f64.le",         ""],
        0x66 => ["f64.ge",         ""],

        # Numeric operators
        0x67 => ["i32.clz",        ""],
        0x68 => ["i32.ctz",        ""],
        0x69 => ["i32.popcnt",     ""],
        0x6a => ["i32.add",        ""],
        0x6b => ["i32.sub",        ""],
        0x6c => ["i32.mul",        ""],
        0x6d => ["i32.div_s",      ""],
        0x6e => ["i32.div_u",      ""],
        0x6f => ["i32.rem_s",      ""],
        0x70 => ["i32.rem_u",      ""],
        0x71 => ["i32.and",        ""],
        0x72 => ["i32.or",         ""],
        0x73 => ["i32.xor",        ""],
        0x74 => ["i32.shl",        ""],
        0x75 => ["i32.shr_s",      ""],
        0x76 => ["i32.shr_u",      ""],
        0x77 => ["i32.rotl",       ""],
        0x78 => ["i32.rotr",       ""],

        0x79 => ["i64.clz",        ""],
        0x7a => ["i64.ctz",        ""],
        0x7b => ["i64.popcnt",     ""],
        0x7c => ["i64.add",        ""],
        0x7d => ["i64.sub",        ""],
        0x7e => ["i64.mul",        ""],
        0x7f => ["i64.div_s",      ""],
        0x80 => ["i64.div_u",      ""],
        0x81 => ["i64.rem_s",      ""],
        0x82 => ["i64.rem_u",      ""],
        0x83 => ["i64.and",        ""],
        0x84 => ["i64.or",         ""],
        0x85 => ["i64.xor",        ""],
        0x86 => ["i64.shl",        ""],
        0x87 => ["i64.shr_s",      ""],
        0x88 => ["i64.shr_u",      ""],
        0x89 => ["i64.rotl",       ""],
        0x8a => ["i64.rotr",       ""],

        0x8b => ["f32.abs",        ""],
        0x8c => ["f32.neg",        ""],
        0x8d => ["f32.ceil",       ""],
        0x8e => ["f32.floor",      ""],
        0x8f => ["f32.trunc",      ""],
        0x90 => ["f32.nearest",    ""],
        0x91 => ["f32.sqrt",       ""],
        0x92 => ["f32.add",        ""],
        0x93 => ["f32.sub",        ""],
        0x94 => ["f32.mul",        ""],
        0x95 => ["f32.div",        ""],
        0x96 => ["f32.min",        ""],
        0x97 => ["f32.max",        ""],
        0x98 => ["f32.copysign",   ""],

        0x99 => ["f64.abs",        ""],
        0x9a => ["f64.neg",        ""],
        0x9b => ["f64.ceil",       ""],
        0x9c => ["f64.floor",      ""],
        0x9d => ["f64.trunc",      ""],
        0x9e => ["f64.nearest",    ""],
        0x9f => ["f64.sqrt",       ""],
        0xa0 => ["f64.add",        ""],
        0xa1 => ["f64.sub",        ""],
        0xa2 => ["f64.mul",        ""],
        0xa3 => ["f64.div",        ""],
        0xa4 => ["f64.min",        ""],
        0xa5 => ["f64.max",        ""],
        0xa6 => ["f64.copysign",   ""],

        # Conversions
        0xa7 => ["i32.wrap_i64",        ""],
        0xa8 => ["i32.trunc_f32_s",     ""],
        0xa9 => ["i32.trunc_f32_u",     ""],
        0xaa => ["i32.trunc_f64_s",     ""],
        0xab => ["i32.trunc_f64_u",     ""],

        0xac => ["i64.extend_i32_s",    ""],
        0xad => ["i64.extend_i32_u",    ""],
        0xae => ["i64.trunc_f32_s",     ""],
        0xaf => ["i64.trunc_f32_u",     ""],
        0xb0 => ["i64.trunc_f64_s",     ""],
        0xb1 => ["i64.trunc_f64_u",     ""],

        0xb2 => ["f32.convert_i32_s",   ""],
        0xb3 => ["f32.convert_i32_u",   ""],
        0xb4 => ["f32.convert_i64_s",   ""],
        0xb5 => ["f32.convert_i64_u",   ""],
        0xb6 => ["f32.demote_f64",      ""],

        0xb7 => ["f64.convert_i32_s",   ""],
        0xb8 => ["f64.convert_i32_u",   ""],
        0xb9 => ["f64.convert_i64_s",   ""],
        0xba => ["f64.convert_i64_u",   ""],
        0xbb => ["f64.promote_f32",     ""],

        # Reinterpretations
        0xbc => ["i32.reinterpret_f32", ""],
        0xbd => ["i64.reinterpret_f64", ""],
        0xbe => ["f32.reinterpret_i32", ""],
        0xbf => ["f64.reinterpret_i64", ""],
        )

LOAD_SIZE = Dict( 0x28 => 4,
              0x29 => 8,
              0x2a => 4,
              0x2b => 8,
              0x2c => 1,
              0x2d => 1,
              0x2e => 2,
              0x2f => 2,
              0x30 => 1,
              0x31 => 1,
              0x32 => 2,
              0x33 => 2,
              0x34 => 4,
              0x35 => 4,
              0x36 => 4,
              0x37 => 8,
              0x38 => 4,
              0x39 => 8,
              0x3a => 1,
              0x3b => 2,
              0x3c => 1,
              0x3d => 2,
              0x3e => 4,
              0x40 => 1,
              0x41 => 2,
              0x42 => 1,
              0x43 => 2,
              0x44 => 4 )

######################################
# General Functions
######################################

function hex(x)
    return @sprintf("%x", x)
end

function info(args...)
  if INFO
      #os.write(2, str * endd)
      print("\n+ info: ", join(args," | "))
      #if end == '': sys.stderr.flush()
  end
end

function debug(args...)
  if DEBUG
      #os.write(2, str * endd)
      print("\n+ debug: ", join(args," | "))
      #if end == '': sys.stderr.flush()
  end
end


# math functions

function unpack_nan32(i32)
  if IS_RPYTHON
      return float_unpack(i32, 4)
  else
      return struc.unpack('f', struc.pack('I', i32))[1]
  end
end

function unpack_nan64(i64)
  if IS_RPYTHON
      return float_unpack(i64, 8)
  else
      return struc.unpack('d', struc.pack('Q', i64))[1]
  end
end

#@elidable
function parse_nan(typee, arg)
  if   typee == F32
      v = unpack_nan32(0x7fc00000)
  else
      v = unpack_nan64(0x7ff8000000000000)
  end
  return v
end

# @elidable
function parse_number(type1, arg)
  arg = [c for c in arg if c != "_"].join("")
  if   type1 == I32
      if   arg[1:3] == "0x"   v = (I32, string_to_int(arg,16), 0.0)
      elseif arg[1:4] == "-0x"  v = (I32, string_to_int(arg,16), 0.0)
      else                   v = (I32, string_to_int(arg,10), 0.0)
      end
  elseif type1 == I64
      if arg[1:3] == "0x"     v = (I64, string_to_int(arg,16), 0.0)
      elseif arg[1:4] == "-0x"  v = (I64, string_to_int(arg,16), 0.0)
      else                    v = (I64, string_to_int(arg,10), 0.0)
      end
  elseif type1 == F32
      if   arg.find("nan")>=0 v = (F32, 0, parse_nan(type1, arg))
      elseif arg.find("inf")>=0 v = (F32, 0, float_fromhex(arg))
      elseif arg[1:3] == "0x"   v = (F32, 0, float_fromhex(arg))
      elseif arg[1:4] == "-0x"  v = (F32, 0, float_fromhex(arg))
      else                   v = (F32, 0, float(arg))
      end
  elseif type1 == F64
      if   arg.find("nan")>=0 v = (F64, 0, parse_nan(type1, arg))
      elseif arg.find("inf")>=0 v = (F64, 0, float_fromhex(arg))
      elseif arg[1:3] == "0x"   v = (F64, 0, float_fromhex(arg))
      elseif arg[1:4] == "-0x"  v = (F64, 0, float_fromhex(arg))
      else                    v = (F64, 0, float(arg))
      end
  else
      raise("invalid number %s" , arg) # vvv
  end
  return v
end

# # Integer division that rounds towards 0 (like C)
# @elidable
function idiv_s(a,b)
  if a*b>0
      return a//b
  else
      return (a+(-a%b))//b
  end
end

# @elidable
function irem_s(a,b)
  if a*b>0
      return a%b
  else -(-a%b)
  end
end

# #

# @elidable
function rotl32(a,cnt)
  return (((a *2^(cnt % 0x20)) & 0xffffffff)
          | (a *2^(0x20 - (cnt % 0x20))))
end

# @elidable
function rotr32(a,cnt)
  return ((a >> (cnt % 0x20))
          | ((a *2^(0x20 - (cnt % 0x20))) & 0xffffffff))
end

# @elidable
function rotl64(a,cnt)
  return (((a *2^(cnt % 0x40)) & 0xffffffffffffffff)
          | (a >> (0x40 - (cnt % 0x40))))
end

# @elidable
function rotr64(a,cnt)
  return ((a >> (cnt % 0x40))
          | ((a *2^(0x40 - (cnt % 0x40))) & 0xffffffffffffffff))
end

# @elidable
function bytes2uint8(b)
  return b[1]
end


# @elidable
function bytes2int8(b)
  val = b[1]
  if val & 0x80
      return val - 0x100
  else
      return val
  end
end

# #

# @elidable
function bytes2uint16(b)
  return (b[2]*2^8) + b[1]
end

# @elidable
function bytes2int16(b)
  val = (b[2]*2^8) + b[1]
  if val & 0x8000
      return val - 0x10000
  else
      return val
  end
end

# #

# @elidable
function bytes2uint32(b)
    print
  return (b[4]*2^24) + (b[3]*2^16) + (b[2]*2^8) + b[1]
end

# @elidable
function uint322bytes(v)
  return [0xff & (v),
          0xff & (v/2^8),
          0xff & (v/2^16),
          0xff & (v/2^24)]
end

# @elidable
function bytes2int32(b)
  val = (b[4]*2^24) + (b[3]*2^16) + (b[2]*2^8) + b[1]
  if val & 0x80000000
      return val - 0x100000000
  else
      return val
  end
end

# @elidable
function int2uint32(i)
  return i & 0xffffffff
end

# @elidable
function int2int32(i)
  val = i & 0xffffffff
  if val & 0x80000000 > 0
      return val - 0x100000000
  else
      return val
  end
end

# #

# @elidable
function bytes2uint64(b)
  return ((b[8]*2^56) + (b[7]*2^48) + (b[6]*2^40) + (b[5]*2^32) +
          (b[4]*2^24) + (b[3]*2^16) + (b[2]*2^8) + b[])
end

# @elidable
function uint642bytes(v)
  return [0xff & (v),
          0xff & (v/2^8),
          0xff & (v/2^16),
          0xff & (v/2^24),
          0xff & (v/2^32),
          0xff & (v/2^40),
          0xff & (v/2^48),
          0xff & (v/2^56)]
end

if IS_RPYTHON
#     @elidable
  function bytes2int64(b)
      return bytes2uint64(b)
  end
else
  function bytes2int64(b)
      val = ((b[8]*2^56) + (b[7]*2^48) + (b[6]*2^40) + (b[5]*2^32) +
              (b[4]*2^24) + (b[3]*2^16) + (b[2]*2^8) + b[1])
      if val & 0x8000000000000000
          return val - 0x10000000000000000
      else
          return val
      end
  end
end

# #

if IS_RPYTHON
#     @elidable
  function int2uint64(i)
      return intmask(i)
  end
else
  function int2uint64(i)
      return i & 0xffffffffffffffff
  end
end

if IS_RPYTHON
#     @elidable
  function int2int64(i)
      return i
  end
else
  function int2int64(i)
      val = i & 0xffffffffffffffff
      if val & 0x8000000000000000
          return val - 0x10000000000000000
      else
          return val
      end
  end
end

# https://en.wikipedia.org/wiki/LEB128
# @elidable
function read_LEB(bytes, pos, maxbits=32, signed=false)
  result = 0
  shift = 0
  bcnt = 0
  startpos = pos
  byte = bytes[pos]
  while true
      byte = bytes[pos]
      pos += 1
      result = result | ((byte & 0x7f)*2^shift)
      shift +=7
      if (byte & 0x80) == 0
          break
      end
      # Sanity check length against maxbits
      bcnt += 1
      if bcnt > ceil(maxbits/7.0)
          raise("Unsigned LEB at byte %s overflow" ,  # Exception vvv
                  startpos)
      end
  end
  if signed && (shift < maxbits) && (byte >= 0x40)
      # Sign extend
      result = result | - (1 *2^shift)
  end
  return (pos, result)
end

# @elidable
function read_I32(bytes, pos)
  assert(pos >= 1)
  return bytes2uint32(bytes[pos:pos+3])
end

# @elidable
function read_I64(bytes, pos)
  assert(pos >= 0)
  return bytes2uint64(bytes[pos:pos+7])
end

# @elidable
function read_F32(bytes, pos)
  assert(pos >= 0)
  bits = bytes2int32(bytes[pos:pos+7])
  num = unpack_f32(bits)
  # fround hangs if called with nan
  if num isa NaN return num end
  return fround(num, 5)
end

# @elidable
function read_F64(bytes, pos)
  assert(pos >= 0)
  bits = bytes2int64(bytes[pos:pos+7])
  return unpack_f64(bits)
end

function write_I32(bytes, pos, ival)
  bytes[pos:pos+3] = uint322bytes(ival)
end

function write_I64(bytes, pos, ival)
  bytes[pos:pos+7] = uint642bytes(ival)
end

function write_F32(bytes, pos, fval)
  ival = intmask(pack_f32(fval))
  bytes[pos:pos+3] = uint322bytes(ival)
end

function write_F64(bytes, pos, fval)
  ival = intmask(pack_f64(fval))
  bytes[pos:pos+7] = uint642bytes(ival)
end


function value_repr(val)
    print(val)
  vt, ival, fval = val
  vtn = VALUE_TYPE[vt]
  if   vtn in ("i32", "i64")
      return @sprintf("%s:%s" , hex(ival), vtn)
  elseif vtn in ("f32", "f64")
      if IS_RPYTHON
          # TODO: fix this to be like python
          return @sprintf("%f:%s" , fval, vtn)
      else
          str = @sprintf("%.7g" , fval)
          if str.find(".") < 0
              return @sprintf("%f:%s" , fval, vtn)
          else
              return @sprintf("%s:%s" , str, vtn)
          end
      end
  else
      raise("unknown value type %s" , vtn) #vvv
  end
end

function type_repr(t)
  return @sprintf("<index: %s, form: %s, params: %s, results: %s, mask: %s>" ,
          t.index, VALUE_TYPE[t.form],
          [VALUE_TYPE[p] for p in t.params],
          [VALUE_TYPE[r] for r in t.results], hex(t.mask))
end

function export_repr(e)
  return @sprintf("<kind: %s, field: '%s', index: 0x%x>" ,
          EXTERNAL_KIND_NAMES[e.kind], e.field, e.index)
end

function func_repr(f)
  if f isa FunctionImport
      return @sprintf("<type: 0x%x, import: '%s.%s'>" ,
              f.value_type.index, f.mod, f.field)
  else
      return @sprintf("<type: 0x%x, locals: %s, start: 0x%x, end: 0x%x>" ,
              f.value_type.index, [VALUE_TYPE[p] for p in f.locals],
              f.start, f.finish)
  end
end

function block_repr(block) # vvv
  if block isa Block
      return @sprintf("%s<0/0->%d>" ,
              BLOCK_NAMES[block.kind],
              length(block.value_type.results))
  elseif block isa Function
      return @sprintf("fn%d<%d/%d->%d>" ,
              block.index, length(block.value_type.params),
              length(block.locals), length(block.value_type.results))
  end
end

function stack_repr(sp, fp, stack)
  res = []
  for i in range(1,length=sp+1)
      if i == fp
          push!(res, "*")
      end
      push!(res, value_repr(stack[i]))
  end
  return "[" * join(res, " ") * "]"
end

function callstack_repr(csp, bs) # vvv
  return "[" * join([@sprintf("%s(sp:%d/fp:%d/ra:0x%x)" ,
      block_repr(bs[i][1]),bs[i][2],bs[i][3],bs[i][4])
                      for i in range(1,length=csp+1)]," ") * "]"
end

function dump_stacks(sp, stack, fp, csp, callstack)
  debug("      * stack:     %s" , (
      stack_repr(sp, fp, stack)))
  debug("      * callstack: %s" , (
      callstack_repr(csp, callstack)))
end

function byte_code_repr(bytes)
  res = []
  for val in bytes
      if val < 16
          push!(res, val)
      else
          push!(res, val)
      end
  end
  return "[" * join(res, ",") * "]"
end

function skip_immediates(code, pos)
  opcode = code[pos]
  pos += 1
  vals = []
  imtype = OPERATOR_INFO[opcode][1]
  print("\n\nimtype: ",imtype)
  if   "varuint1" == imtype
      pos, v = read_LEB(code, pos, 1)
      push!(vals, v)
  elseif "varint32" == imtype
      pos, v = read_LEB(code, pos, 32)
      push!(vals, v)
  elseif "varuint32" == imtype
      pos, v = read_LEB(code, pos, 32)
      push!(vals, v)
  elseif "varuint32+varuint1" == imtype
      pos, v = read_LEB(code, pos, 32)
      push!(vals, v)
      pos, v = read_LEB(code, pos, 1)
      push!(vals, v)
  elseif "varint64" == imtype
      pos, v = read_LEB(code, pos, 64)
      push!(vals, v)
  elseif "varuint64" == imtype
      pos, v = read_LEB(code, pos, 64)
      push!(vals, v)
  elseif "uint32" == imtype
      push!(vals, read_F32(code, pos))
      pos += 4
  elseif "uint64" == imtype
      push!(vals, read_F64(code, pos))
      pos += 8
  elseif "block_type" == imtype
      pos, v = read_LEB(code, pos, 7)  # block type signature
      push!(vals, v)
  elseif "memory_immediate" == imtype
      pos, v = read_LEB(code, pos, 32)  # flags
      push!(vals, v)
      pos, v = read_LEB(code, pos, 32)  # offset
      push!(vals, v)
  elseif "br_table" == imtype
      pos, count = read_LEB(code, pos, 32)  # target count
      push!(vals, v)
      for i in range(1,length=count)
          pos, v = read_LEB(code, pos, 32)  # target
          push!(vals, v)
      end
      pos, v = read_LEB(code, pos, 32)  # default target
      push!(vals, v)
  elseif "" == imtype
      pass # no immediates
  else
      raise("unknown immediate type %s" , imtype)  # vvv
  end
  return pos, vals
end

function find_blocks(code, start, endd, block_map)  # vvv
  pos = start
  # stack of blocks with current at top: (opcode, pos) tuples
  opstack = []
  #
  # Build the map of blocks
  #
  opcode = 0
  while pos <= endd
      opcode = code[pos]
      debug("0x%x: %s, opstack: " ,  #%s
         pos, OPERATOR_INFO[opcode][1])
         # ,["%d,%s,0x%x" , (o,s.index,p for (o,s,p) in opstack)])
      if   0x02 <= opcode <= 0x04  # block, loop, if
          block = Block(opcode, BLOCK_TYPE[code[pos+1]], pos)
          push!(opstack, block)
          block_map[pos] = block
      elseif 0x05 == opcode  # mark else positions
          assert(opstack[-1].kind == 0x04, "else not matched with if")
          opstack[-1].else_addr = pos+1
      elseif 0x0b == opcode  # end
          if pos == endd break end
          block = opstack.pop()
          if block.kind == 0x03  # loop: label after start
              block.update(pos, block.start+2)
          else  # block/if: label at end
              block.update(pos, pos)
          end
      end
          pos, _ = skip_immediates(code, pos)
  end
  assert(opcode == 0xb, "function block did not end with 0xb")
  assert(length(opstack) == 0, "function ended in middle of block")
  debug("block_map: %s" , block_map)
  return block_map
end

# @unroll_safe
function pop_block(stack, callstack, sp, fp, csp)
  block, orig_sp, orig_fp, ra = callstack[csp+1]
  csp -= 1
  t = block.value_type
  # Validate return value if there is one
  if VALIDATE
      if length(t.results) > 1
          raise("multiple return values unimplemented") # vvv
      end
      if length(t.results) > sp+1
          raise("stack underflow")
      end
  end
  if length(t.results) == 1
      # Restore main value stack, saving top return value
      save = stack[sp+1]
      sp -= 1
      if save[1] != t.results[1]
          raise("call signature mismatch: %s != %s (%s)" ,
              VALUE_TYPE[t.results[1]], VALUE_TYPE[save[1]],
                      value_repr(save)) end
      # Restore value stack to original size prior to call/block
      if orig_sp < sp
          sp = orig_sp
      end
      # Put back return value if we have one
      sp += 1
      stack[sp+1] = save
  else
      # Restore value stack to original size prior to call/block
      if orig_sp < sp
          sp = orig_sp
      end
  end
  return block, ra, sp, orig_fp, csp
end

# @unroll_safe
function do_call(stack, callstack, sp, fp, csp, func, pc, indirect=false)

    # Push block, stack size and return address onto callstack
    t = func.value_type
    csp += 1
    #callstack[csp] = (func, sp-length(t.params), fp, pc) # vvv
    print("\n\nfunc ",func," ",csp,"\n\n")

    # Update the pos/instruction counter to the function
    pc = func.start  # vvv

    if TRACE
      info("  Calling function 0x%x, start: 0x%x, end: 0x%x, %d locals, %d params, %d results" ,
          func.index, func.start, func.finish,
          length(func.locals), length(t.params), length(t.results))
    end
    # set frame pointer to include parameters
    fp = sp - length(t.params) + 1

    # push locals (dropping extras)
    for lidx in range(1, length=length(func.locals))  #vvv
        ltype = func.locals[lidx]
        sp += 1
        stack[sp] = (ltype, 0, 0.0)
    end
    return pc, sp, fp, csp
end


# @unroll_safe
function do_call_import(stack, sp, memory, import_function, func)
  t = func.value_type
  args = []
  for idx in range(1,length=length(t.params)-1, -1, -1)
      arg = stack[sp]
      sp -= 1
      push!(args, arg)
#        if VALIDATE:
#            # make sure args match type signature
#            ptype = t.params[idx]
#            if ptype != arg[1]:
#                raise WAException("call signature mismatch: %s != %s" , (
#                    VALUE_TYPE[ptype], VALUE_TYPE[arg[1]]))
  end
  # Workaround rpython failure to identify type
  results = [(0, 0, 0.0)]
  results.pop()
  args.reverse()
  results.extend(import_function(func.mod, func.field, memory, args))

  # make sure returns match type signature
  for (idx, rtype) in enumerate(t.results)
      if idx < length(results)
          res = results[idx]
          if rtype != res[1]
              raise("return signature mismatch") # vvv
          sp += 1
          stack[sp] = res
      else
          raise("return signature mismatch") # vvv
      end
  end
  return sp
  end

end

# Main loop/JIT

function get_location_str(opcode, pc, code, func, table, block_map)
    return @sprintf("0x%x %s(0x%x)" ,
            pc, OPERATOR_INFO[opcode][1], opcode)
end

# @elidable
function get_block(block_map, pc)
    return block_map[pc]
end

# @elidable
function get_function(func, fidx)
    return func[fidx+1]
end

# @elidable
function bound_violation(opcode, addr, pages)
    return addr < 1 || addr+LOAD_SIZE[opcode] > pages*(2^16)
end

# @elidable
function get_from_table(table, tidx, table_index)
    tbl = table[tidx]
    if table_index < 0 || table_index >= length(tbl)
        raise("undefined element")     # vvv  WAException
    end
    return tbl[table_index]
end

if IS_RPYTHON
    # greens/reds must be sorted ints, refs, floats
    jitdriver = JitDriver(
            greens=["opcode", "pc",
                    "code", "function", "table", "block_map"],
            reds=["sp", "fp", "csp",
                  "module", "memory", "stack", "callstack"],
            get_printable_location=get_location_str)
end


function interpret_mvp(mod,
        # Greens
        pc, code, func, table, block_map,
        # Reds
        memory, sp, stack, fp, csp, callstack)
    #print("\n",stack)
    info(" Interpret_mvp: len code, sp: ", length(code),sp)
    while pc < length(code)

        opcode = code[pc]
        info(" Interpret step: ", pc, sp,"opcode: ",opcode, OPERATOR_INFO[opcode])
        if IS_RPYTHON
            jitdriver.jit_merge_point(
                    # Greens
                    opcode=opcode,
                    pc=pc,
                    code=code,
                    func=func,
                    table=table,
                    block_map=block_map,
                    # Reds
                    sp=sp, fp=fp, csp=csp,
                    mod=mod, memory=memory,
                    stack=stack, callstack=callstack)
        end
        cur_pc = pc
        pc += 1
        if TRACE
            dump_stacks(sp, stack, fp, csp, callstack)
            # _, immediates = skip_immediates(code, cur_pc)  # vvv
#             info("    0x%x <0x%x/%s%s%s>" , (
#                 cur_pc, opcode, OPERATOR_INFO[opcode][1],
#                 " " if immediates else "",
#                 ",".join(["0x%x" , i for i in immediates])))
        end
        #
        # Control flow operators
        #
        if   0x00 == opcode  # unreachable
            raise("unreachable")    # vvv  WAException
        elseif 0x01 == opcode  # nop
            pass
        elseif 0x02 == opcode  # block
            pc, ignore = read_LEB(code, pc, 32) # ignore block_type
            block = get_block(block_map, cur_pc)
            csp += 1
            callstack[csp] = (block, sp, fp, 0)
            if TRACE debug("      - block %s", block_repr(block)) end
        elseif 0x03 == opcode  # loop
            (pc, ignore) = read_LEB(code, pc, 32) # ignore block_type
            block = get_block(block_map, cur_pc)
            csp += 1
            callstack[csp] = (block, sp, fp, 0)
            if TRACE debug("      - block %s", block_repr(block)) end
        elseif 0x04 == opcode  # if
            (pc, ignore) = read_LEB(code, pc, 32) # ignore block_type
            block = get_block(block_map, cur_pc)
            csp += 1
            callstack[csp] = (block, sp, fp, 0)
            cond = stack[sp]
            sp -= 1
            if !(cond[1])  # if false (I32)
                # branch to else block or after end of if
                if block.else_addr == 0
                    # no else block so pop if block and skip end
                    csp -= 1
                    pc = block.br_addr+1
                else
                    pc = block.else_addr
                end
            end
            if TRACE
                debug("      - cond %s jump to 0x%x, block %s",
                        value_repr(cond), pc, block_repr(block)) end
        elseif 0x05 == opcode  # else
            block = callstack[csp][1]
            pc = block.br_addr
            if TRACE
                debug("      - of %s jump to 0x%x",
                        block_repr(block), pc) end
        elseif 0x0b == opcode  # end
            (block, ra, sp, fp, csp) = pop_block(stack, callstack, sp,
                    fp, csp)
            if TRACE debug("      - of %s", block_repr(block)) end
            if block isa Function
                # Return to return address
                pc = ra
                if csp == -1
                    # Return to top-level, ignoring return_addr
                    return pc, sp, fp, csp
                else
                    if TRACE
                        info("  Returning from func 0x%x to 0x%x",
                                block.index, pc) end
                end
            elseif block isa Block && block.kind == 0x00
                # this is an init_expr
                return pc, sp, fp, csp
            else
                pass # end of block/loop/if, keep going
            end
        elseif 0x0c == opcode  # br
            (pc, br_depth) = read_LEB(code, pc, 32)
            csp -= br_depth
            block, _, _, _ = callstack[csp]
            pc = block.br_addr # set to end for pop_block
            if TRACE debug("      - to 0x%x", pc) end
        elseif 0x0d == opcode  # br_if
            pc, br_depth = read_LEB(code, pc, 32)
            cond = stack[sp]
            sp -= 1
            if cond[1]  # I32
                csp -= br_depth
                block, _, _, _ = callstack[csp]
                pc = block.br_addr # set to end for pop_block
            end
            if TRACE
                debug("      - cond %s, to 0x%x", cond[1], pc) end
        elseif 0x0e == opcode  # br_table
            pc, target_count = read_LEB(code, pc, 32)
            depths = []
            for c in range(1,length=target_count)
                pc, depth = read_LEB(code, pc, 32)
                push!(depths, depth)
            end
            pc, br_depth = read_LEB(code, pc, 32) # default
            expr = stack[sp]
            sp -= 1
            if VALIDATE assert(expr[1] == I32) end
            didx = expr[1]  # I32
            if didx >= 1 && didx <= length(depths)
                br_depth = depths[didx]
            end
            csp -= br_depth
            block, _, _, _ = callstack[csp]
            pc = block.br_addr # set to end for pop_block
            if TRACE
                debug("      - depths %s, didx %d, to 0x%x",
                        depths, didx, pc) end
        elseif 0x0f == opcode  # return
            # Pop blocks until reach Function signature
            while csp >= 1
                if callstack[csp][1] isa Function break end
                # We don't use pop_block because the end opcode
                # handler will do this for us and catch the return
                # value properly.
                block = callstack[csp]
                csp -= 1
            end
            if VALIDATE assert(csp >= 1) end
            block = callstack[csp][1]
            if VALIDATE assert(block isa Function) end
            # Set instruction pointer to end of func
            # The actual pop_block and return is handled by handling
            # the end opcode
            pc = block.finish                            # block.end. vvv
            if TRACE debug("      - to 0x%x" , pc) end
        #
        # Call operators
        #
        elseif 0x10 == opcode  # call
            pc, fidx = read_LEB(code, pc, 32)
            func = get_function(func, fidx)
            if func isa FunctionImport
                t = func.type
                if TRACE
                    debug("      - calling import %s.%s(%s)" ,
                        func.module, func.field,
                                join([VALUE_TYPE[a] for a in t.params ],",")) end
                sp = do_call_import(stack, sp, memory,
                        mod.import_function, func)
            elseif func isa Function
                pc, sp, fp, csp = do_call(stack, callstack, sp, fp,
                        csp, func, pc)
                if TRACE debug("      - calling func fidx %d" *
                            " at 0x%x" , fidx, pc) end
            end
        elseif 0x11 == opcode  # call_indirect
            pc, tidx = read_LEB(code, pc, 32)
            pc, reserved = read_LEB(code, pc, 1)
            type_index_val = stack[sp]
            sp -= 1
            if VALIDATE assert(type_index_val[1] == I32) end
            table_index = int(type_index_val[2])  # I32
            promote(table_index)
            fidx = get_from_table(table, ANYFUNC, table_index)
            promote(fidx)
            if VALIDATE assert(csp < CALLSTACK_SIZE, "call stack exhausted") end
            func = get_function(func, fidx)
            if VALIDATE && func.value_type.mask != mod.value_type[tidx].mask
                raise("indirect call type mismatch (call type %s and func type %s differ" , func.value_type.index, tidx) end   # vvv  WAException
            pc, sp, fp, csp = do_call(stack, callstack, sp, fp, csp,
                                        func, pc, true)
            if TRACE
                debug("      - table idx 0x%x, tidx 0x%x," *
                      " calling func fidx 0x%x at 0x%x" ,
                                            table_index, tidx, fidx, pc) end
        #
        # Parametric operators
        #
        elseif 0x1a == opcode  # drop
            if TRACE debug("      - dropping %s" , value_repr(stack[sp])) end
            sp -= 1
        elseif 0x1b == opcode  # select
            cond, a, b = stack[sp], stack[sp-1], stack[sp-2]
            sp -= 2
            if cond[1]  # I32
                stack[sp] = b
            else
                stack[sp] = a
            end
            if TRACE
                debug("      - cond 0x%x, selected %s" ,
                   cond[1], value_repr(stack[sp])) end
        #
        # Variable access
        #
        elseif 0x20 == opcode  # get_local
            pc, arg = read_LEB(code, pc, 32)
            sp += 1
            stack[sp] = stack[fp+arg]
            if TRACE debug("      - got %s" , value_repr(stack[sp])) end
        elseif 0x21 == opcode  # set_local
            pc, arg = read_LEB(code, pc, 32)
            val = stack[sp]
            sp -= 1
            stack[fp+arg] = val
            if TRACE debug("      - to %s" , value_repr(val)) end
        elseif 0x22 == opcode  # tee_local
            pc, arg = read_LEB(code, pc, 32)
            val = stack[sp] # like set_local but do not pop
            stack[fp+arg] = val
            if TRACE debug("      - to %s" , value_repr(val)) end
        elseif 0x23 == opcode  # get_global
            pc, gidx = read_LEB(code, pc, 32)
            sp += 1
            stack[sp] = mod.global_list[gidx]
            if TRACE debug("      - got %s" , value_repr(stack[sp])) end
        elseif 0x24 == opcode  # set_global
            pc, gidx = read_LEB(code, pc, 32)
            val = stack[sp]
            sp -= 1
            mod.global_list[gidx] = val
            if TRACE debug("      - to %s" , value_repr(val)) end
        #
        # Memory-related operators
        #
        # Memory load operators
        elseif 0x28 <= opcode <= 0x35
            pc, flags = read_LEB(code, pc, 32)
            pc, offset = read_LEB(code, pc, 32)
            addr_val = stack[sp]
            sp -= 1
            if flags != 2
                if TRACE
                    info("      - unaligned load - flags 0x%x," *
                         " offset 0x%x, addr 0x%x" ,
                             flags, offset, addr_val[1]) end
            end
            addr = addr_val[1] + offset
            if bound_violation(opcode, addr, memory.pages)
                raise("out of bounds memory access")    end  # vvv  WAException
            assert(addr >= 1)
            if   0x28 == opcode  # i32.load
                res = (I32, bytes2uint32(memory.bytes[addraddr+4]), 0.0)
            elseif 0x29 == opcode  # i64.load
                res = (I64, bytes2uint64(memory.bytes[addraddr+8]), 0.0)
            elseif 0x2a == opcode  # f32.load
                res = (F32, 0, read_F32(memory.bytes, addr))
            elseif 0x2b == opcode  # f64.load
                res = (F64, 0, read_F64(memory.bytes, addr))
            elseif 0x2c == opcode  # i32.load8_s
                res = (I32, bytes2int8(memory.bytes[addraddr+1]), 0.0)
            elseif 0x2d == opcode  # i32.load8_u
                res = (I32, memory.bytes[addr], 0.0)
            elseif 0x2e == opcode  # i32.load16_s
                res = (I32, bytes2int16(memory.bytes[addraddr+2]), 0.0)
            elseif 0x2f == opcode  # i32.load16_u
                res = (I32, bytes2uint16(memory.bytes[addraddr+2]), 0.0)
            elseif 0x30 == opcode  # i64.load8_s
                res = (I64, bytes2int8(memory.bytes[addraddr+1]), 0.0)
            elseif 0x31 == opcode  # i64.load8_u
                res = (I64, memory.bytes[addr], 0.0)
            elseif 0x32 == opcode  # i64.load16_s
                res = (I64, bytes2int16(memory.bytes[addraddr+2]), 0.0)
            elseif 0x33 == opcode  # i64.load16_u
                res = (I64, bytes2uint16(memory.bytes[addraddr+2]), 0.0)
            elseif 0x34 == opcode  # i64.load32_s
                res = (I64, bytes2int32(memory.bytes[addraddr+4]), 0.0)
            elseif 0x35 == opcode  # i64.load32_u
                res = (I64, bytes2uint32(memory.bytes[addraddr+4]), 0.0)
            else
                raise("%s(0x%x) unimplemented" ,      # vvv  WAException
                    OPERATOR_INFO[opcode][1], opcode)
            end
            sp += 1
            stack[sp] = res
        # Memory store operators
        elseif 0x36 <= opcode <= 0x3e
            pc, flags = read_LEB(code, pc, 32)
            pc, offset = read_LEB(code, pc, 32)
            val = stack[sp]
            sp -= 1
            addr_val = stack[sp]
            sp -= 1
            if flags != 2
                if TRACE
                    info("      - unaligned store - flags 0x%x," *
                         " offset 0x%x, addr 0x%x, val 0x%x" ,
                             flags, offset, addr_val[1], val[1]) end
            end
            addr = addr_val[1] + offset
            if bound_violation(opcode, addr, memory.pages)
                raise("out of bounds memory access")    end  # vvv  WAException
            assert(addr >= 1)
            if   0x36 == opcode  # i32.store
                write_I32(memory.bytes, addr, val[1])
            elseif 0x37 == opcode  # i64.store
                write_I64(memory.bytes, addr, val[1])
            elseif 0x38 == opcode  # f32.store
                write_F32(memory.bytes, addr, val[2])
            elseif 0x39 == opcode  # f64.store
                write_F64(memory.bytes, addr, val[2])
            elseif 0x3a == opcode  # i32.store8
                memory.bytes[addr] = val[1] & 0xff
            elseif 0x3b == opcode  # i32.store16
                memory.bytes[addr]   =  val[1] & 0x00ff
                memory.bytes[addr+1] = (val[1] & 0xff00)>>8
            elseif 0x3c == opcode  # i64.store8
                memory.bytes[addr]   =  val[1] & 0xff
            elseif 0x3d == opcode  # i64.store16
                memory.bytes[addr]   =  val[1] & 0x00ff
                memory.bytes[addr+1] = (val[1] & 0xff00)>>8
            elseif 0x3e == opcode  # i64.store32
                memory.bytes[addr]   =  val[1] & 0x000000ff
                memory.bytes[addr+1] = (val[1] & 0x0000ff00)>>8
                memory.bytes[addr+2] = (val[1] & 0x00ff0000)>>16
                memory.bytes[addr+3] = (val[1] & 0xff000000)>>24
            else
                raise("%s(0x%x) unimplemented" ,    # vvv  WAException
                    OPERATOR_INFO[opcode][1], opcode)
            end
        # Memory size operators
        elseif 0x3f == opcode  # current_memory
            pc, reserved = read_LEB(code, pc, 1)
            sp += 1
            stack[sp] = (I32, mod.memory.pages, 0.0)
            if TRACE
                debug("      - current 0x%x" , mod.memory.pages) end
        elseif 0x40 == opcode  # grow_memory
            pc, reserved = read_LEB(code, pc, 1)
            prev_size = mod.memory.pages
            delta = stack[sp][2]  # I32
            mod.memory.grow(delta)
            stack[sp] = (I32, prev_size, 0.0)
            debug("      - delta 0x%x, prev 0x%x" , (
                delta, prev_size))
        #
        # Constants
        #
        elseif 0x41 == opcode  # i32.const
            pc, val = read_LEB(code, pc, 32, true)
            sp += 1
            stack[sp+1] = (I32, val, 0.0)
            if TRACE debug("      - %s" , value_repr(stack[sp])) end
        elseif 0x42 == opcode  # i64.const
            pc, val = read_LEB(code, pc, 64, true)
            sp += 1
            stack[sp+1] = (I64, val, 0.0)
            if TRACE debug("      - %s" , value_repr(stack[sp])) end
        elseif 0x43 == opcode  # f32.const
            sp += 1
            stack[sp] = (F32, 0, read_F32(code, pc))
            pc += 4
            if TRACE debug("      - %s" , value_repr(stack[sp])) end
        elseif 0x44 == opcode  # f64.const
            sp += 1
            stack[sp] = (F64, 0, read_F64(code, pc))
            pc += 8
            if TRACE debug("      - %s" , value_repr(stack[sp])) end
        #
        # Comparison operators
        #
        # unary
        elseif opcode in [0x45, 0x50]
            a = stack[sp]
            sp -= 1
            if   0x45 == opcode # i32.eqz
                if VALIDATE assert(a[1] == I32) end
                res = (I32, a[1] == 0, 0.0)
            elseif 0x50 == opcode # i64.eqz
                if VALIDATE assert(a[1] == I64) end
                res = (I32, a[1] == 0, 0.0)
            else
                raise("%s(0x%x) unimplemented" ,     # vvv  WAException
                    OPERATOR_INFO[opcode][1], opcode)
            end
            if TRACE
                debug("      - (%s) = %s" ,
                    value_repr(a), value_repr(res)) end
            sp += 1
            stack[sp] = res
        # binary
        elseif 0x46 <= opcode <= 0x66
            a, b = stack[sp-1], stack[sp]
            sp -= 2
            if   0x46 == opcode # i32.eq
                if VALIDATE assert(a[1] == I32 && b[1] == I32) end
                res = (I32, a[1] == b[1], 0.0)
            elseif 0x47 == opcode # i32.ne
                if VALIDATE assert(a[1] == I32 && b[1] == I32) end
                res = (I32, a[1] != b[1], 0.0)
            elseif 0x48 == opcode # i32.lt_s
                if VALIDATE assert(a[1] == I32 && b[1] == I32) end
                res = (I32, int2int32(a[1]) < int2int32(b[1]), 0.0)
            elseif 0x49 == opcode # i32.lt_u
                if VALIDATE assert(a[1] == I32 && b[1] == I32) end
                res = (I32, int2uint32(a[1]) < int2uint32(b[1]), 0.0)
            elseif 0x4a == opcode # i32.gt_s
                if VALIDATE assert(a[1] == I32 && b[1] == I32) end
                res = (I32, int2int32(a[1]) > int2int32(b[1]), 0.0)
            elseif 0x4b == opcode # i32.gt_u
                if VALIDATE assert(a[1] == I32 && b[1] == I32) end
                res = (I32, int2uint32(a[1]) > int2uint32(b[1]), 0.0)
            elseif 0x4c == opcode # i32.le_s
                if VALIDATE assert(a[1] == I32 && b[1] == I32) end
                res = (I32, int2int32(a[1]) <= int2int32(b[1]), 0.0)
            elseif 0x4d == opcode # i32.le_u
                if VALIDATE assert(a[1] == I32 && b[1] == I32) end
                res = (I32, int2uint32(a[1]) <= int2uint32(b[1]), 0.0)
            elseif 0x4e == opcode # i32.ge_s
                if VALIDATE assert(a[1] == I32 && b[1] == I32) end
                res = (I32, int2int32(a[1]) >= int2int32(b[1]), 0.0)
            elseif 0x4f == opcode # i32.ge_u
                if VALIDATE assert(a[1] == I32 && b[1] == I32) end
                res = (I32, int2uint32(a[1]) >= int2uint32(b[1]), 0.0)
            elseif 0x51 == opcode # i64.eq
                if VALIDATE assert(a[1] == I64 && b[1] == I64) end
                res = (I32, a[1] == b[1], 0.0)
            elseif 0x52 == opcode # i64.ne
                if VALIDATE assert(a[1] == I64 && b[1] == I64) end
                res = (I32, a[1] != b[1], 0.0)
            elseif 0x53 == opcode # i64.lt_s
                if VALIDATE assert(a[1] == I64 && b[1] == I64) end
                res = (I32, int2int64(a[1]) < int2int64(b[1]), 0.0)
            elseif 0x54 == opcode # i64.lt_u
                if VALIDATE assert(a[1] == I64 && b[1] == I64) end
                res = (I32, int2uint64(a[1]) < int2uint64(b[1]), 0.0)
            elseif 0x55 == opcode # i64.gt_s
                if VALIDATE assert(a[1] == I64 && b[1] == I64) end
                res = (I32, int2int64(a[1]) > int2int64(b[1]), 0.0)
            elseif 0x56 == opcode # i64.gt_u
                if VALIDATE assert(a[1] == I64 && b[1] == I64) end
                res = (I32, int2uint64(a[1]) > int2uint64(b[1]), 0.0)
            elseif 0x57 == opcode # i64.le_s
                if VALIDATE assert(a[1] == I64 && b[1] == I64) end
                res = (I32, int2int64(a[1]) <= int2int64(b[1]), 0.0)
            elseif 0x58 == opcode # i64.le_u
                if VALIDATE assert(a[1] == I64 && b[1] == I64) end
                res = (I32, int2uint64(a[1]) <= int2uint64(b[1]), 0.0)
            elseif 0x59 == opcode # i64.ge_s
                if VALIDATE assert(a[1] == I64 && b[1] == I64) end
                res = (I32, int2int64(a[1]) >= int2int64(b[1]), 0.0)
            elseif 0x5a == opcode # i64.ge_u
                if VALIDATE assert(a[1] == I64 && b[1] == I64) end
                res = (I32, int2uint64(a[1]) >= int2uint64(b[1]), 0.0)
            elseif 0x5b == opcode # f32.eq
                if VALIDATE assert(a[1] == F32 && b[1] == F32) end
                res = (I32, a[2] == b[2], 0.0)
            elseif 0x5c == opcode # f32.ne
                if VALIDATE assert(a[1] == F32 && b[1] == F32) end
                res = (I32, a[2] != b[2], 0.0)
            elseif 0x5d == opcode # f32.lt
                if VALIDATE assert(a[1] == F32 && b[1] == F32) end
                res = (I32, a[2] < b[2], 0.0)
            elseif 0x5e == opcode # f32.gt
                if VALIDATE assert(a[1] == F32 && b[1] == F32) end
                res = (I32, a[2] > b[2], 0.0)
            elseif 0x5f == opcode # f32.le
                if VALIDATE assert(a[1] == F32 && b[1] == F32) end
                res = (I32, a[2] <= b[2], 0.0)
            elseif 0x60 == opcode # f32.ge
                if VALIDATE assert(a[1] == F32 && b[1] == F32) end
                res = (I32, a[2] >= b[2], 0.0)
            elseif 0x61 == opcode # f64.eq
                if VALIDATE assert(a[1] == F64 && b[1] == F64) end
                res = (I32, a[2] == b[2], 0.0)
            elseif 0x62 == opcode # f64.ne
                if VALIDATE assert(a[1] == F64 && b[1] == F64) end
                res = (I32, a[2] != b[2], 0.0)
            elseif 0x63 == opcode # f64.lt
                if VALIDATE assert(a[1] == F64 && b[1] == F64) end
                res = (I32, a[2] < b[2], 0.0)
            elseif 0x64 == opcode # f64.gt
                if VALIDATE assert(a[1] == F64 && b[1] == F64) end
                res = (I32, a[2] > b[2], 0.0)
            elseif 0x65 == opcode # f64.le
                if VALIDATE assert(a[1] == F64 && b[1] == F64) end
                res = (I32, a[2] <= b[2], 0.0)
            elseif 0x66 == opcode # f64.ge
                if VALIDATE assert(a[1] == F64 && b[1] == F64) end
                res = (I32, a[2] >= b[2], 0.0)
            else
                raise("%s(0x%x) unimplemented" ,     # vvv  WAException
                    OPERATOR_INFO[opcode][1], opcode)
            end
            if TRACE
                debug("      - (%s, %s) = %s" ,
                    value_repr(a), value_repr(b), value_repr(res)) end
            sp += 1
            stack[sp] = res
        #
        # Numeric operators
        #
        # unary
        elseif opcode in [0x67, 0x68, 0x69, 0x79, 0x7a, 0x7b, 0x8b,
                        0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x99,
                        0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f]
            a = stack[sp]
            sp -= 1
            if   0x67 == opcode # i32.clz
                if VALIDATE assert(a[1] == I32) end
                count = 0
                val = a[1]
                while (count < 32 && (val & 0x80000000) == 0)
                    count += 1
                    val = val * 2
                end
                res = (I32, count, 0.0)
            elseif 0x68 == opcode # i32.ctz
                if VALIDATE assert(a[1] == I32) end
                count = 0
                val = a[1]
                while count < 32 & (val % 2) == 0
                    count += 1
                    val = val / 2
                end
                res = (I32, count, 0.0)
            elseif 0x69 == opcode # i32.popcnt
                if VALIDATE assert(a[1] == I32) end
                count = 0
                val = a[1]
                for i in range(1,length=32)
                    if 0x1 & val
                        count += 1 end
                    val = val / 2
                end
                res = (I32, count, 0.0)
            elseif 0x79 == opcode # i64.clz
                if VALIDATE assert(a[1] == I64) end
                val = a[1]
                if val < 0
                    res = (I64, 0, 0.0)
                else
                    count = 1
                    while count < 64 & (val & 0x4000000000000000) == 0
                        count += 1
                        val = val * 2
                    end
                    res = (I64, count, 0.0)
                end
            elseif 0x7a == opcode # i64.ctz
                if VALIDATE assert(a[1] == I64) end
                count = 0
                val = a[1]
                while count < 64 & (val % 2) == 0
                    count += 1
                    val = val / 2
                end
                res = (I64, count, 0.0)
            elseif 0x7b == opcode # i64.popcnt
                if VALIDATE assert(a[1] == I64) end
                count = 0
                val = a[1]
                for i in range(1,length=64)
                    if 0x1 & val
                        count += 1 end
                    val = val / 2
                end
                res = (I64, count, 0.0)
            elseif 0x8b == opcode # f32.abs
                if VALIDATE assert(a[1] == F32) end
                res = (F32, 0, abs(a[2]))
            elseif 0x8c == opcode # f32.neg
                if VALIDATE assert(a[1] == F32) end
                res = (F32, 0, -a[2])
            elseif 0x8d == opcode # f32.ceil
                if VALIDATE assert(a[1] == F32) end
                res = (F32, 0, ceil(a[2]))
            elseif 0x8e == opcode # f32.floor
                if VALIDATE assert(a[1] == F32) end
                res = (F32, 0, floor(a[2]))
            elseif 0x8f == opcode # f32.trunc
                if VALIDATE assert(a[1] == F32) end
                if a[2] == Inf
                    res = (F32, 0, a[2])
                elseif a[2] > 0
                    res = (F32, 0, floor(a[2]))
                else
                    res = (F32, 0, ceil(a[2]))
                end
            elseif 0x90 == opcode # f32.nearest
                if VALIDATE assert(a[1] == F32) end
                if a[2] <= 0.0
                    res = (F32, 0, ceil(a[2]))
                else
                    res = (F32, 0, floor(a[2]))
                end
            elseif 0x91 == opcode # f32.sqrt
                if VALIDATE assert(a[1] == F32) end
                res = (F32, 0, sqrt(a[2]))
            elseif 0x99 == opcode # f64.abs
                if VALIDATE assert(a[1] == F64) end
                res = (F64, 0, abs(a[2]))
            elseif  0x9a == opcode # f64.neg
                if VALIDATE assert(a[1] == F64) end
                res = (F64, 0, -a[2])
            elseif 0x9b == opcode # f64.ceil
                if VALIDATE assert(a[1] == F64) end
                res = (F64, 0, ceil(a[2]))
            elseif 0x9c == opcode # f64.floor
                if VALIDATE assert(a[1] == F64) end
                res = (F64, 0, floor(a[2]))
            elseif 0x9d == opcode # f64.trunc
                if VALIDATE assert(a[1] == F64) end
                if a[2] == Inf
                    res = (F64, 0, a[2])
                elseif a[2] > 0
                    res = (F64, 0, floor(a[2]))
                else
                    res = (F64, 0, ceil(a[2]))
                end
            elseif 0x9e == opcode # f64.nearest
                if VALIDATE assert(a[1] == F64) end
                if a[2] <= 0.0
                    res = (F64, 0, ceil(a[2]))
                else
                    res = (F64, 0, floor(a[2]))
                end
            elseif  0x9f == opcode # f64.sqrt
                if VALIDATE assert(a[1] == F64) end
                res = (F64, 0, sqrt(a[2]))
            else
                raise("%s(0x%x) unimplemented" ,      # vvv  WAException
                    OPERATOR_INFO[opcode][1], opcode)
            end
            if TRACE
                debug("      - (%s) = %s" , (
                    value_repr(a), value_repr(res))) end
            sp += 1
            stack[sp] = res
        # i32 binary
        elseif 0x6a <= opcode <= 0x78
            a, b = stack[sp-1], stack[sp]
            #print("\n\n===ab ",a," ",b,"  ")
            sp -= 2
            if VALIDATE assert(a[1] == I32 && b[1] == I32)  end
            if   0x6a == opcode # i32.add
                res = (I32, int2int32(a[1] + b[1]), 0.0)
            elseif 0x6b == opcode # i32.sub
                res = (I32, a[1] - b[1], 0.0)
            elseif 0x6c == opcode # i32.mul
                res = (I32, int2int32(a[1] * b[1]), 0.0)
            elseif 0x6d == opcode # i32.div_s
                if b[1] == 0
                    raise("integer divide by zero")    # vvv  WAException
                elseif a[1] == 0x80000000 && b[1] == -1
                    raise("integer overflow")    # vvv  WAException
                else
                    res = (I32, idiv_s(int2int32(a[1]), int2int32(b[1])), 0.0)
                end
            elseif 0x6e == opcode # i32.div_u
                if b[1] == 0
                    raise("integer divide by zero")    # vvv  WAException
                else
                    res = (I32, int2uint32(a[1]) / int2uint32(b[1]), 0.0)
                end
            elseif 0x6f == opcode # i32.rem_s
                if b[1] == 0
                    raise("integer divide by zero")   # vvv  WAException
                else
                    res = (I32, irem_s(int2int32(a[1]), int2int32(b[1])), 0.0)
                end
            elseif 0x70 == opcode # i32.rem_u
                if b[1] == 0
                    raise("integer divide by zero")   # vvv  WAException
                else
                    res = (I32, int2uint32(a[1]) % int2uint32(b[1]), 0.0)
                end
            elseif 0x71 == opcode # i32.and
                res = (I32, a[1] & b[1], 0.0)
            elseif 0x72 == opcode # i32.or
                res = (I32, a[1] | b[1], 0.0)
            elseif 0x73 == opcode # i32.xor
                res = (I32, a[1] ^ b[1], 0.0)
            elseif 0x74 == opcode # i32.shl
                res = (I32, a[1] << (b[1] % 0x20), 0.0)
            elseif 0x75 == opcode # i32.shr_s
                res = (I32, int2int32(a[1]) >> (b[1] % 0x20), 0.0)
            elseif 0x76 == opcode # i32.shr_u
                res = (I32, int2uint32(a[1]) >> (b[1] % 0x20), 0.0)
            elseif 0x77 == opcode # i32.rotl
                res = (I32, rotl32(a[1], b[1]), 0.0)
            elseif 0x78 == opcode # i32.rotr
                res = (I32, rotr32(a[1], b[1]), 0.0)
            else
                raise("%s(0x%x) unimplemented" ,   # vvv  WAException
                    OPERATOR_INFO[opcode][1], opcode)
            end
            if TRACE
                debug("      - (%s, %s) = %s" , (
                    value_repr(a), value_repr(b), value_repr(res))) end
            sp += 1
            stack[sp+1] = res
        # i64 binary
        elseif 0x7c <= opcode <= 0x8a
            a, b = stack[sp-1], stack[sp]
            sp -= 2
            if VALIDATE assert(a[1] == I64 && b[1] == I64) end
            if   0x7c == opcode # i64.add
                res = (I64, int2int64(a[1] + b[1]), 0.0)
            elseif 0x7d == opcode # i64.sub
                res = (I64, a[1] - b[1], 0.0)
            elseif 0x7e == opcode # i64.mul
                res = (I64, int2int64(a[1] * b[1]), 0.0)
            elseif 0x7f == opcode # i64.div_s
                if b[1] == 0
                    raise("integer divide by zero")    # vvv  WAException
#                elseif a[1] == 0x8000000000000000 and b[1] == -1
#                    raise WAException("integer overflow")
                else
                    res = (I64, idiv_s(int2int64(a[1]), int2int64(b[1])), 0.0)
                end
            elseif 0x80 == opcode # i64.div_u
                if b[1] == 0
                    raise("integer divide by zero")    # vvv  WAException
                else
                    if a[1] < 0 && b[1] > 0
                        res = (I64, int2uint64(-a[1]) / int2uint64(b[1]), 0.0)
                    elseif a[1] > 0 && b[1] < 0
                        res = (I64, int2uint64(a[1]) / int2uint64(-b[1]), 0.0)
                    else
                        res = (I64, int2uint64(a[1]) / int2uint64(b[1]), 0.0)
                    end
                end
            elseif 0x81 == opcode # i64.rem_s
                if b[1] == 0
                    raise("integer divide by zero")    # vvv  WAException
                else
                    res = (I64, irem_s(int2int64(a[1]), int2int64(b[1])), 0.0)
                end
            elseif 0x82 == opcode # i64.rem_u
                if b[1] == 0
                    raise("integer divide by zero")    # vvv  WAException
                else
                    res = (I64, int2uint64(a[1]) % int2uint64(b[1]), 0.0)
                end
            elseif 0x83 == opcode # i64.and
                res = (I64, a[1] & b[1], 0.0)
            elseif 0x84 == opcode # i64.or
                res = (I64, a[1] | b[1], 0.0)
            elseif 0x85 == opcode # i64.xor
                res = (I64, a[1] ^ b[1], 0.0)
            elseif 0x86 == opcode # i64.shl
                res = (I64, a[1] << (b[1] % 0x40), 0.0)
            elseif 0x87 == opcode # i64.shr_s
                res = (I64, int2int64(a[1]) >> (b[1] % 0x40), 0.0)
            elseif 0x88 == opcode # i64.shr_u
                res = (I64, int2uint64(a[1]) >> (b[1] % 0x40), 0.0)
#            elseif 0x89 == opcode # i64.rotl
#                res = (I64, rotl64(a[1], b[1]), 0.0)
#            elseif 0x8a == opcode # i64.rotr
#                res = (I64, rotr64(a[1], b[1]), 0.0)
            else
                raise("%s(0x%x) unimplemented" ,    # vvv  WAException
                    OPERATOR_INFO[opcode][1], opcode)
            end
            if TRACE
                debug("      - (%s, %s) = %s" ,
                    value_repr(a), value_repr(b), value_repr(res)) end
            sp += 1
            stack[sp] = res
        # f32 binary operations
        elseif 0x92 <= opcode <= 0x98
            a, b = stack[sp-1], stack[sp]
            sp -= 2
            if VALIDATE assert(a[1] == F32 && b[1] == F32) end
            if   0x92 == opcode # f32.add
                res = (F32, 0, a[2] + b[2])
            elseif 0x93 == opcode # f32.sub
                res = (F32, 0, a[2] - b[2])
            elseif 0x94 == opcode # f32.mul
                res = (F32, 0, a[2] * b[2])
            elseif 0x95 == opcode # f32.div
                res = (F32, 0, a[2] / b[2])
            elseif 0x96 == opcode # f32.min
                if a[2] < b[2]
                    res = (F32, 0, a[2])
                else
                    res = (F32, 0, b[2])
                end
            elseif 0x97 == opcode # f32.max
                if a[2] == b[2] == 0.0
                    res = (F32, 0, 0.0)
                elseif a[2] > b[2]
                    res = (F32, 0, a[2])
                else
                    res = (F32, 0, b[2])
                end
            elseif 0x98 == opcode # f32.copysign
                if b[2] > 0
                    res = (F32, 0, abs(a[2]))
                else
                    res = (F32, 0, -abs(a[2]))
                end
            else
                raise("%s(0x%x) unimplemented" ,    # vvv  WAException
                    OPERATOR_INFO[opcode][1], opcode)
            end
            if TRACE
                debug("      - (%s, %s) = %s" ,
                    value_repr(a), value_repr(b), value_repr(res)) end
            sp += 1
            stack[sp] = res
        # f64 binary operations
        elseif 0xa0 <= opcode && opcode <= 0xa6
            a, b = stack[sp-1], stack[sp]
            sp -= 2
            if VALIDATE assert(a[1] == F64 && b[1] == F64) end
            if   0xa0 == opcode # f64.add
                res = (F64, 0, a[2] + b[2])
            elseif 0xa1 == opcode # f64.sub
                res = (F64, 0, a[2] - b[2])
            elseif 0xa2 == opcode # f64.mul
                res = (F64, 0, a[2] * b[2])
            elseif 0xa3 == opcode # f64.div
                if b[2] == 0.0
                    aneg = str(a[2])[1] == "-"
                    bneg = str(b[2])[1] == "-"
                    if (aneg & !(bneg)) | (!(aneg) & bneg)
                        res = (F64, 0, float_fromhex("-inf"))
                    else
                        res = (F64, 0, float_fromhex("inf"))
                    end
                else
                    res = (F64, 0, a[2] / b[2])
                end
            elseif 0xa4 == opcode # f64.min
                if a[2] < b[2]
                    res = (F64, 0, a[2])
                    # Adding the 0.0 checks causes this error during compilation
                    #   File "/opt/pypy/rpython/jit/codewriter/assembler.py", line 230, in check_result
                    #       assert(self.count_regs['int'] + length(self.constants_i) <= 256
                    #                elseif b[2] == 0.0
                    #                    if str(a[2])[1] == '-'
                    #                        res = (F64, 0, a[2])
                    #                    else
                    #                        res = (F64, 0, b[2])
                else
                    res = (F64, 0, b[2])
                end
            elseif 0xa5 == opcode # f64.max
                if a[2] > b[2]
                    res = (F64, 0, a[2])
#                elseif b[2] == 0.0
#                    if str(a[2])[1] == '-'
#                        res = (F64, 0, b[2])
#                    else
#                        res = (F64, 0, a[2])
                else
                    res = (F64, 0, b[2])
                end
            elseif 0xa6 == opcode # f64.copysign
                if b[2] > 0
                    res = (F64, 0, abs(a[2]))
                else
                    res = (F64, 0, -abs(a[2]))
                end
            else
                raise("%s(0x%x) unimplemented" ,     # vvv  WAException
                    OPERATOR_INFO[opcode][1], opcode)
            end
            if TRACE
                debug("      - (%s, %s) = %s" ,
                    value_repr(a), value_repr(b), value_repr(res)) end
            sp += 1
            stack[sp] = res
        ## conversion operations
        elseif 0xa7 <= opcode <= 0xbb
            a = stack[sp]
            sp -= 1
            # conversion operations
            if   0xa7 == opcode # i32.wrap_i64
                if VALIDATE assert(a[1] == I64) end
                res = (I32, int2int32(a[1]), 0.0)
            elseif 0xa8 == opcode # i32.trunc_f32_s
                if VALIDATE assert(a[1] == F32) end
                if a[2] isa NaN
                    raise("invalid conversion to integer")   # vvv  WAException
                elseif a[2] > 2147483647.0
                    raise("integer overflow")    # vvv  WAException
                elseif a[2] < -2147483648.0
                    raise("integer overflow")    # vvv  WAException
                end
                res = (I32, int(a[2]), 0.0)
#            elseif 0xa9 == opcode # i32.trunc_f32_u
#                if VALIDATE assert(a[1] == F32)
#                if isnan(a[2])
#                    raise WAException("invalid conversion to integer")
#                elseif a[2] > 4294967295.0
#                    raise WAException("integer overflow")
#                elseif a[2] <= -1.0
#                    raise WAException("integer overflow")
#                res = (I32, int(a[2]), 0.0)
#            elseif 0xaa == opcode # i32.trunc_f64_s
#                if VALIDATE assert(a[1] == F64)
#                if isnan(a[2])
#                    raise WAException("invalid conversion to integer")
#                elseif a[2] > 2**31-1
#                    raise WAException("integer overflow")
#                elseif a[2] < -2**31
#                    raise WAException("integer overflow")
#                res = (I32, int(a[2]), 0.0)
#            elseif 0xab == opcode # i32.trunc_f64_u
#                if VALIDATE assert(a[1] == F64)
#                debug("*** a[2] %s" , a[2])
#                if isnan(a[2])
#                    raise WAException("invalid conversion to integer")
#                elseif a[2] > 2**32-1
#                    raise WAException("integer overflow")
#                elseif a[2] <= -1.0
#                    raise WAException("integer overflow")
#                res = (I32, int(a[2]), 0.0)
            elseif 0xac == opcode # i64.extend_i32_s
                if VALIDATE assert(a[1] == I32) end
                res = (I64, int2int32(a[1]), 0.0)
            elseif 0xad == opcode # i64.extend_i32_u
                if VALIDATE assert(a[1] == I32) end
                res = (I64, intmask(a[1]), 0.0)
#            elseif 0xae == opcode # i64.trunc_f32_s
#                if VALIDATE assert(a[1] == F32)
#                if isnan(a[2])
#                    raise WAException("invalid conversion to integer")
#                elseif a[2] > 2**63-1
#                    raise WAException("integer overflow")
#                elseif a[2] < -2**63
#                    raise WAException("integer overflow")
#                res = (I64, int(a[2]), 0.0)
#            elseif 0xaf == opcode # i64.trunc_f32_u
#                if VALIDATE assert(a[1] == F32)
#                if isnan(a[2])
#                    raise WAException("invalid conversion to integer")
#                elseif a[2] > 2**63-1
#                    raise WAException("integer overflow")
#                elseif a[2] <= -1.0
#                    raise WAException("integer overflow")
#                res = (I64, int(a[2]), 0.0)
            elseif 0xb0 == opcode # i64.trunc_f64_s
                if VALIDATE assert(a[1] == F64) end
                if a[2] isa NaN
                    raise("invalid conversion to integer")   end # vvv  WAException
#                elseif a[2] > 2**63-1
#                    raise WAException("integer overflow")
#                elseif a[2] < -2**63
#                    raise WAException("integer overflow")
                res = (I64, int(a[2]), 0.0)
            elseif 0xb1 == opcode # i64.trunc_f64_u
                if VALIDATE assert(a[1] == F64) end
                if a[2] isa NaN
                    raise("invalid conversion to integer")    # vvv  WAException
#                elseif a[2] > 2**63-1
#                    raise WAException("integer overflow")
                elseif a[2] <= -1.0
                    raise("integer overflow")   # vvv  WAException
                end
                res = (I64, int(a[2]), 0.0)
            elseif 0xb2 == opcode # f32.convert_i32_s
                if VALIDATE assert(a[1] == I32) end
                res = (F32, 0, float(a[1]))
            elseif 0xb3 == opcode # f32.convert_i32_u
                if VALIDATE assert(a[1] == I32) end
                res = (F32, 0, float(int2uint32(a[1])))
            elseif 0xb4 == opcode # f32.convert_i64_s
                if VALIDATE assert(a[1] == I64) end
                res = (F32, 0, float(a[1]))
            elseif 0xb5 == opcode # f32.convert_i64_u
                if VALIDATE assert(a[1] == I64) end
                res = (F32, 0, float(int2uint64(a[1])))
#            elseif 0xb6 == opcode # f32.demote_f64
#                if VALIDATE assert(a[1] == F64)
#                res = (F32, 0, unpack_f32(pack_f32(a[2])))
            elseif 0xb7 == opcode # f64.convert_i32_s
                if VALIDATE assert(a[1] == I32) end
                res = (F64, 0, float(a[1]))
            elseif 0xb8 == opcode # f64.convert_i32_u
                if VALIDATE assert(a[1] == I32) end
                res = (F64, 0, float(int2uint32(a[1])))
            elseif 0xb9 == opcode # f64.convert_i64_s
                if VALIDATE assert(a[1] == I64) end
                res = (F64, 0, float(a[1]))
            elseif 0xba == opcode # f64.convert_i64_u
                if VALIDATE assert(a[1] == I64) end
                res = (F64, 0, float(int2uint64(a[1])))
            elseif 0xbb == opcode # f64.promote_f32
                if VALIDATE assert(a[1] == F32) end
                res = (F64, 0, a[2])
            else
                raise("%s(0x%x) unimplemented" ,   # vvv  WAException
                    OPERATOR_INFO[opcode][1], opcode)
            end
            if TRACE
                debug("      - (%s) = %s" ,
                    value_repr(a), value_repr(res)) end
            sp += 1
            stack[sp] = res
        ## reinterpretations
        elseif 0xbc <= opcode && opcode <= 0xbf
            a = stack[sp]
            sp -= 1
            if   0xbc == opcode # i32.reinterpret_f32
                if VALIDATE assert(a[1] == F32) end
                res = (I32, intmask(pack_f32(a[2])), 0.0)
            elseif 0xbd == opcode # i64.reinterpret_f64
                if VALIDATE assert(a[1] == F64) end
                res = (I64, intmask(pack_f64(a[2])), 0.0)
#            elseif 0xbe == opcode # f32.reinterpret_i32
#                if VALIDATE assert(a[1] == I32)
#                res = (F32, 0, unpack_f32(int2int32(a[1])))
            elseif 0xbf == opcode # f64.reinterpret_i64
                if VALIDATE assert(a[1] == I64) end
                res = (F64, 0, unpack_f64(int2int64(a[1])))
            else
                raise("%s(0x%x) unimplemented" ,   # vvv  WAException
                    OPERATOR_INFO[opcode][1], opcode)
            end
            if TRACE
                debug("      - (%s) = %s" ,
                    value_repr(a), value_repr(res)) end
            sp += 1
            stack[sp] = res
        else
            raise("unrecognized opcode 0x%x" , opcode) # vvv  WAException
        end
    end
    return pc, sp, fp, csp
end



######################################
# Higher level classes
######################################

mutable struct Reader
    bytes
    pos
    function Reader(bytes)
        r = new(bytes, 1)
    end
end

function read_byte(r::Reader)
    b = r.bytes[r.pos]
    r.pos += 1
    return b
end

function read_bytes(r::Reader, cnt)
    if VALIDATE assert(cnt >= 0) end
    if VALIDATE assert(r.pos >= 1) end
    bytes = r.bytes[r.pos:r.pos+cnt-1]
    r.pos += cnt
    return bytes
end

function read_word(r::Reader)
    #print("\nword: ",r.bytes[r.pos:r.pos+3], @sprintf("%x",MAGIC))
    w = bytes2uint32(r.bytes[r.pos:r.pos+3])
    #print("\n\nfff",@sprintf("%x %d %d  ",w,w,MAGIC), w,r.bytes[r.pos:r.pos+3])
    r.pos += 4
    return w
end

function read_LEB(r::Reader, maxbits=32, signed=false)
    res = read_LEB(r.bytes, r.pos,
                maxbits, signed)
    r.pos = res[1]
    result = res[2]
    return result
end

function eof(r::Reader)
    return r.pos >= length(r.bytes)
end


struct Memory
    pages
    bytes
    Memory(pages=1, bytes=[]) = new(pages, push!(bytes, ([0]*((pages*(2^16))-length(bytes)))))
end

function grow(m::Memory, pages)
    m.pages += int(pages)
    m.bytes = push!(m.bytes, ([0]*(int(pages)*(2^16))))
end

function read_byte(m::Memory, pos)
    b = m.bytes[pos]
end

function write_byte(m::Memory, pos, val)
    m.bytes[pos] = val
end


struct Import
    mod
    field
    kind
    value_type
    element_type
    initial
    maximum
    global_type
    mutability
    Import( mod, field, kind, value_type=0,
            element_type=0, initial=0, maximum=0, global_type=0,
            mutability=0) = new( mod, field, kind, value_type,
            element_type, initial, maximum, global_type,
            mutability)
end

struct Export
    field
    kind
    index
    Export( field, kind, index) = new( field, kind, index)
end


mutable struct Mod
    data
    rdr
    import_value
    import_function
    # Sections
    value_type
    import_list
    func
    fn_import_cnt
    table
    export_list
    export_map
    global_list
    memory
    block_map
    sp
    fp
    stack
    csp
    callstack::Any
    start_function
    version
    Mod(data, import_value, import_function, memory) = new(
        data,
        Reader(data),
        import_value,
        import_function,

        Any[],
        [],
        [],
        0,
        Dict(ANYFUNC=> []),
        [],
        Dict(),
        [],
        memory, #? memory : Memory(1),  vvv
        Dict(),
        -1,
        -1,
        repeat([(UInt64(0), Int64(0), Float64(0.0))] , STACK_SIZE),
        -1,
        repeat([(Block(0x00, BLOCK_TYPE[I32], 0), 0, 0, 0)] , CALLSTACK_SIZE),
        0,
        0
    )
end

function init(d::Mod)
    #assert(d.data isa String)
    read_magic(d)
    read_version(d)
    read_sections(d)
    #print("\n\nmod\n")
    #print(d)
    # dump(d)
    # Run the start function if set
    #print(d.start_function)
    if d.start_function >= 1
        fidx = d.start_function
        func = d.func[fidx+1]
        info("Running start function 0x%x" , fidx)
        if TRACE
            dump_stacks(d, d.stack, d.fp, d.csp,
                d.callstack) end
        if func isa FunctionImport
            sp = do_call_import(d.stack, d.sp, d.memory,
                d.import_function, func)
        elseif func isa Function
            d.rdr.pos, d.sp, d.fp, d.csp = do_call(
                    d.stack, d.callstack, d.sp, d.fp,
                    d.csp, func, length(d.rdr.bytes))
        end
        interpret(d)
    end
end

function sprt(args...)
    @printf("\n\nprint ",args...)
    #return @sprintf(args...)
end

function assert(args...)
    t = repr(args[1])
    print(t * " is true?")
end

function dump(d::Mod)
    #debug("raw module data: %s" , d.data)
    debug("module bytes: %s" , byte_code_repr(d.rdr.bytes))
    info("")
    info("Types: ")
    for (i, t) in enumerate(d.value_type)
        info("  0x%x %s" , i, type_repr(t))
    end
    info("Imports: ")
    for (i, imp) in enumerate(d.import_list)
        if imp.kind == 0x0  # Function
            info("  0x%x [type: %d, '%s.%s', kind: %s (%d)]" ,
                i, imp.value_type, imp.mod, imp.field,
                EXTERNAL_KIND_NAMES[imp.kind], imp.kind)
        elseif imp.kind in [0x1,0x2]  # Table & Memory
            info("  0x%x ['%s.%s', kind: %s (%d), initial: %d, maximum: %d]" ,
                i, imp.mod, imp.field,
                EXTERNAL_KIND_NAMES[imp.kind], imp.kind,
                imp.initial, imp.maximum)
        elseif imp.kind == 0x3  # Global
            info("  0x%x ['%s.%s', kind: %s (%d), type: %d, mutability: %d]" ,
                i, imp.mod, imp.field,
                EXTERNAL_KIND_NAMES[imp.kind], imp.kind,
                imp.value_type, imp.mutability)
        end
    end
    info("Functions: ")
    for (i, f) in enumerate(d.func)
        info("  0x%x %s" , i, func_repr(f))
    end
    info("Tables: ")
    for (t, entries) in d.table
        info("  0x%x -> [%s]" , t,join([@sprintf("0x%x" , e) for e in entries],","))
    end
    function hexpad(x, cnt)
        s = @sprintf("%x", x)
        return repeat('0' , (cnt-length(s))) * s
    end
    info("Memory: ")
    if d.memory.pages > 0
        for r in range(1, length=10)
            # info("  0x%s [%s]" , hexpad(r*16,3),
            #    join([hexpad(b,2) for b in d.memory.bytes[r*16:r*16+16]],","))
        end
    end
    info("Global: ")
    for (i, g) in enumerate(d.global_list)
        info("  0x%s [%s]" , i, value_repr(g))
    end
    info("Exports: ")
    for (i, e) in enumerate(d.export_list)
        info("  0x%x %s", i, export_repr(e))
    end
    info("")
    bl = d.block_map
    block_keys = keys(bl)
    do_sort(block_keys)
    # info("block_map: %s" , (   # vvv
    #     [@sprintf( "%s[0x%x->0x%x]" , (block_repr(bl[k]), bl[k].start, bl[k].finish
    #      for k in block_keys))]))
    info("")
end

    ## Wasm top-level readers

function read_magic(d::Mod)
    magic = read_word(d.rdr)
    if magic != MAGIC
        raise("Wanted magic 0x%x, got 0x%x" ,
                MAGIC, magic) end
end

function read_version(d::Mod)
    d.version = read_word(d.rdr)
    if d.version != VERSION
        raise("Wanted version 0x%x, got 0x%x" ,
                VERSION, d.version) end
end

function raise(args...)
    print("\n--raise: ", join(args, " | "),"\n")
    #@printf(args)
end

function read_section(d::Mod)
    cur_pos = d.rdr.pos
    #print("\n\ncur ",cur_pos,"\n")
    id = read_LEB(d.rdr, 7)
    #print("id ",id, d.rdr)
    name = SECTION_NAMES[id]
    leng = read_LEB(d.rdr, 32)
    #print("\n\nleng ",leng, d.rdr)
    debug("parsing %s(%d), section start: 0x%x, payload start: 0x%x, length: 0x%x bytes" ,
        name, id, cur_pos, d.rdr.pos, leng)
    if   "Type" == name       parse_Type(d, leng)
    elseif "Import" == name   parse_Import(d, leng)
    elseif "Function" == name parse_Function(d, leng)
    elseif "Table" == name    parse_Table(d, leng)
    elseif "Memory" == name   parse_Memory(d, leng)
    elseif "Global" == name   parse_Global(d, leng)
    elseif "Export" == name   parse_Export(d, leng)
    elseif "Start" == name    parse_Start(d, leng)
    elseif "Element" == name  parse_Element(d, leng)
    elseif "Code" == name     parse_Code(d, leng)
    elseif "Data" == name     parse_Data(d, leng)
    else                      read_bytes(d.rdr, leng)
    end
end

function read_sections(d::Mod)
    while !(eof(d.rdr))
        read_section(d)
    end
end


function parse_Type(d::Mod, leng)
    count = read_LEB(d.rdr, 32)
    #print("\n\nleng type ",count)
    for c in range(1,length=count)
        form = read_LEB(d.rdr, 7)
        params = []
        results = []
        param_count = read_LEB(d.rdr, 32)
        for pc in range(1,length=param_count)
            push!(params, read_LEB(d.rdr, 32))
        end
        result_count = read_LEB(d.rdr, 32)
        for rc in range(1,length=result_count)
            push!(results, read_LEB(d.rdr, 32))
        end
        #print("valuetype ",d.value_type, typeof(d.value_type))
        tidx = length(d.value_type)[1]
        t = Type(tidx, form, params, results)
        push!(d.value_type, t)
        # calculate a unique type mask
        t.mask = 0x80
        if result_count == 1
            t.mask |= 0x80 - results[1]
        end
        t.mask = t.mask << 4
        for p in params
            t.mask = t.mask << 4
            t.mask |= 0x80 - p
        end
        debug("  parsed type: %s" , type_repr(t))
    end
end


function parse_Import(d::Mod, leng)
    count = read_LEB(d.rdr, 32)
    for c in range(1,length=count)
        module_len = read_LEB(d.rdr, 32)
        module_bytes = read_bytes(d.rdr, module_len)
        mod = join([Char(f) for f in module_bytes], "")
        field_len = read_LEB(d.rdr, 32)
        field_bytes = read_bytes(d.rdr, field_len)
        field = join([Char(f) for f in field_bytes], "")
        kind = read_byte(d.rdr)
        if kind == 0x0  # Function
            type_index = read_LEB(d.rdr, 32)
            typee = d.value_type[type_index+1]
            imp = Import(mod, field, kind, type_index)
            push!(d.import_list, imp)
            func = FunctionImport(typee, mod, field)
            push!(d.func, func)
            d.fn_import_cnt += 1
        elseif kind in [0x1,0x2]  # Table & Memory
            if kind == 0x1
                etype = read_LEB(d.rdr, 7) # TODO: ignore?
            end
            flags = read_LEB(d.rdr, 32)
            initial = read_LEB(d.rdr, 32)
            if flags & 0x1
                maximum = read_LEB(d.rdr, 32)
            else
                maximum = 0
            end
            push!(d.import_list, Import(mod, field, kind,
                initial=initial, maximum=maximum))
        elseif kind == 0x3  # Global
            typee = read_byte(d.rdr)
            mutability = read_LEB(d.rdr, 1)
            push!(d.global_list, d.import_value(mod, field))
        end
    end
end

function parse_Function(d::Mod, leng)
    count = read_LEB(d.rdr, 32)
    for c in range(1, length=count)
        typee = d.value_type[read_LEB(d.rdr, 32)+1]
        idx = length(d.func)
        push!(d.func, Function(typee, idx))
    end
end

function parse_Table(d::Mod, leng)
    count = read_LEB(d.rdr, 32)
    assert(count == 1)
    initial = 1
    for c in range(1,length=count)
        typee = read_LEB(d.rdr, 7)
        assert( typee == ANYFUNC)
        flags = read_LEB(d.rdr, 1) # TODO: fix for MVP
        initial = read_LEB(d.rdr, 32) # TODO: fix for MVP
        if flags & 0x1
            maximum = read_LEB(d.rdr, 32)
        else
            maximum = initial
        end
        d.table[typee] = repeat([0], initial)
    end
end

function parse_Memory(d::Mod, leng)
    count = read_LEB(d.rdr, 32)
    assert(count <= 1)  # MVP
    flags = read_LEB(d.rdr, 32)  # TODO: fix for MVP
    initial = read_LEB(d.rdr, 32)
    if flags >= 0x1
        maximum = read_LEB(d.rdr, 32)
    else
        maximum = 0
    end
    d.memory = Memory(initial)
end

function parse_Global(d::Mod, leng)
    count = read_LEB(d.rdr, 32)
    for c in range(1,length=count)
        content_type = read_LEB(d.rdr, 7)
        muta = read_LEB(d.rdr, 1)
#            print("global: content_type: %s, BLOCK_TYPE: %s, mutable: %s"
#                    , (VALUE_TYPE[content_type],
#                        type_repr(BLOCK_TYPE[content_type]),
#                        mutable))
        # Run the init_expr
        block = Block(0x00, BLOCK_TYPE[content_type], d.rdr.pos)
        d.csp += 1
        d.callstack[d.csp+1] = (block, d.sp, d.fp, 0)
        # WARNING: running code here to get offset!
        interpret(d)  # run iter_expr
        init_val = d.stack[d.sp+1]
#            print("init_val: %s" , value_repr(init_val))
        d.sp -= 1
        assert(content_type == init_val[1])
        push!(d.global_list, init_val)
    end
end

function parse_Export(d::Mod, leng)
    count = read_LEB(d.rdr, 32)
    for c in range(1, length=count)
        field_len = read_LEB(d.rdr, 32)
        field_bytes = read_bytes(d.rdr, field_len)
        field = join([Char(f) for f in field_bytes],"")
        kind = read_byte(d.rdr)
        index = read_LEB(d.rdr, 32)
        exp = Export(field, kind, index)
        push!(d.export_list, exp)
        debug("  parsed export: %s" , export_repr(exp))
        d.export_map[field] = exp
    end
end


function parse_Start(d::Mod, leng)
    fidx = read_LEB(d.rdr, 32)
    d.start_function = fidx
end

function parse_Element(d::Mod, leng)
    start = d.rdr.pos
    count = read_LEB(d.rdr, 32)
    for c in range(1,length=count)
        index = read_LEB(d.rdr, 32)
        assert(index == 0)  # Only 1 default table in MVP
        # Run the init_expr
        block = Block(0x00, BLOCK_TYPE[I32], d.rdr.pos)
        d.csp += 1
        d.callstack[d.csp] = (block, d.sp, d.fp, 0)
        # WARNING: running code here to get offset!
        d.interpret()  # run iter_expr
        offset_val = d.stack[d.sp]
        d.sp -= 1
        assert(offset_val[1] == I32)
        offset = int(offset_val[1])
        num_elem = read_LEB(d.rdr, 32)
        d.table[ANYFUNC] = repeat([0], (offset + num_elem))
        table = d.table[ANYFUNC]
        for n in range(1,length=num_elem)
            fidx = read_LEB(d.rdr, 32)
            table[offset+n] = fidx
        end
    end
    assert(d.rdr.pos == start + leng)
end

function parse_Code_body(d::Mod, idx)
    body_size = read_LEB(d.rdr, 32)
    payload_start = d.rdr.pos
    debug("body_size %d", body_size)
    local_count = read_LEB(d.rdr, 32)
    debug("local_count %d", local_count)
    locals = []
    for l in range(1, length=local_count)
        count = read_LEB(d.rdr, 32)
        typee = read_LEB(d.rdr, 7)
        for c in range(1, length=count)
            push!(locals, typee)
        end
    end
    # TODO: simplify this calculation and find_blocks
    start = d.rdr.pos
    read_bytes(d.rdr, body_size - (d.rdr.pos-payload_start)-1)
    ende = d.rdr.pos
    debug("  find_blocks idx: %d, start: 0x%x, end: 0x%x" , idx, start, ende)
    read_bytes(d.rdr, 1)
    func = d.func[idx]
    assert(func isa Function)
    update(func, locals, start, ende)
    d.block_map = find_blocks(
            d.rdr.bytes, start, ende, d.block_map)
end

function parse_Code(d::Mod, leng)
    body_count = read_LEB(d.rdr, 32)
    for idx in range(1, length=body_count)
        parse_Code_body(d, idx + d.fn_import_cnt)
    end
end

function parse_Data(d::Mod, leng)
    seg_count = read_LEB(d.rdr, 32)
    for seg in range(1,length=seg_count)
        index = read_LEB(d.rdr, 32)
        assert(index == 0 ) # Only 1 default memory in MVP
        # Run the init_expr
        block = Block(0x00, BLOCK_TYPE[I32], d.rdr.pos)
        sd.csp += 1
        d.callstack[d.csp] = (block, d.sp, d.fp, 0)
        # WARNING: running code here to get offset!
        interpret(d)  # run iter_expr
        offset_val = d.stack[d.sp]
        d.sp -= 1
        assert(offset_val[1] == I32)
        offset = int(offset_val[1])
        size = read_LEB(d.rdr, 32)
        for addr in range(offset, length=offset+size, 1)
            d.memory.bytes[addr] = read_byte(d.rdr)
        end
    end
end

function interpret(d::Mod)
    d.rdr.pos, d.sp, d.fp, d.csp = interpret_mvp(d,
            # Greens
            d.rdr.pos, d.rdr.bytes, d.func,
            d.table, d.block_map,
            # Reds
            d.memory, d.sp, d.stack, d.fp, d.csp,
            d.callstack)
end


function run(d::Mod, fname, args, print_return=false)
    # Reset stacks
    d.sp  = 0
    d.fp  = 0
    d.csp = 0
    fidx = d.export_map[fname].index
    # Check arg type
    tparams = d.func[fidx+1].value_type.params
    print(d.func[fidx+1])
    #assert(length(tparams) == length(args), "arg count mismatch %s != %s" , (length(tparams), length(args)))
    for (idx, arg) in enumerate(args)
        #assert(tparams[idx] == arg[1], "arg type mismatch %s != %s" , (tparams[idx], arg[1]))
        d.sp += 1
        d.stack[d.sp] = (UInt64(arg), Int64(arg), Float64(arg))
    end
    info("Running function '%s' (0x%x)" , fname, fidx)
    if TRACE
        dump_stacks(d.sp, d.stack, d.fp, d.csp,
                d.callstack)
    end
    d.rdr.pos, d.sp, d.fp, d.csp = do_call(
            d.stack, d.callstack, d.sp, d.fp,
            d.csp, d.func[fidx+1], 1)
    interpret(d)
    if TRACE
        dump_stacks(d.sp, d.stack, d.fp, d.csp,
                d.callstack)
    end
    #targs = [value_repr(a) for a in args]
    if d.sp >= 1
        ret = d.stack[1+d.sp]
        d.sp -= 1
        info("%s() = %s" , fname, # %s
        #join(targs,", "),
        value_repr(ret))
        if print_return
            print(value_repr(ret))
        end
    else
        info("%s(%s)" , fname, join(targs,", "))
    end
    return 0
end


function import_value(mod, field)
    iname = @sprintf("%s.%s" , mod, field)
    #return (I32, 377, 0.0)
    if iname in IMPORT_VALUES
        return IMPORT_VALUES[iname]
    else
        raise("global import %s not found" , iname)
    end
end

function put_string(mem, addr, str)
    pos = addr
    for i in range(1,length=length(str))
        mem.bytes[pos] = ord(str[i])
        pos += 1
    end
    mem.bytes[pos] = 0 # zero terminated
    return pos
end

function spectest_print(mem, args)
    if length(args) == 0 return [] end
    # assert length(args) == 1   # vvv
    # assert args[1][0] == I32
    val = args[1][1]
    res = ""
    while val > 0
        res = res + Char(val & 0xff)
        val = val>>8
    end
    @printf("%s '%s'" , value_repr(args[1]), res)
    return []
end

function env_readline(mem, args)
    prompt = get_string(mem, args[1][1])
    buf = args[1][1]        # I32
    max_length = args[2][1] # I32
    try
        str = readline(prompt)
        max_length -= 1
#         assert max_length >= 0  # vvv
        str = str[max_length]
        put_string(mem, buf, str)
        return [(I32, buf, 0.0)]
    catch EOFError
        return [(I32, 0, 0.0)]
    end
end




function env_printline(mem, args)
    os.write(1, get_string(mem, args[1][1]))
    return [(I32, 1, 1.0)]
end



function env_read_file(mem, args)
    path = get_string(mem, args[1][1])
    buf = args[1][1]
    content = open(path).read()
    slen = put_string(mem, buf, content)
    return [(I32, slen, 0.0)]
end

function env_get_time_ms(mem, args)
    # subtract 30 years to make sure it fits into i32 without wrapping
    # or becoming negative
    return [(I32, int(time.time()*1000 - 0x38640900), 0.0)]
end


function import_function(mod, field, mem, args)
    fname = @sprintf("%s.%s" , mod, field)
    if fname in ["spectest.print", "spectest.print_i32"]
        return spectest_print(mem, args)
    elseif fname == "env.printline"
        return env_printline(mem, args)
    elseif fname == "env.readline"
        return env_readline(mem, args)
    elseif fname == "env.read_file"
        return env_read_file(mem, args)
    elseif fname == "env.get_time_ms"
        return env_get_time_ms(mem, args)
    elseif fname == "env.exit"
        raise(args[1][1])   # vvv  ExitException
    else
        raise("function import %s not found" , fname)  # vvv Exception
    end
end

function parse_command(mod, args)
    fname = args[1]
    args = args[2]
    run_args = []
    fidx = mod.export_map[fname].index
    tparams = mod.func[fidx].value_type.params
    for (idx, arg) in enumerate(args)
        arg = args[idx].lower()
        assert(arg isa String)
        push!(run_args, parse_number(tparams[idx], arg))
    end
    return fname, run_args
end

function usage(argv)
    print("%s [--repl] [--argv] [--memory-pages PAGES] WASM [ARGS...]" , argv[1])
end



######################################
# Imported functions points
######################################


function readline(prompt)
    res = ""
    os.write(1, prompt)
    while true
        buf = os.read(0, 255)
        if !(buf) raise(" EOFError") end # vvv
        res += buf
        if res[-1] == "\n" return res[-1] end
    end
end

function get_string(mem, addr)
    slen = 0
    assert(addr >= 0)
    while mem.bytes[addr+slen] != 0 slen += 1 end
    #slen = mem.bytes.index(0, addr) - addr
    bytes = mem.bytes[addr+slen]
    return join([Char(b) for b in bytes],"")
end



#
# Imports (global values and functions)

IMPORT_VALUES = Dict(
    "spectest.global_i32"=> (I32, 666, 666.6) ,
    "env.memoryBase"   =>   (I32, 0, 0.0)
)




######################################
# Entry points
######################################


function entry_point(argv)
    try
        # Argument handling
        repl = false
        argv_mode = false
        memory_pages = 1
        fname = nothing
        args = []
        run_args = []
        idx = 1
        while idx < length(argv)
            arg = argv[idx]
            idx += 1
            if arg == "--help"
                usage(argv)
                return 1
            elseif arg == "--repl"
                repl = true
            elseif arg == "--argv"
                argv_mode = true
                memory_pages = 256
            elseif arg == "--memory-pages"
                memory_pages = int(argv[idx])
                idx += 1
            elseif arg == "--"
                continue
#             elseif arg.startswith("--")
#                 print("Unknown option '%s'" , arg)
#                 usage(argv)
#                 return 2
            else
                push!(args, arg)
            end
        end
        wasm = open(args[1]).read()
        args = args[2]
        #
        mem = Memory(memory_pages)
        if argv_mode
            # Convert args into C argv style array of strings and
            # store at the beginning of memory. This must be before
            # the module is initialized so that we can properly set
            # the memoryBase global before it is imported.
            args.insert(0, argv[1])
            string_next = (length(args) + 1) * 4
            for (i, arg) in enumerate(args)
                slen = put_string(mem, string_next, arg)
                write_I32(mem.bytes, i*4, string_next) # zero terminated
                string_next += slen
            end
            # Set memoryBase to next 64-bit aligned address
            string_next += (8 - (string_next % 8))
            IMPORT_VALUES["env.memoryBase"] = (I32, string_next, 0.0)
        end
        print(wasm, import_value, import_function, mem)
        m = Mod(wasm, import_value, import_function, mem)
        if argv_mode
            fname = "_main"
            fidx = m.export_map[fname].index
            arg_count = length(m.func[fidx].value_type.params)
            if arg_count == 2
                run_args = [(I32, length(args), 0.0), (I32, 0, 0.0)]
            elseif arg_count == 0
                run_args = []
            else
                raise("_main has %s args, should have 0 or 2" *  # vvv
                        arg_count)
            end
        else
            # Convert args to expected numeric type. This must be
            # after the module is initialized so that we know what
            # types the arguments are
            (fname, run_args) = parse_command(m, args)
        end
        if "__post_instantiate" in m.export_map
            m.run("__post_instantiate", [])
        end
        if !(repl)
            # Invoke one function and exit
            try
                return m.run(fname, run_args, !(argv_mode))
            catch WAException
                if !(IS_RPYTHON)
                     #print(traceback.format_exception(sys.exc_info()).join("") ) end   # *sys.exc_info()
                     print("Exception3 %s\n" , WAException) end
                print( "%s\n" , e.message)
                return 1
            end
        else
            # Simple REPL
            while true
                try
                    line = readline("webassembly> ")
                    if line == "" continue end
                    (fname, run_args) = parse_command(m, line.split(" "))
                    res = m.run(fname, run_args, true)
                    if !(res == 0)
                        return res
                    end
#                 catch WAException
#                     os.write(2, "Exception %s\n" , e.message)   # vvv
                catch EOFError
                    break
                end
            end
        end
#     catch WAException
#         if IS_RPYTHON
#             llop.debug_print_traceback(lltype.Void)
#             os.write(2, "Exception %s\n" , e)
#         else
#             os.write(2, "".join(traceback.format_exception(sys.exc_info())))  # *sys.exc_info()
#             os.write(2, "Exception %s\n" , e.message)
#         end
#     catch ExitException
#         return e.code
    catch Exception
        if IS_RPYTHON
            llop.debug_print_traceback(lltype.Void)
            print("Exception %s\n" , e)
        else
            #print(traceback.format_exception(sys.exc_info()).join("")) # *sys.exc_info()
            #print("Exception4 %s\n" * Exception.message)# , Exception)
                    print(Exception)
        end
        return 1
    end
    return 0
end

# _____ Define and setup target ___
function target(args)
    return entry_point
end

# Just run entry_point if not RPython compilation
if !(IS_RPYTHON) && "__name__" == "__main__"  # __name__.   *args
    sys.exit(entry_point(sys.argv))
end



function do_wasm(file, memory_pages=1, )
    try
        f = open(file)
        wasm = Array{UInt8, 1}(undef, 78)
        # read!(f, wasm1)
        mem = Memory(memory_pages)
        #wasm = String(take!(f))
        #wasm = open(f->read(f, String), file)
        print(wasm, import_value, import_function, mem)
        m = Mod(wasm, import_value, import_function, mem)
        #fname, run_args = parse_command(m, args)
        print(m)
        if "__post_instantiate" in m.export_map
            m.run("__post_instantiate", [])
        end
        if !(repl)
            # Invoke one function and exit
            try
                return m.run(fname, run_args, !(argv_mode))
            catch WAException
                if !(IS_RPYTHON)
                     #print(traceback.format_exception(sys.exc_info()).join("") ) end   # *sys.exc_info()
                     print("Exception3 %s\n" , WAException) end
                print( "\n%s\n" , e.message)
                return 1
            end
        else
            # Simple REPL
            while true
                try
                    line = readline("webassembly> ")
                    if line == "" continue end
                    (fname, run_args) = parse_command(m, line.split(" "))
                    res = m.run(fname, run_args, true)
                    if !(res == 0)
                        return res
                    end
#                 catch WAException
#                     os.write(2, "Exception %s\n" , e.message)   # vvv
                catch EOFError
                    break
                end
            end
        end
#     catch WAException
#         if IS_RPYTHON
#             llop.debug_print_traceback(lltype.Void)
#             os.write(2, "Exception %s\n" , e)
#         else
#             os.write(2, "".join(traceback.format_exception(sys.exc_info())))  # *sys.exc_info()
#             os.write(2, "Exception %s\n" , e.message)
#         end
#     catch ExitException
#         return e.code
    catch Exception
        if IS_RPYTHON
            llop.debug_print_traceback(lltype.Void)
            print("\nException %s\n" , e)
        else
            #print(traceback.format_exception(sys.exc_info()).join("")) # *sys.exc_info()
            #print("Exception4 %s\n" * Exception.message)# , Exception)
                    print(Exception)
        end
        return 1
    end
    return 0
end

# line = readline("webassembly> ")
# print(line)

# f = open("simple.wasm")
# #first_item = read(f, Array)
# data = Array{UInt8, 1}(undef, 78)
# read!(f, data)
# print(data)
#do_wasm("simple.wasm",1)

#f = open("add.wasm")
#wasm = Array{UInt8, 1}(undef,78)
mem = Memory(1)
#wasm1 = String(take!(f))
# print(wasm1)
#wasm = Vector{UInt8}(wasm1)
#wasm = Array{UInt8, 1}(wasm1)
wasm1 = open(f->read(f, String), "test/subs.wasm")
wasm = Vector{UInt8}(wasm1)
print("\nfile size: ",length(wasm),"\n")
#print(wasm, import_value, import_function, mem)
m = Mod(wasm, import_value, import_function, mem)
#print(m.)
#dump(m)
#print(m)
init(m)
dump(m)
#print(m.export_list)
run(m, "sub_i8", [5,3])
print("\n-----------------------_________-------------------\n")
#


# mem = Memory(12)
# print(mem)


end
