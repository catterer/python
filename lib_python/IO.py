import struct
import varint
import random
import time
from functools import total_ordering

_decoder = varint.decodeVarint32 

def RidInit_chat(id):
    return RidInit(2, id)
def RidInit(type, id):
    return OStream().putU32(id).putU16(0).putU8(0).putU8(type).data

class KustLogHdr(object):
    def __init__(self):
        self.magic      = None
        self.lsn        = None
        self.type       = None
        self.ts         = None
        self.data_len   = None
        self.data_crc   = None
        self.hdr_crc    = None
    def __repr__(self):
        return '{}/{}'.format(self.lsn, time.ctime(self.ts))

class KustMod(object):
    def __init__(self, key_printer):
        self.sid = None
        self.key = None
        self.mod_ver = None
        self.mod = None
        self.resp = None
        self.req_id = None
        self.key_printer = key_printer

    def __repr__(self):
        key = None
        if self.key_printer:
            key = self.key_printer(IStream(self.key))
        return '{}:{}'.format(key, self.mod_ver)

class Rid(object):
    def __init__(self, u64_or_type, id = 0):
        self.type = 0
        self.id = 0
        if id:
            self.type = u64_or_type
            self.id = id
        else:
            istr = IStream(OStream().putU64(u64_or_type).data)
            self.id = istr.getU32()
            self.id += istr.getU16() << 32
            self.id += istr.getU8() << 48
            self.type = istr.getU8()
    def __int__(self):
        return self.id + (self.type << 56)
    def __repr__(self):
        return '{}:{}'.format(self.type, self.id)
    def __str__(self):
        return self.__repr__()
    def __eq__(self, other):
        return int(self) == int(other)
    def __hash__(self):
        return int(self)
    def bin(self):
        return OStream().putU64(int(self)).data

@total_ordering
class MsgId(object):
    def parse(self, istr):
        self.c = istr.getU32()
        self.t = istr.getU32()
    def __eq__(self, other):
        return int(self) == int(other)

    def __lt__(self, other):
        return int(self) < int(other)

    def __init__(self, t_or_u64, c=0):
        if (c):
            if (t_or_u64 == -1):
                t_or_u64 = 2**32-1
            self.c = c
            self.t = t_or_u64
        else:
            if (t_or_u64 == -1):
                t_or_u64 = 2**64-1
            self.parse(IStream(OStream().putU64(t_or_u64).data))
    def __int__(self):
        return IStream(OStream().putU32(self.c).putU32(self.t).data).getU64()
    def __repr__(self):
        if (int(self)):
            return '{0}={1}:{2}'.format(int(self), self.t, self.c)
        else:
            return '0'
    def __hash__(self):
        return int(self)


class IStream(object):
    def __init__(self,data):
        self.data = data
        self.dlen = len(data)
        self.offset = 0

    def __str__(self):
        return str(self.data)

    def __unpack(self, fmt):
        r = struct.unpack_from(fmt, self.data, self.offset)
        self.offset += struct.calcsize(fmt)
        return r

    def expectedLen(self, methName):
        tmp = '\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
        istr = IStream(tmp)
        initLen = istr.inAvail()
        cb = getattr(istr, methName)
        cb()
        return initLen - istr.inAvail()

    def getU8(self):
        return self.__unpack('B')[0];

    def getU16(self):
        return self.__unpack('<H')[0];

    def getU32(self):
        return self.__unpack('<L')[0];

    def getKustLogHdr(self):
        kh = KustLogHdr()
        kh.magic      = self.getU32()
        kh.lsn        = self.getU64()
        kh.type       = self.getU32()
        kh.ts         = self.getU32()
        kh.data_len   = self.getU32()
        kh.data_crc   = self.getU32()
        kh.hdr_crc    = self.getU32()
        return kh

    def getKustMod(self, key_printer):
        km = KustMod(key_printer)
        km.sid        = self.getU8()
        km.key        = self.getLps().getAll()
        km.mod_ver    = self.getU64()
        km.mod        = self.getLps().getAll()
        km.resp       = self.getLps()
        km.req_id     = self.getLps().data
        return km

    def getU64(self):
        return self.__unpack('<Q')[0];

    def getRid(self):
        r = self.getU64()
        return Rid(r)

    def getMsgId(self):
        return MsgId(self.getU64())

    def getIproHdr(self):
        return self.getU32(), self.getU32(), self.getU32()
    def getLps(self):
        length = self.getU32()
        return IStream(self.__unpack('<{0}s'.format(length))[0])

    def getBlob(self, len):
        return self.__unpack('<{0}s'.format(len))[0]

    def getAll(self):
        return self.getBlob(self.inAvail())

    def getTlv(self):
        return self.getU32(), self.getLps()

    def Tlvs(self):
        while (self.inAvail()):
            yield self.getTlv()
        raise StopIteration

    def Lpss(self):
        while (self.inAvail()):
            yield self.getLps()
        raise StopIteration

    def getVarInt(self):
        val, new_off = _decoder(self.data, self.offset)
        self.offset = new_off
        return val

    def getVarIntLps(self):
        length, new_off = _decoder(self.data, self.offset)
        self.offset = new_off
        return IStream(self.__unpack('<{0}s'.format(length))[0])

    def getVarIntLpsNum(self):
        length, new_off = _decoder(self.data, self.offset)
        self.offset = new_off
        r = IStream(self.__unpack('<{0}s'.format(length))[0])
        if(length == 2):
            return r.getU16()
        if(length == 4):
            return r.getU32()
        if(length == 8):
            return r.getU64()


    def inAvail(self):
        return self.dlen - self.offset

class OStream(object):
    def __init__(self, data = ''):
        self.data = data

    def __str__(self):
        return str(self.data)

    def __pack(self, fmt, *args):
        self.data += struct.pack(fmt, *args)
        return self

    def putReqId(self,grepme=''):
        return self.putLps(grepme+str(random.randint(100,999)) + '#' + str(random.randint(10,99)))

    def putU8(self, num):
        return self.__pack('B', num)

    def putU16(self, num):
        return self.__pack('<H', num)

    def putU32(self, num):
        return self.__pack('<L', num)

    def putMsgId(self, mid):
        return self.putU64(int(mid))

    def putTlv(self, tag, data):
        return self.putU32(tag).putLps(data)

    def putI32(self, num):
        return self.__pack('<l', num)

    def putRid(self, type, id):
        return self.putBlob(RidInit(type, id))

    def putChatId(self, id):
        return self.putRid(2, id)

    def putOrigin(self):
        return self.putLps(OStream().putU32(1).putLps("asdf").data)

    def putMchatHdr(self, type, id):
        return self.putReqId().putRid(type, id).putOrigin()

    def putU64(self, num):
        return self.__pack('<Q', num)

    def putLps(self,data):
        self.putU32(len(data))
        return self.__pack('<{0}s'.format(len(data)), data)

    def putBlob(self, data):
        return self.__pack('<{0}s'.format(len(data)), data)

    def putTlv(self, tag, data):
        self.putU32(tag)
        return self.putLps(data)

    def putIPkt(self, msg, data):
        self.putU32(msg)
        self.putU32(len(data))
        self.putU32(0)
        self.putBlob(data)

    def putISPkt(self, msg, key, data):
        paylo = OStream().putLps(key).putBlob(data)

        self.putU16(msg)
        self.putU16(1)
        self.putU32(len(paylo.data))
        self.putU32(0)
        self.putBlob(paylo.data)

    def encloseLps(self):
        return OLps(self)

    def encloseCLps(self):
        return OCLps(self)

class OLps(OStream):
    def __init__(self, ostream):
        super(OLps, self).__init__()
        self.ostream = ostream

    def __enter__(self):
        return self

    def __exit__(self, exception, value, traceback):
        if exception:
            return False
        
        self.ostream.putLps(self.data)

class OCLps(OLps):
    def __init__(self, ostream):
        super(OCLps, self).__init__(ostream)
        self.lpsCount = 0

    def putLps(self, data):
        super(OCLps, self).putLps(data)
        self.lpsCount += 1

    def __exit__(self, exception, value, traceback):
        self.data = struct.pack('<L', self.lpsCount) + self.data
        super(OCLps, self).__exit__(exception, value, traceback)

class IPacket(IStream):
    def __init__(self, msg, seq, proto, data):
        super(IPacket, self).__init__(data)
        self.proto = proto
        self.msg = msg
        self.seq = seq

    @staticmethod
    def create(hdr, data):
        _, proto, seq, msg = struct.unpack_from('<L L 2L', hdr) 
        return IPacket(msg, seq, proto, data)
