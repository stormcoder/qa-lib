#! python3
import time, struct
import logging as lg
import uuid, sys, platform
from array import array


class UDPMessage(object):
    """
    A class for dealing with UDP packats passed to and from the UDPProxy or UDPRelay.
    """
    DATALEN = (2**16) - (62) - 2
    FORMAT = "!HHIf25s25s%ss"%DATALEN
    def __init__(self, Destination, Source, Data):
        self.dest = Destination
        self.source = Source
        self.data = Data[0:min(self.DATALEN, len(Data))]
        self.version = 0x01
        self.timestamp = time.time()
        self.hdrSz = 62
        self.msgSz = self.hdrSz + self.DATALEN#len(self.data)
        #assert self.msgSz < 2**16, "Packet is to large. Allowed 256 bytes"
        self.packet = struct.pack(self.FORMAT, self.msgSz, self.hdrSz, self.version, self.timestamp, self.dest, self.source, self.data)
        assert self.msgSz == len(self.packet), "message length and the actual length of the message don't match. packet length = %s and msgSz = %s"%(len(self.packet), self.msgSz)
        return
    def write(self, fileHandle):
        fileHandle.write(self.packet)
        fileHandle.write("\n")
        return
    def __str__(self):
        return self.packet
    def __repr__(self):
        return "<UDPMessage: dest = %s, source = %s, version = %s, timestamp = %s, HeaderSize = %s, MsgSize = %s>"%(self.dest, self.source, self.version, self.timestamp, self.hdrSz, self.msgSz)
    @staticmethod
    def parse(msgArr):
        msgSz, hdrSz, version, timestamp, dest, source, data = struct.unpack(UDPMessage.FORMAT, msgArr)
        return UDPMessage(dest, source, data)

class TCPClientRequest(object):
    def __init__(self, data):
        self.version = 0x01
        self.datasize = len(data)
        self.data = data
        self.payload = struct.pack("!BI%ss"%self.datasize, self.version, self.datasize, data)
        return
    def __str__(self):
        return self.payload
    def __repr__(self):
        return "< version=%s datasize=%s>"%(self.version, self.datasize)
    def write(self, fileHandle):
        fileHandle.write(self.payload)
        return
    @classmethod
    def parse(cls, msg):
        msglen = len(msg)
        datalen = msglen - 5
        ver, sz, data = struct.unpack("!BI%ss"%datalen)
        assert sz == datalen, "Unpacked data length is different than calculated. %s vs %s"%(sz, datalen)
        rslt = cls(data)
        rslt.version = ver
        return rslt

class TCPClientResponse(TCPClientRequest):
    def __init__(self, data):
        TCPClientRequest.__init__(self, data)
        return

class TCPServerRequest(object):
    HEADERSIZE = 75
    opcode = 0x87A1
    version = 0x01
    def __init__(self, clientIP, clientPort, UNDI, data):
        self.IP = clientIP
        self.port = clientPort
        self.UNDI = UNDI
        self.datasize = len(data)
        self.data = data
        self.payload = struct.pack("!HB16sH50sI%ss"%self.datasize, self.opcode, self.version, self.IP, self.port, self.UNDI, self.datasize, self.data)
        return
    def __str__(self):
        return self.payload
    def __repr__(self):
        return "< Opcode=%s Version=%s IP=%s Port=%s UNDI=%s Data Length=%s >"%(self.opcode, self.version, self.IP, self.port, self.UNDI, self.datasize)
    @classmethod
    def parse(cls, msg):
        sz = len(msg) - cls.HEADERSIZE
        op, ver, IP, port, UNDI, dsz, data = struct.unpack("!HB16sH50sI%ss"%sz, msg)
        rslt = cls(IP, port, UNDI, data)
        assert rslt.version == ver, "Message version does not match. Expected version %s. Actual version is %s"%(rslt.version, ver)
        assert cls.opcode == op, "Opcode for new object doesn't match the expected value. Expected opcode is %s actual opcode is %s"%(cls.opcode, op)
        assert sz == dsz, "Data sizes do not match. Expected size is %s actual size is %s"%(sz, dsz)
        return rslt


def __getWindowsInfo():
    UNDI = None
    hostname = None
    hostname = platform.node()
    return (hostname, UNDI)

def __getLinuxInfo():
    UNDI = None
    hostname = platform.node()
    return (hostname, UNDI)

getBoxInfo = None
if platform.uname()[0] == "Windows":
    getBoxInfo = __getWindowsInfo
elif platform.uname()[0] == "Linux" or platform.uname()[0] == "Darwin":
    getBoxInfo = __getLinuxInfo
else:
    sys.stderr.write("\a\a\a\nUndefined platform. Aborting.\n\a\a\a")
    sys.exit(1)
"""
x Provide a test name and test run UUID, host name, host UNDI.
Provide utilities to provide this info for manual tests. start test utility generates the run ID and the end and abort utilities that contain the generated info.
run either the end or abort utility cause the other utility to be removed.
x There should be a web service that these utilities hit.

"""



def startTest(testname, host):
    """
    Mark the start abd end of a test run.
    """
    host, UNDI = getBoxInfo()
    runID = uuid.uuid5(uuid.NAMESPACE_DNS, host)
    lg.info("Test, %s, run started on %s/%s with runID %s"%(testname, host, UNDI, runID.hex))
    def abort():
        lg.info("Aborting test run %s for test %s on %s/%s"%(runID.hex, testname, host, UNDI))
        return
    def end():
        lg.info("Ending test run %s for test %s on %s/%s"%(runID.hex, testname, host, UNDI))
        return
    return end, abort



def progressivebytes(size):
    rslt = array("B")
    x = 0
    for a in range(size):
        rslt.append(2**x)
        if x >= 8:
            x = 0
    return rslt.tostring()

def sendMsg(sock, msg):
    msglen = len(msg)
    total = 0
    while total < msglen:
        sent = sock.send(msg[total:total + min(4096, msglen - total)])
        if sent == 0:
            lg.error("No data was sent.")
            raise Exception("No data was sent.")
        total += sent
    return



def Continuous(forever=True):
    """
    This is meant to be used as a decorator
    If used with no argument the parens are still needed due to the default argument. seems to be a bug.
    """
    def wrap(func):
        def wrapped(*args, **kwargs):
            rslt = None
            rslt = func(*args, **kwargs)
            while forever:
                rslt = func(*args, **kwargs)
            return rslt
        wrapped.__name__ = func.__name__
        wrapped.__doc__ = func.__doc__
        wrapped.__dict__.update(func.__dict__)
        return wrapped
    return wrap






