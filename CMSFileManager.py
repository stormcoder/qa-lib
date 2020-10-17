#! python3
import argparse as ap
import sys, logging as lg
from lxml import etree
from enum import Enum
from types import GeneratorType as Generator
from QAFramework import getAttrText, getElement, validationFailure, genID, chunk
from QAFramework import getElementList, expectTrue,  notice
from pathlib import Path
from time import sleep, strftime
from random import randint
from collections.abc import Iterator
from itertools import chain

class RESULTCODES(Enum):
    PASS = 0
    FAIL = -1
    ERROR = 1

def handleArgs():
    EPILOG = ""
    DESCRIPTION = "Connect to the CMS and run test data through the server. This is a test interface for development."
    USAGE = "CMSFileManager.py --ADDRESS 127.0.0.1 [--PORT 5011] [--ITERATIONS 1] --CMD \"<Request><Devices/></Request>\""
    parser = ap.ArgumentParser(epilog=EPILOG, description=DESCRIPTION, usage=USAGE)
    parser.add_argument("--ADDRESS", required=True, help="The server under test")
    parser.add_argument("--PORT", required=False, default=5011, type=int, help="The port to connect to of the server under test.")
    parser.add_argument("--ITERATIONS", default=1, type=int, help="The number of times to run the data.")
    #parser.add_argument("--CMD", dest="CMDS", action="append", nargs="*", help="The cmd and arguments to send. ")
    args = parser.parse_args(sys.argv[1:], handleArgs)
    return args


def CreateSync(*devices, **attribs):
    """
    Create a Sync request for the given devices.
    <Sync>
    <Device UNDI="0A;0000000061"/>
    </Sync>
    """
    sync = etree.Element("Sync", attrib=attribs)
    sync.extend(devices)
    return etree.ElementTree(sync)

def ConfigsCmd(**attribs):
    rslt = etree.Element("Configs", attrib=attribs)
    return rslt

def QConfigs(**attribs):
    rslt = CreateRequest(
        ConfigsCmd(**attribs))
    return rslt

def CreateRequest(*elements, **attribs):
    """
    Create a request using the given element objects.
    @elements the sub elements for this request.
    @attribs are the attributes to add to the request element
    """
    Req = etree.Element("Request", attrib=attribs)
    Req.extend(elements)
    tree = etree.ElementTree(Req)
    return tree

def DevicesCmd(**attribs):
    """
    Create a devices command with the given attributes.
    @attribs attribute names and values.
    """
    rslt = etree.Element("Devices", attrib=attribs)
    return rslt
#yes there are two slightly different elements to deal with.
def DeviceCmd(**attribs):
    """
    Create a device element. Note there is a Devices element which is different.
    """
    rslt = etree.Element("Device", attrib=attribs)
    return rslt

def NewConf(ctype, *elements, **attribs):
    """
    Create a config element with the given type and sub elements and attributes.
    @ctype config type
    @elementts child elements
    """
    rslt = etree.Element("Config", attrib=attribs)
    rslt.set("TYPE", ctype)
    rslt.extend(elements)
    return rslt

def BuildConfiguration(*configurations, **attribs):
    rslt = CreateRequest(
        *configurations, **attribs)
    return rslt

class eFreq(Enum):
    Hour = 0
    Day = 1
    Week = 2
    Month = 3

def ConnectConf(Freq, timestamp, skew="1", **attribs):
    """
    Create Connect config item.
    @Freq Either a string or eFreq object.
    @timestamp a time range for the connection to occur.
    @skew a value to skew the connect time by.
    @attrib additional attribute values.
    """
    assert int(skew), "Bad skew value"
    rslt = etree.Element("Connect", attrib=attribs)
    rslt.set("FREQUENCY", str(Freq))
    rslt.set("TIME", timestamp)
    rslt.set("SKEW", skew)
    return rslt

def NotifyConf(filetype, tcp, **attribs):
    """
    Create a notify config type.
    @filetype to notify on
    @tcp the host to notify with an XML doc.
    """
    rslt = etree.Element("Notify", attrib=attribs)
    rslt.set("FILETYPE", filetype)
    rslt.set("TCP", tcp)
    return rslt

def LocationConfig(name, path, **attribs):
    """
    Create a location config type
    @name name of the location
    @path the path of the location
    @attribs additional attributes.
    """
    rslt = etree.Element("Location", attrib=attribs)
    rslt.set("NAME", name)
    rslt.set("VALUE", path)
    return rslt

def TransferWindowConfig(ttype, trange, **attribs):
    """
    Create a transfer window element
    @ttype the transfer type
    @trange the time range
    @attribs additional attributes
    """
    rslt = etree.Element("TransferWindow", attrib=attribs)
    rslt.set("TYPE", ttype)
    rslt.set("SPAN", trange)
    return rslt

def TransferConfig(ttype, lowspeed, lowtime, maxsendspeed, maxrecvspeed, minavgspeed, **attribs):
    rslt = etree.Element("Transfer", attrib=attribs)
    rslt.set("TYPE", ttype)
    rslt.set("LOWSPEED", lowspeed)
    rslt.set("LOWTIME", lowtime)
    rslt.set("MAXSENDSPEED", maxsendspeed)
    rslt.set("MAXRECVSPEED", maxrecvspeed)
    rslt.set("MINAVGSPEED", minavgspeed)
    return rslt

def AddDevice(undi, devtype, configtype, **attribs):
    """
    Create an add device request
    @undi the device UNDI
    @devtype the type of the device
    @configtype the config type to use.
    """
    return CreateRequest(
        DeviceCmd(UNDI=undi, DEVICETYPE=devtype, CONFIGTYPE=configtype, **attribs))

def AddDevices(*DevInfoLst, **attribs):
    """
    One or more tuples of (undi, devtype, configtype) are used to create add device commands.
    """
    devlst = [DeviceCmd(UNDI=undi, DEVICETYPE=devtype, CONFIGTYPE=configtype) for undi, devtype, configtype in [x for x in DevInfoLst]]
    return CreateRequest(*devlst, **attribs)


def DownloadCmd(*devices, **attribs):
    """
    Create a Download element
    @devices the devices that will be downloading this
    @attribs The attributes for this element
    """
    rslt = etree.Element("Download", attrib=attribs)
    rslt.extend(devices)
    return rslt

def AddPublication(serverloc, servfilename, devloc, devfilename, starttime, filetype="", groupid="", priority="50", delay="", delorphan=True, autosync=False, *devices, **attribs):
    """
    Create an add publication request.
    @serverloc location on the server where the file resides
    @servfilename the name of the file on the server
    @devloc Where are we storing this file on the client
    @devfilename What we are calling this file on the client
    @starttime when is the download to start
    @filetype the type of file that is to be downloaded
    @groupid the group ID for this publication
    @priority the download priority for this publication
    @delay the installation delay for this publication
    @delorphan delete any orphan files from publications that no longer exist
    @devices the devices that this publication is targetting.
    @autosync Should the devices synch immediately.
    @attribs additional attributes for the download element
    """
    print(serverloc)
    attribs["SERVERLOCATION"] = serverloc
    attribs["SERVERFILENAME"] = servfilename
    attribs["DEVICELOCATION"] = devloc
    attribs["DEVICEFILENAME"] = devfilename
    attribs["TRANSFERSTARTTIME"] = starttime
    attribs["FILETYPE"] = filetype
    attribs["GROUPID"] = groupid
    attribs["PRIORITY"] = priority
    attribs["DELAYINSTALLTIME"] = delay
    attribs["DELETEORPHAN"] = str(int(delorphan))
    attribs["AUTOSYNC"] = str(int(autosync))
    rslt = CreateRequest(
        DownloadCmd(*devices), **attribs)
    return rslt

def CreateUpdate(*elements, **attribs):
    """
    Create and update request
    """
    rslt = etree.Element("Update", attrib=attribs)
    rslt.extend(elements)
    return etree.ElementTree(rslt)

def UpdatePublication(fileid, filetype="", groupid="", priority="", servloc="", servfilename="", *devices, **attribs):
    attribs["IDFILE"] = fileid
    attribs["FILETYPE"] = filetype
    attribs["GROUPID"] = groupid
    attribs["PRIORITY"] = priority
    attribs["SERVERLOCATION"] = servloc
    attribs["SERVERFILENAME"] = servfilename
    rslt = etree.ElementTree(CreateUpdate(
            DownloadCmd(*[DevicesCmd(UNDI=x) for x in devices], **attribs)))
    return rslt

def UploadCmd(*devices, **attribs):
    """
    Create an upload element
    @devices the devices that will be doing the uploading
    @attribs Upload attributes
    """
    rslt = etree.Element("Upload", attrib=attribs)
    rslt.extend(devices)
    return rslt


def AddUpload(serverloc, devloc, devfilename, filetype="", groupid="", priority="25", transstart="", autosync=False, *devices, **attribs):
    """
    Create an upload request.
    @serverloc location on the server where the file resides
    @devloc Where are we storing this file on the client
    @devfilename What we are calling this file on the client
    @filetype the type of file that is to be downloaded
    @groupid the group ID for this publication
    @priority the download priority for this publication
    @transstart the time to start the upload
    @devices the devices that this publication is targetting.
    @autosync Should the devices synch immediately.
    @attribs additional attributes for the download element
    """
    attribs["SERVERLOCATION"] = serverloc
    attribs["DEVICELOCATION"] = devloc
    attribs["DEVICEFILENAME"] = devfilename
    attribs["FILETYPE"] = filetype
    attribs["GROUPID"] = groupid
    attribs["PRIORITY"] = priority
    attribs["AUTOSYNC"] = str(int(autosync))
    attribs["TRANSFERSTART"] = transstart
    rslt = CreateRequest(
        UploadCmd(*devices, **attribs))
    return rslt

def UpdateUpload(fileid, filetype="", groupid="", priority="", *devices, **attribs):
    attribs["IDFILE"] = fileid
    attribs["FILETYPE"] = filetype
    attribs["GROUPID"] = groupid
    attribs["PRIORITY"] = priority
    rslt = CreateUpdate(
        UploadCmd(*[DevicesCmd(UNDI=x) for x in devices], **attribs))
    return rslt

def QDevices(**attribs):
    """
    Query Devices status
    """
    rslt = CreateRequest(
        DevicesCmd(**attribs))
    return rslt

def QPublications(**attribs):
    """
    Query publication status
    """
    rslt = CreateRequest(
        etree.Element("Files", attrib=attribs))
    return rslt

def InfoCmd(**attribs):
    rslt = etree.Element("Info", attrib=attribs)
    return rslt

def QDeviceInfo(UNDI, **attribs):
    """
    Query the info for a device
    """
    attribs["UNDI"] = UNDI
    rslt = CreateRequest(
        InfoCmd(**attribs))
    return rslt

def QPublicationInfo(fileid, **attribs):
    """
    Query info on a publication
    """
    attribs["IDFILE"] = fileid
    rslt = CreateRequest(
        InfoCmd(**attribs))
    return rslt

def DelCmd(**attribs):
    """
    Del something
    """
    rslt = etree.Element("Delete", attrib = attribs)
    return rslt

def RemoveDevice(devid, **attribs):
    """
    Remove the given device
    """
    attribs["IDDEVICE"] = devid
    rslt = CreateRequest(
        DelCmd(**attribs))
    return rslt

def RemoveCmd(**attribs) -> etree._Element:
    return etree.Element("Remove", attrib=attribs)

def RemovePublicationDevicesCmd(idfile: str, UNDIS: Iterator or Generator, **attribs) -> etree._Element:
    """
    Creator a generator of remove devices from publication cmds.
    idfile is the id of the publication
    UNDIS is a generator that produces UNDI strings
    """
    attribs["IDFILE"] = idfile
    return (CreateRequest(DownloadCmd(*RemoveCmd(UNDI=undi), **attribs)) for undi in UNDIS)


def RemoveDevices(devidlst, **attribs):
    dels = [DelCmd(IDDEVICE=di) for di in devidlst]
    return CreateRequest(*dels)

def QTransferStats(fileid, summarize=False, **attribs):
    """
    Query the transfer stats for a given publication
    """
    attribs["IDFILE"] = fileid
    attribs["SUMMARIZE"] = str(int(summarize))
    rslt = CreateRequest(
        InfoCmd(**attribs))
    return rslt

def QTransferLog(undi, start, end, **attribs):
    """
    Query the transfer log for a device
    """
    attribs["UNDI"] = undi
    attribs["BEGIN"] = start
    attribs["END"] = end
    rslt = CreateRequest(
        etree.Element("TransferLog", attrib=attribs))
    return rslt

def Success(xmlobj):
    """
    Check for errors in responses.
    """
    attribs = xmlobj.xpath("//@ERROR")
    nodes = xmlobj.xpath("//Error")
    return len(nodes) == 0 and len(attribs) == 0

def sendCmd(host, port, cmd):
    """
    Send a cmd string to the server.
    @host is the host address
    @port is the port on the server to send the command
    @cmd is the string form of an XML document.
    """
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.settimeout(240)
    s.sendall(cmd)
    s.shutdown(socket.SHUT_WR)
    sleep(1)
    buff = s.recv(4096)
    data = []
    data.append(buff)
    while len(buff) > 0:
        buff = s.recv(4096)
        if buff:
            data.append(buff)
        else:
            break
    s.close()
    return etree.fromstringlist(data)


def stream(xmlobj):
    """
    Convert an XML object to a unicode string understandable by the server.
    """
    return etree.tostring(xmlobj, pretty_print=True, encoding='utf-8')

def DevIDsFromResp(respobj):
    """
    Extract device ID's from a devices response.
    """
    ids = respobj.xpath("//Device/@IDDEVICE")
    #print ids
    return ids


def RespCompare(req, qresp):
    """
    Compare the response the the request and make sure there is a correlation.
    """
    #assert type(req) == type(qresp), "Parameters do not have matching types."
    #assert resp1.getroot().tag == resp2.getroot().tag, "Message types are not the same."
    rslt = True
    src = req.getroot() if type(etree.ElementTree()) == type(req) else req
    targ = qresp.getroot() if type(etree.ElementTree()) == type(qresp) else qresp
    for c in src:
        ps = targ.find(c.tag)
        if not len(ps):
            rslt = False
            lg.debug("Unable to find %s in targ."%c.tag)
            break
        else:
            flg = False
            for p in ps:
                if any(True for k in src if k not in targ):
                    flg = True
                    lg.debug("Attribs are the same for the config objects.")
                    break
            rslt = rslt and flg
    if not rslt: lg.debug("RespCompare found a miss match.")
    return rslt

def chkconfigresp1(req, Qresp):
    """
    Check a given request against a query resp to make sure that they agree.
    """
    rslt = True
    try:
        rslt = expectTrue(Success(Qresp), "Query response has errors.\n%s"%stream(Qresp))
        rnodes = req.xpath("//Config")
        qnodes = Qresp.xpath("//Config")
        rslt = rslt and expectTrue(len(rnodes) > 0, "req object has no Config nodes.\n%s"%stream(req))
        rslt = rslt and expectTrue(len(qnodes) > 0, "Qresp object has no Config nodes.\n%s"%stream(Qresp))
        #rslt = rslt and expectEqual(len(rnodes), len(qnodes), "Config node counts don't match.\n%s\n%s"%(stream(req), stream(Qresp)))
        rslt = rslt and RespCompare(req, Qresp)
    except Exception as info:
        lg.error("chkconfiggresp1 failed because %s\nreq:\nQresp:\n%s\n%s"%(info, stream(req), stream(Qresp)))
        return RESULTCODES.ERROR
    return RESULTCODES.PASS if rslt else RESULTCODES.FAIL


def execTC(req, expected, ADDRESS, PORT, fhport, lg):
    """
    Performs the actual test using the test data supplied.
    """
    from DistTesting import pubToFH
    send, quit = pubToFH("localhost", fhport)
    rslt = RESULTCODES.FAIL
    try:
        resp = sendCmd(ADDRESS, PORT, stream(req))
        lg.debug("Sending req:\n%s"%stream(req))
        chk = expectTrue(Success(resp), "AddDevices cmd failed.\n%s"%stream(resp))
        if chk:
            for x in req.xpath("//Device/@UNDI"):
                send(x)
        if chk: rslt = RESULTCODES.PASS
    except Exception as info:
        rslt = RESULTCODES.ERROR
        lg.exception("execTC: Failed with an exception because %s.\n%s"%(info, stream(req)))
    return rslt



def chkdevresp(riddevices, qiddevices, lg):
    """
    Checks the results of a add device test.
    """
    expectTrue(len(qiddevices) > 0, "No device ID's found in query.")
    expectTrue(len(riddevices) > 0, "No device ID's found in request.")
    rslt = RESULTCODES.PASS if qiddevices.issuperset(riddevices) else RESULTCODES.FAIL
    return rslt

def genUNDI(network=10, UNDILen = 25):
    """
    Produces a unique UNDI
    """
    from uuid import uuid4
    #genUNDI.__test__ = False
    o = uuid4()
    h1 = abs(hash(o.bytes))
    h2 = abs(hash(o.int))
    padded = "%%0%sd%%0%sd"%(UNDILen/2, UNDILen/2)
    #print(padded)
    h = padded%(h1,h2)#"%022d%022d"
    rslt = "%02X;%022s"%(network, h)
    if len(rslt) > UNDILen: rslt = rslt[0:25]
    return rslt

def genADTestData():
    """
    Produces the test data. Generates over 13K requests
    """
    #genADTestData.__test__ = False
    data = chain([(AddDevice(genUNDI(), "Windows", "shockwave"), RESULTCODES.PASS),#One windows device
                  (AddDevices(*[(genUNDI(112), "Windows", "shockwave") for x in range(50)]), RESULTCODES.PASS),#fifty Linux devices
                  (AddDevices(*[(genUNDI(), "Linux", "mdrink") for x in range(50)]), RESULTCODES.PASS)],
                 ((AddDevice(genUNDI(), "Linux", "shockwave"), RESULTCODES.PASS) for xx in range(1000)),
                 ((AddDevice(genUNDI(112), "Windows", "default"), RESULTCODES.PASS) for x in range(2000)),
                 ((AddDevice(genUNDI(y), "BSD", "default"), RESULTCODES.PASS) for y in range(256)),
                 ((AddDevices(*[(genUNDI(112), "Windows", "shockwave") for ww in range(50)]), RESULTCODES.PASS) for z in
                  range(200)),
                 ((AddDevices(*[(genUNDI(112), "Windows", "shockwave") for ww in range(1000)]), RESULTCODES.PASS) for z
                  in range(10)))
    yield from data
    return

def addSomeDevices(host="192.168.168.21", port=5011) -> Generator:
    for x in genADTestData():
        def close() -> tuple:
            resp = sendCmd(host, port, stream(x[0]))
            error = getElement(resp, "ERROR")
            undi = getAttrText(resp, "UNDI")
            if error is not None:
                validationFailure("addDevice for %s failed because because '%s'"%(undi, error))
                return undi, RESULTCODES.FAIL
            else:
                return undi, RESULTCODES.PASS
        yield close
    return


def getUnusedDevices(dbsrv="192.168.168.35", servname="fts21.world", uname="fts", pword="xxxxx") -> Generator:
    import cx_Oracle as ora
    from QAFramework import DBIterator
    conn = ora.Connection(uname, pword, ora.makedsn(dbsrv, 1521, service_name=servname))
    yield from (x[0] for x in DBIterator(conn.cursor().execute('SELECT "IDDEVICE" from "DEVICES" where "LASTCONNECTTIME" IS null')))
    return

def removeUnusedDeviceCmds(idgen=getUnusedDevices) -> Generator:
    """
    Generate remove device cmds devices for device that have not registered.
    returns a generator that yields a remove request.
    """
    for ID in idgen():
        #ID = str(row[0])
        yield RemoveDevice(ID)
    return

def removeUnusedDeviceCmdsFaster(idgen=getUnusedDevices, grpsz=10) -> Generator:
    """
    Remove groups devices at a time. Should speed things up.
    """
    gen = idgen()
    ids = chunk(grpsz, gen)
    while ids is not None:
        yield RemoveDevices(ids)
        ids = chunk(grpsz, gen)
    return

def removeUnusedDevices(cmdgen=removeUnusedDeviceCmds, srv="192.168.168.21", port=5011) -> Generator:
    for cmd in cmdgen():
        resp = sendCmd(srv, port, stream(cmd))
        elst = getElementList(resp, "Delete")
        if elst is None or len(elst) == 0:
            validationFailure("removeUnusedDevices failed. Response was empty.")
        else:
            yield [getAttrText(delel, "IDDEVICE") for delel in elst]
    return


def getFiles(spath: Path or Generator) -> Generator:
    """
    spath is either a directory path or a generator is paths to the individual files.
    Returns a generator of files.
    """
    it = spath.iterdir() if isinstance(spath, Path) else spath
    yield from it
    return

def generateDownloadCmds(mpath: Path or Iterator or Generator, pubpath: Path, devices: tuple)-> Generator:
    """
    mpath is a Path for a directory or an iterator/generator that produce paths of individual files.
    pubpath is the root publication path as configured in the servers registry.
    devices is a tuple of UNDIs
    """
    #def AddPublication(serverloc, servfilename, devloc, devfilename, starttime, filetype="", groupid="", priority="50", delay="", delorphan=True, autosync=False, *devices, **attribs)
    assert isinstance(mpath, (Path, Iterator, Generator)), "mpath must be a Path, Iterator, or Generator that produces Paths."
    yield from (AddPublication(str(x.parent.relative_to(pubpath)),
                               x.name,
                               "Other",
                               str(genID()),
                               strftime("%Y-%m-%d %H:%M:%S"),
                               "", "", "50", "", True, False,
                               *[DeviceCmd(UNDI=y) for y in devices])
                               for x in getFiles(mpath))


def addPublicationsFromPaths(paths: Iterator or Generator, devices=("0A;0000000053", ), pubpath=Path(r"\\localhost\cms"), host="192.168.168.21", port=5011) -> Generator:
    """
    paths is an iterator or generator that produces Path objects.
    The pubpath default assumes a Windows environment
    """
    for x in generateDownloadCmds(paths, pubpath, devices):
        notice(stream(x))
        def close() -> tuple:
            resp = sendCmd(host, port, stream(x))
            error = getElement(resp, "ERROR")
            if error is not None:
                validationFailure("addPublication failed because %s:\n%s"%(error.text, stream(x)))
                return getAttrText(resp, "IDFILE"), RESULTCODES.FAIL
            else:
                return getAttrText(resp, "IDFILE"), RESULTCODES.PASS
        yield close
    return


def randomBytes(length: int):
    return bytearray(randint(0, 255) for x in range(length))

def createRandomFiles(path=Path(r"\\192.168.168.27\cms\temp"), filelength=1000) -> Generator:
    """
    Generates randomly generated files under a given directory with the given length.
    The default path assumes a Windows environment
    """
    assert path.exists() and path.is_dir(), "path must be an existing directory."
    while True:
        fn = "%s.%s"%(genID(), randint(0, 999))
        nf = Path(path, fn)
        with nf.open(mode="wb") as f:
            f.write(randomBytes(filelength))
        yield nf
    return

def updateFiles(filepaths: Generator or Iterator, length: int) -> Generator:
    """
    Take a generator or iterator of Paths and add data to each of them.
    """
    for fp in filepaths:
        with fp.open(mode="ba+") as f:
            f.write(randomBytes(length))
        yield fp
    return


def getPublicationIDs(host="192.168.168.21", port=5011) -> Generator:
    """
    produce a generator of publication ID's.
    """
    resp = sendCmd(host, port, stream(QPublications()))
    error = getElement(resp, "ERROR")
    if error is not None:
        validationFailure("getPublicationIDs failed because %s"%error.text)
    else:
        yield from (x.get("IDFILE") for x in getElementList(resp, "File") if x is not None)
    return

def removePublicationCmd(fileid, **attribs):
    """
    Delete a publication.
    """
    attribs["IDFILE"] = fileid
    rslt = CreateRequest(
        DelCmd(**attribs))
    return rslt

def removeCurrentPublications(pubids=getPublicationIDs, host="192.168.168.21", port=5011) -> Generator:
    for cmd in (removePublicationCmd(x) for x in pubids(host, port)):
        def close():
            nonlocal cmd
            resp = sendCmd(host,  port, stream(cmd))
            delete = getElement(resp, "Delete")
            if delete is None:
                validationFailure("Failed to remove publication \n%s"%stream(cmd))
            return delete.get("IDFILE") if isinstance(delete, (etree._Element, )) else None
        yield close
    return

def getDeviceUNDIs(host="192.168.168.21", port=5011) -> Generator:
    resp = sendCmd(host, port, stream(QDevices()))
    yield from (getAttrText(dev, "UNDI") for dev in getElementList(resp, "Device"))

def devicesFromUNDI(UNDIs: Iterator or Generator, grpsz=100) -> Generator:
    chk = chunk(grpsz, UNDIs)
    while chk is not None:
        yield (DeviceCmd(UNDI=undi) for undi in chk)


def updatePublicationDevices(devices: Iterator or Generator, pubids=getPublicationIDs, host="192.168.168.21", port=5011) -> Generator:
    """
    devices should produce UNDI's.
    pubids is a generator function that produces IDFILE's.
    This generator yields closures that send the command when called without arguments.
    """
    for ID in pubids(host, port):
        def close() -> tuple:
            resp = sendCmd(host, port, stream(UpdatePublication(ID, "", "UpdateDevices", "", "", "", *tuple(devices))))
            error = getElement(resp, "ERROR") if resp is not None else None
            if error is not None:
                validationFailure("updatePublicationDevices failed for %s because %s for devices %s"%(ID, error.text, tuple(devices)))
                return ID, RESULTCODES.FAIL
            else:
                return ID, RESULTCODES.PASS
        yield close
    return


def removePublicationDevices(devices: Iterator or Generator, pubids=getPublicationIDs, host="192.168.168.21", port=5011) -> Generator:
    """
    devices should produce UNDI's
    pubids should produce IDFILE's
    Remove the given devices from the given publications.
    This generator produces closures that execute the command when called without arguments.
    """
    for ID in pubids(host, port):
        def close() -> tuple:
            resp = sendCmd(host, port, stream(RemovePublicationDevicesCmd(ID, devices)))
            error = getElement(resp, "ERROR")
            if error is not None:
                validationFailure("removePublicationDevices failed for %s because %s for devices %s"%(ID, error.text, tuple(devices)))
                return ID, RESULTCODES.FAIL
            else:
                return ID, RESULTCODES.PASS
        yield close
    return


