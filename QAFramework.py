#!/usr/bin/env python3.3
from functools import wraps, update_wrapper
import logging as log
from logging.handlers import RotatingFileHandler
from time import time
#import zmq
import sys
import warnings as w
import traceback as tb
from itertools import islice
from time import ctime
from concurrent.futures import Executor, as_completed
from os import environ
import gc
import lxml.etree as et
from uuid import uuid4
from time import sleep
from types import FunctionType as Function,  GeneratorType as Generator
from collections.abc import Iterable as Iterator
from enum import Enum
"""
Produce a stack trace.
'File "{0.f_code.co_filename}", line {0.f_lineno}, in {0.f_code.co_name}'.format(sys._getframe(1))
"""
class RESULTCODES(Enum):
    PASS = 1
    FAIL = 0
    ERROR = -1


def expectEqual(a, b, msg, stacklevel=2):
    rslt = True
    try:
        if a != b:
            rslt = False
            w.warn(msg,  stacklevel=stacklevel)
    except:
        pass
    return rslt

def expectNotEqual(a, b, msg, stacklevel=2):
    rslt = True
    try:
        if a == b:
            rslt = False
            w.warn(msg,  stacklevel=stacklevel)
    except:
        pass
    return rslt

def expectLT(a, b, msg, stacklevel=2):
    rslt = True
    try:
        if a >= b:
            rslt = False
            w.warn(msg, stacklevel=stacklevel)
    except:
        pass
    return rslt

def expectGT(a, b, msg, stacklevel=2):
    rslt = True
    try:
        if a <= b:
            rslt = False
            w.warn(msg,  stacklevel=stacklevel)
    except:
        pass
    return rslt

def expectStrEqNoCase(a, b, msg, stacklevel=2):
    rslt = True
    try:
        if a.lower() != b.lower():
            rslt = False
            w.warn(msg,  stacklevel=stacklevel)
    except:
        pass
    return rslt


def expectTrue(a, msg):
    rslt = expectEqual(a, True, msg, stacklevel=3)
    return rslt

def expectFalse(a, msg):
    rslt = expectEqual(a, False, msg,  stacklevel=3)
    return rslt


def GetWindowsService(name: str, usr: str, pword: str, machine='') -> object:
    from wmi import WMI
    interface = WMI(computer=machine, user=usr, password=pword)
    service = interface.Win32_Service(Name=name)[0]
    assert service, "Service name is invalid"
    class Service(object):
        def __init__(self, svc):
            self.__service = svc
            return
        def start(self):
            rslt, = self.__service.StartService()
            return True if rslt == 0 else False
        def stop(self):
            rslt, = self.__service.StopService()
            return True if rslt == 0 else False
        def pause(self):
            rslt, = self.__service.PauseService()
            return True if rslt == 0 else False
        def resume(self):
            rslt, = self.__service.ResumeService()
            return True if rslt == 0 else False
    return Service(service)

#TODO: Create a file like object that publishes data written to a zmq server.
#TODO: add more info attributes to the exceptions

def isDebug(__cache=[]):
    return bool(int(environ.get("DEBUG", False)))

def setDebug(dbg: bool):
    environ["DEBUG"] = str(int(dbg))
    return


class TestFailed(RuntimeWarning):
    pass

class ExpectedFail(RuntimeWarning):
    pass

class TestError(RuntimeWarning):
    pass

def verify(func):
    #TODO: Setup reverse push client for test status
    #TODO: send the exception to the server
    def sendToZMQ(msg):
        pass
    @wraps(func)
    def decorator(*args, **kw):
        rslt = None
        #nonlocal func
        try:
            with w.catch_warnings(record=True) as warn:
                rslt = func(*args, **kw)
                for x in warn:
                    sendToZMQ(*x)
        except Exception as e:
            sendToZMQ(e)
        return rslt
    return decorator

def testsetup(func):
    #TODO: Execute the func in a seperate thread.
    #TODO: setup zmq pull server for test status
    #TODO: Log the status messages.
    def sendToZMQ(msg):
        return #TODO: Send warning text over socket.
    @wraps(func)
    def decorator(*args, **kw):
        #nonlocal func
        rslt = None
        try:
            rslt = func(*args, **kw)#TODO: Might need to run this in a seperate thread.
        except Exception as e:
            sendToZMQ(e)
        return rslt
    return decorator

def typecheck(f):
    """
    decorator for checking param types versus the annotations on function parameters.
    """
    @wraps(f)
    def wrapped(*args, **kws):
        for i, name in enumerate(f.__code__.co_varnames):
            argtype = f.__annotations__.get(name)
            # Only check if annotation exists and it is as a type
            if isinstance(argtype, type):
                # First len(args) are positional, after that keywords
                if i < len(args):
                    assert isinstance(args[i], argtype)
                elif name in kws:
                    assert isinstance(kws[name], argtype)
        result = f(*args, **kws)
        returntype = f.__annotations__.get('return')
        if isinstance(returntype, type):
            assert isinstance(result, returntype)
        return result
    return wrapped

def autodebug(type, value, tb):
    """
    Break into the debugger on an unhandled exception.
    """
    if hasattr(sys, "ps1") or not sys.stderr.isatty():
        #we're in the repl or something.
        sys.__excepthook__(type, value, tb)
    else:
        import traceback, pdb
        traceback.print_exception(type, value, tb)
        print("\n")
        pdb.pm()
    return

def deprecationWarning(msg):
    w.warn("%s: %s"%(ctime(),msg), category=DeprecationWarning, stacklevel=2)
    return

def deprecated(func):
    '''This is a decorator which can be used to mark functions
    as deprecated. It will result in a warning being emitted
    when the function is used.'''
    @wraps(func)
    def wrapped(*args, **kwargs):
        deprecationWarning("Call to deprecated function %s."%func.__qualname__)
        return func(*args, **kwargs)
    wrapped.__name__ = func.__name__
    wrapped.__doc__ = func.__doc__
    wrapped.__dict__.update(func.__dict__)
    return wrapped

class Retry(object):
    """
    Retry a failed function. Useful for networking. If func returns False or throws an exception then the retry occurs with an appropriate pause.
    """
    def __init__(self, attempts, pause = None):
        self.__attempts = int(abs(attempts))
        self.__count = 0
        self.__func = None
        self.__pause = pause
        return
    def __call__(self, func):
        assert func, "Function is invalid."
        self.__func = func
        @wraps(func)
        def wrapped(*args, **kw):
            doretry = True
            rslt = None
            count = 0
            exc = None
            while doretry and count < self.__attempts:
                count += 1
                exc = None
                try:
                    rslt = self.__func(*args, **kw)
                    doretry = True if not rslt else False
                    exc = None
                except Exception as e:
                    retryWarning("Exception in %s because %s\nparameters: %s\n%s"%(self.__func.__qualname__, e, args, kw))
                    tb.print_tb(sys.exc_info()[2])
                    doretry = True
                    exc = e
                finally:
                    if doretry and self.__pause: sleep(self.__pause)
            if count > 1: retryWarning("retried %s %s times"%(self.__func.__qualname__, count))
            if count >= self.__attempts: retryWarning("Retry attempts exceeded for %s"%self.__func.__qualname__)
            if exc: raise exc
            return rslt
        return wrapped

def loggingSetup(LOGFILEPATH, LOGLEVEL=log.DEBUG):
    LOGFORMAT = "%(asctime)-15s %(levelname)-8s: %(threadName)-8s: %(module)-12s: %(funcName)-15s: %(lineno)-4s %(message)s"
    lg = log.getLogger()
    handler = RotatingFileHandler(LOGFILEPATH, 'a', 10000000, 100) #handler = PUBHandler('tcp://127.0.0.1:12345')
    formatter = log.Formatter(LOGFORMAT)
    handler.setFormatter(formatter)
    lg.addHandler(handler)
    lg.setLevel(LOGLEVEL)
    #log.basicConfig(format=LOGFORMAT, filename=LOGFILEPATH, level=LOGLEVEL)
    return

class ValidationFailure(RuntimeWarning):
    pass

class ValidationError(RuntimeWarning):
    pass

class RetryWarning(RuntimeWarning):
    pass

class ExecutionTrace(RuntimeWarning):
    pass

class DataGenerationFailure(RuntimeWarning):
    pass

class Notice(RuntimeWarning):
    pass

class ServiceError(RuntimeWarning):
    pass

class ApplicationError(RuntimeWarning):
    pass

def debug(msg):
    if isDebug():
        notice(msg)
    return

def validationFailure(msg):
    w.warn("%s: %s"%(ctime(),msg), category=ValidationFailure, stacklevel=2)
    return

def validationError(msg):
    w.warn("%s: %s"%(ctime(),msg), category=ValidationError, stacklevel=2)
    return

def retryWarning(msg):
    w.warn("%s: %s"%(ctime(),msg), category=RetryWarning, stacklevel=2)
    return

def traceMsg(msg):
    w.warn("%s: %s"%(ctime(),msg), category=ExecutionTrace, stacklevel=3)
    return

def dataGenerationFailure(msg):
    w.warn("%s: %s"%(ctime(),msg), category=DataGenerationFailure, stacklevel=2)
    return

def notice(msg):
    w.warn("%s: %s"%(ctime(),msg), category=Notice, stacklevel=2)
    return

def serviceError(msg, stacklevel=2):
    w.warn("%s: %s"%(ctime(),msg), category=ServiceError, stacklevel=stacklevel)
    return

def applicationError(msg):
    w.warn("%s: %s"%(ctime(),msg), category=ApplicationError, stacklevel=2)
    return

def trace(frame, event, arg):
    import threading as t
    name = t.current_thread().name
    if event == "exception":
        print("Thread exception trace: %s Kind is %s. What is %s. frame = %s"%(name, event, arg, frame))
    return

def setIgnoreTrace():
    w.simplefilter(action="ignore", category=ExecutionTrace)
    return

def setIgnoreNotice():
    w.simplefilter(action="ignore", category=Notice)
    return

def DBIterator(rsltCursor, bufsize=100):
    """
    Using the rslts from rsltCursor, incrementally fetch records from DB.
    """
    rows = rsltCursor.fetchmany(bufsize)
    while rows is not None and len(rows) > 0:
        for row in rows:
            yield row
        rows = rsltCursor.fetchmany(bufsize)
    return

def chunk(sz, iterable):
    "Return first n items of the iterable as a list"
    #return tee(iterable, sz)
    for x in range(sz):
        yield next(iterable)

class TraceTimer(object):
    """
    Prints trace messages and execution time of functions.
    """
    def __init__(self, func):
        self.__func = func
        update_wrapper(self, self.__func)
        self.__name__ = func.__name__
        self.__doc__ = func.__doc__
        self.__dict__.update(func.__dict__)
        return
    def __call__(self, *args, **kw):
        rslt = None
        t1 = time()
        try:
            if "__DEBUG__" in globals(): traceMsg("Running %s with args %s"%(self.__func.__qualname__, args if args else kw))
            rslt = self.__func(*args, **kw)
        except Exception as e:
            serviceError("Exception in %s because %s"%(self.__func.__qualname__, e), 3)
            tb.print_tb(sys.exc_info()[2])
            raise e
        finally:
            t2 = time()
            if "__DEBUG__" in globals(): traceMsg("%s has an execution time of %f"%(self.__func.__qualname__, t2 - t1))
            return rslt

def loadPropertiesFile(filename: str) -> dict:
    """
    load a java properties file as a dict.
    """
    import jprops
    rslt = None
    with open(filename, "rb") as f:
        rslt = jprops.load_properties(f)
    return rslt


class Delay(object):
    def __init__(self, sec):
        self.__seconds = sec
        return
    def __call__(self, func):
        self.__func = func
        @wraps(self.__func)
        def wrapper(*args, **kw):
            sleep(self.__seconds)
            rslt = self.__func(*args, **kw)
            return rslt
        return wrapper

class ArgsValid(object):
    def __init__(self, func):
        self.__func = func
        update_wrapper(self, self.__func)
        return
    def __call__(self, *args, **kw):
        if "__DEBUG__" in globals():
            if args is not None and len(args):
                for i, x in enumerate(args, 1):
                    assert x is not None, "argument #%s is not valid."
            if kw is not None and len(kw):
                for k, v in kw.items():
                    assert v is not None, "Keyword argument %s is not valid."%k
        return self.__func(*args, **kw)

class RunAround(object):
    def __init__(self, before, after, beforeargs=None, afterargs=None):
        self.__before = before
        self.__after = after
        self.__bargs = beforeargs
        self.__aargs = afterargs
        return
    def __call__(self, func):
        self.__func = func
        @wraps(self.__func)
        def wrapped(*args, **kw):
            rslt = None
            if isinstance(self.__before, [Function]): self.__before(self.__bargs)
            rslt = self.__func(*args, **kw)
            if isinstance(self.__after, [Function]):self.__after(self.__aargs)
            return rslt
        return wrapped

def genRandomStr(count: int):
    """
    generate a random string of length count.
    """
    from random import choice
    printable = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r'
    rslt = []
    for i in range(count + 1):
        rslt.append(choice(printable))
    return "".join(rslt)




def coroutine(func):
    @wraps(func)
    def wrapper(*args, **kw):
        rslt = func(*args, **kw)
        next(rslt)
        return rslt
    return wrapper

XSLTNS = {"apriva": "http://www.activations.aprivasen.com/", "soap": "http://schemas.xmlsoap.org/soap/envelope/"}
@TraceTimer
def getElementText(element, localname, namespaces=XSLTNS.copy()):
    """
    Grab the first element matching localname and return its text.
    """
    rslt = ""
    finder = et.XPath(".//*[local-name() = $name]", namespaces=namespaces)
    targ = finder(element, name=localname)
    if targ is not None and len(targ) > 0:
        rslt = str(targ[0].text)
    else:
        notice("Element %s not found."%localname)#.with_traceback(sys.exc_info()[2])
    return rslt

@TraceTimer
def getAttrText(element, localname,
                namespaces=XSLTNS.copy()):
    """
    Grab the first attribute matching localname, ignoring namespaces, and return its text.
    """
    rslt = ""
    finder = et.XPath(".//@*[local-name() = $name]", namespaces=namespaces)
    targ = finder(element, name=localname)
    if targ is not None and len(targ):
        rslt = str(targ[0])
    else:
        notice("Attribute %s not found."%localname)#.with_traceback(sys.exc_info()[2])
    return rslt

@TraceTimer
def getElement(element, localname, namespaces=XSLTNS.copy()):
    """
    Grab the first element with the given tag name. Ignores namespaces.
    """
    rslt = None
    finder = et.XPath(".//*[local-name() = $name]", namespaces=namespaces)
    targ = finder(element, name=localname)
    rslt = targ[0] if (targ is not None and len(targ) > 0) else None
    return rslt

def getElementList(element, localname, namespaces=XSLTNS.copy()):
    finder = et.XPath(".//*[local-name() = $name]", namespaces=namespaces)
    return finder(element, name=localname)


def genID(length=22):
    """
    generate a unique ID of the given length. Numeric only.
    If length is zero then an empty string is generated.
    """
    from random import randint
    assert length >= 1, "length must be greater than zero."
    o = uuid4()
    h1 = abs(hash(o.bytes))
    h2 = abs(hash(o.int + randint(0, 1000)))
    padded = "%%0%sd%%0%sd"%(length/2, length/2)
    h = padded%(h1,h2)
    rfmt = "%%0%ss"%length
    rslt = rfmt%h
    return rslt if len(rslt) < length else rslt[0:length]

def parallelize(lambdagen: Generator or Iterator, pool: Executor, donecb: Function, errorcb: Function) -> None:
    """
    Run a list or generator of functions in a thread pool. Results sent to the donecb callback, Exceptions are sent to the errorcb ballback.
    :param lambdagen: Generator that produces functions that have no parameters
    :param pool: This will be a ThreadPoolExecutor
    :param donecb: This is a callback that is called with the result
    :param errorcb: This is a callback that is called with an Exception object
    :return: None is returned.
    """
    with pool:
        functions = chunk(100, lambdagen)
        while functions is not None:
            for x in as_completed([pool.submit(f) for f in functions]):
                try:
                    if donecb is not None: donecb(x.result())
                except Exception as e:
                    serviceError("parallelize received an exception from thread because %s"%e)
                    if errorcb is not None: errorcb(e)
            functions = chunk(100, lambdagen)
    return

#@TraceTimer
def batchedPoolRunner(testgenfunc: Function, dispatchfunc: Function, pool: Executor, size: int, validator: Function) -> int:
    """
    Given a concurrent.futures.pool run the tuples produced by testgenfunc in size chunks. 
    Submit results back to pool using dispatchfunc and the returned result of the func.
    
    testgenfunc is a function generator that produces a tuple with function to run and parameters to the func.
    The testgenfunc must return a two tuple with a function in the first position and the function parameters 
    in the second position as a dictionary.
    dispatchfunc must return an object, list or tuple and these should be compatible with its own inputs.
    POOL can be a ThreadPoolExecutor or a ProcessPoolExecutor
    size is the processing batch size for submitting to the pool.
    testgenfunc should produce tuple with the first element as the function and the second element the 
    parameters to the function

    NOTE: never create a generator that produces closures. Python internally updates the closure in place 
    instead of creating a new one so you'll effectively have the same closure produced throughout the 
    generators life. It's a nasty bug.

    *** Currently Doesn't work on Process Pools. Working on a solution.
    """
    td = testgenfunc()
    futures = set([pool.submit(f, **p) for f, p in chunk(size, td)])
    count = 0
    debug("batchedPoolRunner: Starting main loop.") 
    while len(futures) > 0:
        done = set()
        for job in as_completed(futures):
            if count % 1000 == 0 : gc.collect()
            rslt = job.result() if job is not None else None
            if rslt is not None:
                if not validator(rslt):
                    validationFailure("Test case for %s failed validation."%rslt.Function)
            else:
                serviceError("FutureResult from thread pool is None.")
            done.add(job)
            count += 1
            #futures.remove(job)
            if dispatchfunc is not None:
                #debug("Running dispatchfunc %s."%dispatchfunc.__name__)
                if rslt: futures.add(pool.submit(dispatchfunc, rslt))           
            sys.stdout.write(".")
            sys.stdout.flush()
        futures = futures - done
        if len(futures) < 1000: 
            debug("Adding new jobs")
            futures.update(set([pool.submit(f, **p) for f, p in chunk(size, td)]))
        debug(count)
    return count
