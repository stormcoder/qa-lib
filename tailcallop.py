import sys
from functools import wraps, update_wrapper

def tail_recursion_with_stack_inspection(g):
    '''
    Version of tail_recursion decorator using stack-frame inspection.
    '''
    loc_vars ={"in_loop":False,"cnt":0}

    def result(*args, **kwd):
        if not loc_vars["in_loop"]:
            loc_vars["in_loop"] = True
            while 1:
                tc = g(*args,**kwd)
                try:
                    qual, args, kwd = tc
                    if qual == 'continue':
                        continue
                except TypeError:
                    loc_vars["in_loop"] = False
                    return tc
        else:
            f = sys._getframe()
            if f.f_back and f.f_back.f_back and \
                  f.f_back.f_back.f_code == f.f_code:
                return ('continue',args, kwd)
            return g(*args,**kwd)
    return result

def tail_recursion(g):
    '''
    Version of tail_recursion decorator using no stack-frame inspection.
    '''
    loc_vars ={"in_loop":False,"cnt":0}
    @wraps(g)
    def result(*args, **kwd):
        loc_vars["cnt"]+=1
        if not loc_vars["in_loop"]:
            loc_vars["in_loop"] = True
            while 1:
                tc = g(*args,**kwd)
                try:
                    qual, args, kwd = tc
                    if qual == 'continue':
                        continue
                except (TypeError, ValueError):
                    loc_vars["in_loop"] = False
                    return tc
        else:
            if loc_vars["cnt"]%2==0:
                return ('continue',args, kwd)
            else:
                return g(*args,**kwd)
    return result


class tail_recursive(object):

    def __init__(self, func):
        self.func = func
        self.firstcall = True
        self.CONTINUE = object()
        return

    def __call__(self, *args, **kwd):
        update_wrapper(self.__call__, self.func)
        if self.firstcall:
            func = self.func
            CONTINUE = self.CONTINUE
            self.firstcall = False
            try:
                while True:
                    result = func(*args, **kwd)
                    if result is CONTINUE: # update arguments
                        args, kwd = self.argskwd
                    else: # last call
                        return result
            finally:
                self.firstcall = True
        else: # return the arguments of the tail call
            self.argskwd = args, kwd
            return self.CONTINUE

@tail_recursion
def factorial(n, acc=1):
    "calculate a factorial"
    if n == 0:
       return acc
    res = factorial(n-1, n*acc)
    return res
