from collections import defaultdict
from enum import Enum, auto

from fastec import point_add, point_mul
from roast import H, SessionContext, pre_agg, sign_agg

# Enum values are used for priority (small value = high priority)
class ActionType(Enum):
    NO_OP = 1
    INCOMING = 3
    SESSION_START = 4
    SESSION_SUCCESS = 2

class CoordinatorModel:
    def __init__(self, X, i_to_X, t, n, msg):
        assert len(i_to_X) == n
        assert 2 <= t <= n

        self.X = X
        self.i_to_X = i_to_X
        self.t = t
        self.n = n
        self.msg = msg

        # Invariants:
        #   len(self.ready) < t
        #   len(self.malicious) <= n - t
        self.ready = set()
        self.malicious = set()

        self.i_to_pre = {}
        self.i_to_sid = {}

        # TODO: Is it possible to just store sid_to_ctx?
        self.sid_ctr = 0
        self.sid_to_T = {}
        self.sid_to_R = {}
        self.sid_to_pre = {}
        self.sid_to_i_to_s = defaultdict(dict)

    def handle_incoming(self, i, s_i, pre_i, share_is_valid):
        if i in self.malicious:
            return (ActionType.NO_OP, None)

        if i in self.ready or (i not in self.i_to_pre and s_i is not None):
            self.mark_malicious(i)
            return (ActionType.NO_OP, None)

        if s_i is not None:
            if not share_is_valid:
                self.mark_malicious(i)
                return (ActionType.NO_OP, None)

            sid = self.i_to_sid[i]
            T = self.sid_to_T[sid]
            ctx = SessionContext(self.X, self.i_to_X, self.msg, T, self.sid_to_R[sid], self.sid_to_pre[sid], self.i_to_pre[i])
            self.sid_to_i_to_s[sid][i] = s_i

            if len(self.sid_to_i_to_s[sid]) == self.t:
                sig = sign_agg(ctx, self.sid_to_i_to_s[sid])
                return (ActionType.SESSION_SUCCESS, (ctx, sig))

        self.i_to_pre[i] = pre_i
        self.ready.add(i)
        if len(self.ready) == self.t:
            self.sid_ctr += 1
            sid = self.sid_ctr
            T = set(self.ready)
            pre = pre_agg(self.i_to_pre, T)
            D, E = pre
            b = H('non', self.X, self.msg, D, E)
            R = point_add(D, point_mul(E, b))
            for i in T:
                self.i_to_sid[i] = sid
            self.sid_to_T[sid] = T
            self.sid_to_R[sid] = R
            self.sid_to_pre[sid] = pre
            self.ready.clear()

            data = []
            for i in T:
                ctx = SessionContext(self.X, self.i_to_X, self.msg, T, R, pre, self.i_to_pre[i])
                data.append((ctx, i))
            return (ActionType.SESSION_START, data)

        return (ActionType.NO_OP, None)

    def mark_malicious(self, i):
        self.malicious.add(i)
        assert len(self.malicious) <= self.n - self.t
