
class ElGamalPK(object):

    def __init__(self, g, p, q, y):
        self.g = int(g)
        self.p = int(p)
        self.q = int(q)
        self.y = int(y)

class CPProof(object):
    def __init__(self):
        pass

    def verify_proof(self):
        pass

class DCPProof(object):

    def __init__(self):
        # list of max+1 'CPProof's
        pass

    def verify_proof(self):
        pass
