
import json
import crypto

def helios_log(out, verbose=True):
    if verbose is True:
        print("# " + str(out))

def all_subclasses(cls, keyattr="__name__"):
    """Returns a dictionary of all subclasses of class 'cls'
    with key 'keyattr'. Default key is '__name__' i.e. name of class.
    If key is None, the subclass is not inserted in the list
    """
    assert type(cls) == type(object), "Input must be of type 'class'"
    temp = cls.__subclasses__()
    out = {}
    for sub in temp:
        try:
            key = getattr(sub, keyattr)
            if key!=None:
                if type(key)==list:
                    for k in key:
                        out[k] = sub
                else:
                    out[key] = sub
        except Exception:
            pass
    for sub in temp:
        out.update(all_subclasses(sub, keyattr))
    return out

class HeliosObject(object):

    # Fields with alternatives are grouped in tuples
    FIELDS = []
    JSON_NAME = None
    __subdict = None

    # Initialise object using a dictionary
    def __init__(self, dct):
        """Initialise object using a dictionary that contains
        all required attribute values"""

        HeliosObject.__subdict = all_subclasses(HeliosObject, "JSON_NAME")

        self.hash = crypto.b64_sha256(json.dumps(dct))

        for field in self.FIELDS:
            try:
                if type(field) == tuple:
                    at_least_one_found = False
                    for k,arg in enumerate(field):
                        try:
                            value = HeliosObject.execute_init(arg, dct[arg])
                            setattr(self, arg, value)
                            #This is not executed if previous is not successful
                            at_least_one_found = True
                        except:
                            pass
                    if at_least_one_found is False:
                        raise KeyError()
                else:
                    value = HeliosObject.execute_init(field, dct[field])
                    setattr(self, field, value)
            except KeyError:
                if type(field) == tuple:
                    helios_log("WARNING: At least one of " + str(field) + " is required!")
                else:
                    helios_log("WARNING: " + str(field) + " not found. Setting to None!")
                    self.__dict__[field] = None

    @staticmethod
    def execute_init(arg, dct):
        try:
            constructor = HeliosObject.__subdict[arg]
            # If dct is a list instead of a dictionary then recursively execute_init
            if(type(dct) == list):
                return [constructor(x) for x in dct]
            else:
                return constructor(dct)
        except Exception:
            return dct

    def json2file(self, path):
        """Serialise 'self' as a JSON formatted stream to 'path'
        Arguments:
        self -- object to serialise
        path -- path to the file
        """
        path = path.rstrip("/")
        try:
            with open(path, "w") as out:
                if isinstance(self, HeliosObject):
                    json.dump(self.toJSONDict(), out)
                else:
                    json.dump(self, out)
        except Exception as err:
            helios_log("ERROR: {}".format(err))

    def toJSONString(self):
        out = json.dumps(self.toJSONDict())
        return out

    def toJSONDict(self):
        fields = []
        for field in self.FIELDS:
            if type(field) == tuple:
                for t in field:
                    fields.append(t)
            else:
                fields.append(field)
        out = {}
        for field in fields:
            try:
                temp = getattr(self, field)
                out[field] = HeliosObject.__toJSONDict(temp)
            except AttributeError:
                pass
            except Exception: # It will never get here
                helios_log("CRITICAL ERROR!!!")
        return out

    @staticmethod
    def __toJSONDict(obj):
        if isinstance(obj, HeliosObject):
            return obj.toJSONDict()
        elif type(obj) == list:
            return [HeliosObject.__toJSONDict(x) for x in obj]
        else:
            return obj


################################################################################

class ElectionPK(HeliosObject):

    FIELDS = ["g", "p", "q", "y"]
    # If a key=="public_key" is found, create an instance of
    # this class instead of just using the value in the dictionary
    JSON_NAME = "public_key"

    def __init__(self, dct):
        super().__init__(dct)
        self.g = int(self.g)
        self.p = int(self.p)
        self.q = int(self.q)
        self.y = int(self.y)

    def toJSONDict(self):
        out = {}
        out["g"] = str(self.g)
        out["p"] = str(self.p)
        out["q"] = str(self.q)
        out["y"] = str(self.y)
        return out

    def check_membership(self, ciphertext):
        if not (1 < ciphertext.alpha < (self.p-1)):
            return False

        if not (1 < ciphertext.beta < (self.p-1)):
            return False

        if pow(ciphertext.alpha, self.q, self.p) != 1:
            return False

        if pow(ciphertext.beta, self.q, self.p) != 1:
            return False

        return True


class Election(HeliosObject):

    FIELDS = ["cast_url", "description", "frozen_at", "name",
              "openreg", "public_key", "questions", "short_name",
              "use_voter_aliases", "uuid", "voters_hash",
              "voting_ends_at", "voting_starts_at"]

    def __init__(self, dct):
        super().__init__(dct)
        # self.checkOpenReg()

    def verify_voters_hash(self, voters, verbose=True):
        if self.openreg==False and self.voters_hash==None:
            helios_log("WARNING: Open Registration is disabled but "
                       + "voters_hash is null!", verbose)
            return False
        if self.openreg==True and self.voters_hash==None:
            return True
        if self.voters_hash != crypto.b64_sha256(json.dumps(voters)):
            return False

        return True

    def verify_result(self, trustees, tallies, result):
        pass

################################################################################

class Voter(HeliosObject):

    FIELDS = ["election_uuid", "name", "uuid", ("voter_id","voter_id_hash"),
              "voter_type"]

    def __init__(self, dct):
        super().__init__(dct)

    def isAliased(self):
        return isinstance(self, AliasedVoted)


class AliasedVoter(Voter):

    FIELDS = ["alias", "election_uuid", "uuid"]

    def __init__(self, dct):
        super().__init__(dct)


def CreateVoter(dct):
    if "alias" in dct:
        return AliasedVoter(dct)
    else:
        return Voter(dct)

################################################################################

class Ballot(HeliosObject):

    FIELDS = ["cast_at", ("vote_hash", "vote"), "voter_hash", "voter_uuid"]

    def __init__(self, dct):
        super().__init__(dct)


class Vote(HeliosObject):

    FIELDS = ["answers", "election_hash", "election_uuid"]
    JSON_NAME = "vote"

    def __init__(self, dct):
        super().__init__(dct)

    def verify(self, election):
        if len(self.answers) != len(election.questions):
            return False

        if self.election_hash != election.hash:
            return False

        if self.election_uuid != election.uuid:
            return False

        for i in range(len(election.questions)):
            answer = self.answers[i]
            question = election.questions[i]
            if not answer.verify(election.public_key, question['min'], question['max']):
                return False

        return True

    def get_all_hashes(self):
        expected_hashes = 0
        all_hashes = set()
        for answer in self.answers:
            for proof in answer.individual_proofs:
                expected_hashes = expected_hashes + 1
                all_hashes.add(proof.sha_challenge)
            if answer.overall_proof is not None:
                expected_hashes = expected_hashes + 1
                all_hashes.add(answer.overall_proof.sha_challenge)
        if 0 in all_hashes:
            helios_log("ERROR: Please run verify() before running get_all_hashes!")
            sys.exit(1)
        return all_hashes,expected_hashes


class EncryptedAnswer(HeliosObject):

    FIELDS = ["choices", "individual_proofs", "overall_proof"]
    JSON_NAME = "answers"

    def __init__(self, dct):
        super().__init__(dct)
        if self.overall_proof is not None:
            self.overall_proof = HeliosDCPProof(self.overall_proof)

    def verify(self, public_key, question_min=0, question_max=None):
        homomorphic_prod = 1

        for choice_num,choice in enumerate(self.choices):
            dcpproof = self.individual_proofs[choice_num]

            if not public_key.check_membership(choice):
                return False

            if not dcpproof.verify(public_key, choice, 0, 1):
                return False

            if question_max is not None:
                homomorphic_prod = choice * homomorphic_prod

        if question_max is not None:
            try:
                if not self.overall_proof.verify(public_key, homomorphic_prod, question_min, question_max):
                    return False
            except AttributeError:
                helios_log("WARNING: 'question_max' is set but overall proof is missing!!!")
                return False

        return True


class ElGamalCiphertext(HeliosObject):

    FIELDS = ["alpha", "beta"]
    JSON_NAME = "choices"

    def __init__(self, dct):
        # super().__init__(dct)
        self.alpha = int(dct["alpha"])
        self.beta = int(dct["beta"])

    def __mul__(self, other):
        if other == 0 or other == 1:
            alpha = self.alpha
            beta = self.beta
        else:
            alpha = self.alpha * other.alpha
            beta = self.beta * other.beta
        return ElGamalCiphertext({"alpha": alpha, "beta": beta})

    def toJSONDict(self):
        return {"alpha": str(self.alpha), "beta": str(self.beta)}

class HeliosCPProof(HeliosObject):

    FIELDS = ["challenge", "commitment", "response"]

    def __init__(self, dct):
        self.hash = crypto.b64_sha256(json.dumps(dct))
        self.challenge = int(dct["challenge"])
        self.A = int(dct["commitment"]["A"])
        self.B = int(dct["commitment"]["B"])
        self.response = int(dct["response"])

    def toJSONDict(self):
        out = {}
        out["challenge"] = str(self.challenge)
        out["commitment"] = {"A": str(self.A), "B": str(self.B)}
        out["response"] = str(self.response)
        return out

    # (g^x, g^r, g^r^x) = (key, alpha, beta/g^v)
    def verify_choice(self, public_key, plaintext, ciphertext):
        g = public_key.g
        p = public_key.p
        # QUESTION: Check if proof elements are in group?
        X = public_key.y
        Y = ciphertext.alpha
        Z = (ciphertext.beta * crypto.modinverse(plaintext, p)) % p

        return crypto.verify_cp_proof( (X,Y,Z), g, p, (self.A, self.B),
                                       self.challenge, self.response )

    # (g^r, g^x, g^r^x) = (alpha, key, dec_factor)
    def verify_partial_decryption_proof(self, public_key, dec_factor, ciphertext):
        g = public_key.g
        p = public_key.p
        X = ciphertext.alpha
        Y = public_key.y
        Z = dec_factor

        if not crypto.verify_cp_proof( (X,Y,Z), g, p, (self.A, self.B),
                                       self.challenge, self.response ):
            return False

        computed_challenge = crypto.int_sha1( str(self.A) + "," + str(self.B) )

        return computed_challenge == self.challenge

class HeliosSchnorrProof(HeliosObject):

    FIELDS = ["challenge", "commitment", "response"]

    def __init__(self, dct):
        self.hash = crypto.b64_sha256(json.dumps(dct))
        self.challenge = int(dct["challenge"])
        self.commitment = int(dct["commitment"])
        self.response = int(dct["response"])

    def toJSONDict(self):
        out = {}
        out["challenge"] = str(self.challenge)
        out["commitment"] = str(self.commitment)
        out["response"] = str(self.response)
        return out

    def verify(self, public_key):
        g = public_key.g
        p = public_key.p
        X = public_key.y

        if not crypto.verify_schnorr_proof(X, g, p, self.commitment,
                                           self.challenge, self.response):
            return False

        expected_challenge = crypto.int_sha1(str(self.commitment))

        return expected_challenge == self.challenge


class HeliosDCPProof(HeliosObject):

    JSON_NAME = "individual_proofs"

    def __init__(self, proofs):
        self.proofs = []
        for proof in proofs:
            self.proofs.append(HeliosCPProof(proof))
        self.sha_challenge = 0

    def toJSONDict(self):
        return [proof.toJSONDict() for proof in self.proofs]

    def verify(self, public_key, ciphertext, min_allowed, max_allowed):
        g = public_key.g
        p = public_key.p
        str_to_hash = ""
        computed_challenge = 0

        if len(self.proofs) != (max_allowed-min_allowed+1):
            return False

        for v,proof in enumerate(self.proofs):
            g_v = pow(g, v+min_allowed, p)

            # Create string to hash
            str_to_hash += "{},{},".format(proof.A, proof.B)

            # Compute total challenge
            computed_challenge += proof.challenge

            # Check each proof
            if not proof.verify_choice(public_key, g_v, ciphertext):
                return False
        computed_challenge = computed_challenge % public_key.q
        str_to_hash = str_to_hash.rstrip(",")

        # Compute expected challenge
        expected_challenge = crypto.int_sha1(str_to_hash)
        self.sha_challenge = expected_challenge

        return expected_challenge == computed_challenge


class Trustee(HeliosObject):

    FIELDS = ["decryption_factors", "decryption_proofs", ("email"), "pok",
              "public_key", "public_key_hash", "uuid"]

    def __init__(self, dct):
        self.decryption_factors = []
        for factor_list in dct["decryption_factors"]:
            temp = [int(x) for x in factor_list]
            self.decryption_factors.append(temp)

        self.decryption_proofs = []
        for proof_list in dct["decryption_proofs"]:
            temp = [HeliosCPProof(x) for x in proof_list]
            self.decryption_proofs.append(temp)

        try:
            self.email = dct["email"]
        except AttributeError:
            pass

        self.pok = HeliosSchnorrProof(dct["pok"])
        self.public_key = ElectionPK(dct["public_key"])
        self.public_key_hash = dct["public_key_hash"]
        self.uuid = dct["uuid"]

    def toJSONDict(self):
        out = super().toJSONDict()
        decryption_factors = out["decryption_factors"]
        out["decryption_factors"] = []
        for factor_list in decryption_factors:
            temp = [str(x) for x in factor_list]
            out["decryption_factors"].append(temp)
        return out

    def verify_secret_key(self):
        return self.pok.verify(self.public_key)
