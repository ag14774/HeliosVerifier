
import json
import crypto
import sys

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

class HeliosException(Exception):
    def __init__(self, message, msg_type=""):
        super().__init__(message)
        self.message = message
        self.msg_type = msg_type

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

    class CiphertextCheckError(HeliosException):
        def __init__(self, message="", uuid=None, question_num=None, choice_num=None):
            super().__init__(message)
            self.uuid = uuid
            self.question_num = question_num
            self.choice_num = choice_num

    class ElectionParamsError(HeliosException):
        def __init__(self, message=""):
            super().__init__(message)

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
            raise self.CiphertextCheckError("alpha not within the correct range")

        if not (1 < ciphertext.beta < (self.p-1)):
            raise self.CiphertextCheckError("beta not within the correct range")

        if pow(ciphertext.alpha, self.q, self.p) != 1:
            raise self.CiphertextCheckError("alpha is not an element of the group")

        if pow(ciphertext.beta, self.q, self.p) != 1:
            raise self.CiphertextCheckError("beta is not an element of the group")

        return True

    def check_key_params(self):
        if not miller_rabin(self.p):
            raise self.ElectionParamsError("p is not a prime")
        if not miller_rabin(self.q):
            raise self.ElectionParamsError("q is not a prime")
        if self.q == (self.p - 1)/2:
            return True
        else:
            if ((self.p - 1) % self.q) > 0:
                raise self.ElectionParamsError("q does not divide p-1")
            if (self.p - 1) % (self.q*self.q) == 0:
                raise self.ElectionParamsError("q^2 divides p-1")
            return True


class Election(HeliosObject):

    FIELDS = ["cast_url", "description", "frozen_at", "name",
              "openreg", "public_key", "questions", "short_name",
              "use_voter_aliases", "uuid", "voters_hash",
              "voting_ends_at", "voting_starts_at"]

    class VotersHashMissing(HeliosException):
        def __init__(self, message=""):
            super().__init__(message)

    class VotersHashCheckError(HeliosException):
        def __init__(self, message=""):
            super().__init__(message)

    def __init__(self, dct):
        super().__init__(dct)
        # self.checkOpenReg()

    def verify_voters_hash(self, voters, verbose=True):
        if self.openreg==False and self.voters_hash==None:
            helios_log("WARNING: Open Registration is disabled but "
                       + "voters_hash is null!", verbose)
            raise self.VotersHashMissing()
        if self.openreg==True and self.voters_hash==None:
            return True
        if self.voters_hash != crypto.b64_sha256(json.dumps(voters)):
            raise self.VotersHashCheckError()

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

    def verify(self, election):
        if self.vote is not None:
            try:
                self.vote.verify(election)
            except HeliosException as exc:
                exc.uuid = self.voter_uuid
                raise


class Vote(HeliosObject):

    FIELDS = ["answers", "election_hash", "election_uuid"]
    JSON_NAME = "vote"

    class BallotWrongNumberOfAnswers(HeliosException):
        def __init__(self, message="", uuid=None):
            super().__init__(message)
            self.uuid = uuid

    class BallotNonMatchingElectionHash(HeliosException):
        def __init__(self, message="", uuid=None):
            super().__init__(message)
            self.uuid = uuid

    class BallotNonMatchingElectionUUID(HeliosException):
        def __init__(self, message="", uuid=None):
            super().__init__(message)
            self.uuid = uuid

    def __init__(self, dct):
        super().__init__(dct)

    def verify(self, election):
        if len(self.answers) != len(election.questions):
            raise self.BallotWrongNumberOfAnswers()

        if self.election_hash != election.hash:
            raise self.BallotNonMatchingElectionHash()

        if self.election_uuid != election.uuid:
            raise self.BallotNonMatchingElectionUUID()

        for i in range(len(election.questions)):
            answer = self.answers[i]
            question = election.questions[i]
            try:
                answer.verify(election.public_key, question['min'], question['max'])
            except HeliosException as exc:
                exc.question_num = i # Add question num to exception
                raise

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

    class OverallProofMissing(HeliosException):
        def __init__(self, message="", uuid=None, question_num=None):
            super().__init__(message)
            self.uuid = uuid
            self.question_num = question_num

    def __init__(self, dct):
        super().__init__(dct)
        if self.overall_proof is not None:
            self.overall_proof = HeliosDCPProof(self.overall_proof)

    def verify(self, public_key, question_min=0, question_max=None):
        homomorphic_prod = 1

        for choice_num,choice in enumerate(self.choices):
            dcpproof = self.individual_proofs[choice_num]

            try:
                public_key.check_membership(choice)
            except HeliosException as exc:
                exc.choice_num = choice_num
                raise

            try:
                dcpproof.verify(public_key, choice, 0, 1)
            except HeliosException as exc:
                exc.proof_type = "individual"
                exc.choice_num = choice_num
                raise

            if question_max is not None:
                homomorphic_prod = choice * homomorphic_prod

        if question_max is not None:
            try:
                self.overall_proof.verify(public_key, homomorphic_prod, question_min, question_max)
            except HeliosException as exc:
                exc.proof_type = "overall"
                raise
            except AttributeError:
                helios_log("WARNING: 'question_max' is set but overall proof is missing!!!")
                raise self.OverallProofMissing()

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

class HeliosDCPProof(HeliosObject):

    JSON_NAME = "individual_proofs"

    class DCPWrongNumberOfProofs(HeliosException):
        def __init__(self, message="", uuid=None, question_num=None,
                     choice_num=None, proof_type=None):
            super().__init__(message)
            self.uuid = uuid
            self.question_num = question_num
            self.choice_num = choice_num
            self.proof_type = proof

    class DCPProofFailed(HeliosException):
        def __init__(self, message="", uuid=None, question_num=None,
                     choice_num=None, proof_type=None):
            super().__init__(message)
            self.uuid = uuid
            self.question_num = question_num
            self.choice_num = choice_num
            self.proof_type = proof

    class DCPChallengeCheckFailed(HeliosException):
        def __init__(self, message="", uuid=None, question_num=None,
                     choice_num=None, proof_type=None):
            super().__init__(message)
            self.uuid = uuid
            self.question_num = question_num
            self.choice_num = choice_num
            self.proof_type = proof

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
            raise self.DCPWrongNumberOfProofs()

        for v,proof in enumerate(self.proofs):
            # Create string to hash
            str_to_hash += "{},{},".format(proof.A, proof.B)

            # Compute total challenge
            computed_challenge += proof.challenge

            # Check each proof
            if not proof.verify_choice(public_key, v+min_allowed, ciphertext):
                raise self.DCPProofFailed()
        computed_challenge = computed_challenge % public_key.q
        str_to_hash = str_to_hash.rstrip(",")

        # Compute expected challenge
        expected_challenge = crypto.int_sha1(str_to_hash)
        self.sha_challenge = expected_challenge

        res = (expected_challenge == computed_challenge)
        if not res:
            raise self.DCPChallengeCheckFailed()
        else:
            return True

class HeliosCPProof(HeliosObject):

    FIELDS = ["challenge", "commitment", "response"]

    PLAINTEXT_INVERSE_CACHE = {}

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
        q = public_key.q
        # QUESTION: Check if proof elements are in group?
        try:
            g_2minus_m = HeliosCPProof.PLAINTEXT_INVERSE_CACHE[plaintext]
        except KeyError:
            i_plaintext = q - plaintext #(mod q)
            g_2minus_m = pow(g, i_plaintext, p)
            HeliosCPProof.PLAINTEXT_INVERSE_CACHE[plaintext] = g_2minus_m
        X = public_key.y
        Y = ciphertext.alpha
        Z = ( ciphertext.beta * g_2minus_m ) % p

        return crypto.verify_cp_proof( (X,Y,Z), g, p, q, (self.A, self.B),
                                       self.challenge, self.response )

    # (g^r, g^x, g^r^x) = (alpha, key, dec_factor)
    def verify_partial_decryption_proof(self, public_key, dec_factor, ciphertext):
        g = public_key.g
        p = public_key.p
        q = public_key.q
        X = ciphertext.alpha
        Y = public_key.y
        Z = dec_factor

        if not crypto.verify_cp_proof( (X,Y,Z), g, p, q, (self.A, self.B),
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
