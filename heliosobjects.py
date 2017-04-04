"""Helios data structures."""
import json

import crypto


def all_subclasses(cls, keyattr="__name__"):
    """Return a dictionary of all subclasses of class 'cls' with key 'keyattr'.

    Default key is '__name__' i.e. name of class.
    If key is None, the subclass is not inserted in the list
    """
    assert type(cls) == type(object), "Input must be of type 'class'"
    temp = cls.__subclasses__()
    out = {}
    for sub in temp:
        try:
            key = getattr(sub, keyattr)
            if key is not None:
                if type(key) == list:
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
    """Generic Helios Exception."""

    def __init__(self, message, msg_type=""):
        """
        Generic HeliosException constructor.

        'message' is self-explanatory.
        'msg_type' is currently not used. It can be ERROR,
        INFO or WARNING.
        """
        super().__init__(message)
        self.message = message
        self.msg_type = msg_type


class HeliosObject(object):
    """
    Generic HeliosObject, not used by itself.

    All Helios structures inherit from 'HeliosObject'.
    It provides methods for converting to and from JSON notation.
    """

    FIELDS = []  # Optional fields are in tuples.
    JSON_NAME = None  # Refered to by this name in JSON
    __subdict = None  # All subclasses keyed by 'JSON_NAME'

    def __init__(self, dct):
        """Initialise object using a dictionary."""
        HeliosObject.__subdict = all_subclasses(HeliosObject, "JSON_NAME")

        self.hash = crypto.b64_sha256(json.dumps(dct))

        # Default constructor loops over all fields in 'self.FIELDS',
        # and finds the value in the dictionary. If there is a HeliosObject
        # subclass for this structure, the value is then passed as a
        # parameter to the correct contructor.
        for field in self.FIELDS:
            if type(field) == tuple:
                for k, arg in enumerate(field):
                    try:
                        value = HeliosObject.execute_init(arg, dct[arg])
                        setattr(self, arg, value)
                    # Optional field - do not throw error
                    except KeyError:
                        pass
            else:
                try:
                    value = HeliosObject.execute_init(field, dct[field])
                    setattr(self, field, value)
                except KeyError:
                    print("## WARNING: {} not found. Setting to None!".format(
                        field))
                    self.__dict__[field] = None

    @staticmethod
    def execute_init(arg, dct):
        """
        Find constructor for arg and create object.

        This will search to find the correct subclass and use it to
        create a new object with 'dct' as input. If no class is found,
        dct is returned back as is.
        """
        try:
            constructor = HeliosObject.__subdict[arg]
            # If dct is a list instead of a dictionary
            # then recursively execute_init
            if (type(dct) == list):
                return [constructor(x) for x in dct]
            else:
                return constructor(dct)
        except Exception:
            return dct

    def json2file(self, path):
        """
        Serialise 'self' as a JSON formatted stream to 'path'.

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
            print("## ERROR: {}".format(err))

    def toJSONString(self):
        """Convert to a JSON object and then stringify."""
        out = json.dumps(self.toJSONDict())
        return out

    def toJSONDict(self):
        """Covnert to JSON object."""
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
            except Exception as e:  # It will never get here
                print("## CRITICAL ERROR: {}!!!".format(e))
        return out

    @staticmethod
    def __toJSONDict(obj):
        if isinstance(obj, HeliosObject):
            return obj.toJSONDict()
        elif type(obj) == list:
            return [HeliosObject.__toJSONDict(x) for x in obj]
        else:
            return obj


###############################################################################


class ElectionPK(HeliosObject):
    """Class used for the election public key."""

    FIELDS = ["g", "p", "q", "y"]

    # If a key=="public_key" is found, create an instance of
    # this class instead of just using the value in the dictionary
    JSON_NAME = "public_key"

    def __init__(self, dct):
        """
        Constructor for ElectionPK class.

        Converts strings to integers before storing them.
        """
        super().__init__(dct)
        self.g = int(self.g)
        self.p = int(self.p)
        self.q = int(self.q)
        self.y = int(self.y)

    def toJSONDict(self):
        """Same as in HeliosObject.'toJSONDict'."""
        out = {}
        out["g"] = str(self.g)
        out["p"] = str(self.p)
        out["q"] = str(self.q)
        out["y"] = str(self.y)
        return out

    def check_membership(self, ciphertext):
        """
        Check if an ElGamal ciphertext is an element of the group.

        1)Check if alpha is in the correct range.
        2)Check if beta is in the correct range.
        3)Check if alpha is an element of the group.
        4)Check if beta is an element of the group.
        """
        if not (1 < ciphertext.alpha < (self.p - 1)):
            raise self.CiphertextCheckError(
                "alpha not within the correct range")

        if not (1 < ciphertext.beta < (self.p - 1)):
            raise self.CiphertextCheckError(
                "beta not within the correct range")

        if pow(ciphertext.alpha, self.q, self.p) != 1:
            raise self.CiphertextCheckError(
                "alpha is not an element of the group")

        if pow(ciphertext.beta, self.q, self.p) != 1:
            raise self.CiphertextCheckError(
                "beta is not an element of the group")

        return True

    def check_election_params(self):
        """
        Check if the election parameters are correct.
        """
        if self.p.bit_length() < 2048:
            raise self.ElectionParamsError(
                "p is only {} bits. >=2048 is recommended".format(
                    self.p.bit_length()))
        if self.q.bit_length() < 256:
            raise self.ElectionParamsError(
                "q is only {} bits. >=256 is recommended".format(
                    self.q.bit_length()))
        if pow(self.g, self.q, self.p) != 1:
            raise self.ElectionParamsError(
                "g is not a generator of a group of order q")
        if not (1 < self.g < self.p-1):
            raise self.ElectionParamsError("g is not within the correct range")
        if pow(self.y, self.q, self.p) != 1:
            raise self.ElectionParamsError("y is not a member of the group")
        if not (1 < self.y < self.p-1):
            raise self.ElectionParamsError("y is not within the correct range")
        if not crypto.miller_rabin(self.p):
            raise self.ElectionParamsError("p is not a prime")
        if not crypto.miller_rabin(self.q):
            raise self.ElectionParamsError("q is not a prime")
        if self.q == (self.p - 1) // 2:
            return True
        else:
            if ((self.p - 1) % self.q) > 0:
                raise self.ElectionParamsError("q does not divide p-1")
            if (self.p - 1) % (self.q * self.q) == 0:
                raise self.ElectionParamsError("q^2 divides p-1")
            return True

    class CiphertextCheckError(HeliosException):
        def __init__(self,
                     message="",
                     uuid=None,
                     question_num=None,
                     choice_num=None):
            super().__init__(message)
            self.uuid = uuid
            self.question_num = question_num
            self.choice_num = choice_num

    class ElectionParamsError(HeliosException):
        def __init__(self, message=""):
            super().__init__(message)


class Election(HeliosObject):

    FIELDS = [
        "cast_url", "description", "frozen_at", "name", "openreg",
        "public_key", "questions", "short_name", "use_voter_aliases", "uuid",
        "voters_hash", "voting_ends_at", "voting_starts_at"
    ]

    def __init__(self, dct):
        super().__init__(dct)

    def verify_voters_hash(self, voters, verbose=True):
        if self.openreg is False and self.voters_hash is None:
            # raise self.VotersHashMissing()
            return
        if self.openreg is True and self.voters_hash is None:
            return True
        if self.voters_hash != crypto.b64_sha256(json.dumps(voters)):
            raise self.VotersHashCheckError()

        return True

    class VotersHashMissing(HeliosException):
        def __init__(self, message=""):
            super().__init__(message)

    class VotersHashCheckError(HeliosException):
        def __init__(self, message=""):
            super().__init__(message)


###############################################################################


class Voter(HeliosObject):

    FIELDS = [
        "election_uuid", "name", "uuid", ("voter_id", "voter_id_hash"),
        "voter_type"
    ]

    def __init__(self, dct):
        super().__init__(dct)

    def isAliased(self):
        """Check if voter is aliased."""
        return hasattr(self, 'alias')


class AliasedVoter(Voter):

    FIELDS = ["alias", "election_uuid", "uuid"]

    def __init__(self, dct):
        super().__init__(dct)


def CreateVoter(dct):
    if "alias" in dct:
        return AliasedVoter(dct)
    else:
        return Voter(dct)


###############################################################################


class Ballot(HeliosObject):

    FIELDS = ["cast_at", ("vote_hash", "vote"), "voter_hash", "voter_uuid"]

    def __init__(self, dct):
        super().__init__(dct)

    def verify(self, election):
        if self.vote is not None:
            try:
                return self.vote.verify(election)
            except HeliosException as exc:
                exc.uuid = self.voter_uuid
                raise
        else:
            return True

    def get_all_hashes(self):
        try:
            return self.vote.get_all_hashes()
        except HeliosException as exc:
            exc.uuid = self.voter_uuid
            raise


class Vote(HeliosObject):

    FIELDS = ["answers", "election_hash", "election_uuid"]
    JSON_NAME = "vote"

    def __init__(self, dct):
        super().__init__(dct)

    def verify(self, election):
        if len(self.answers) != len(election.questions):
            raise self.BallotNotWellFormed()

        if self.election_hash != election.hash:
            raise self.BallotNonMatchingElectionHash()

        if self.election_uuid != election.uuid:
            raise self.BallotNonMatchingElectionUUID()

        for i in range(len(election.questions)):
            answer = self.answers[i]
            question = election.questions[i]
            if len(answer.choices) != len(question["answers"]):
                raise self.BallotNotWellFormed()
            try:
                answer.verify(election.public_key, question['min'],
                              question['max'])
            except HeliosException as exc:
                exc.question_num = i  # Add question num to exception
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
        if len(all_hashes) != expected_hashes:
            raise self.BallotChallengeReused()
        return all_hashes

    class BallotNotWellFormed(HeliosException):
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

    class BallotChallengeReused(HeliosException):
        def __init__(self, message="", uuid=None):
            super().__init__(message)
            self.uuid = uuid


class EncryptedAnswer(HeliosObject):

    FIELDS = ["choices", "individual_proofs", "overall_proof"]
    JSON_NAME = "answers"

    def __init__(self, dct):
        super().__init__(dct)
        if self.overall_proof is not None:
            self.overall_proof = HeliosDCPProof(self.overall_proof)

    def verify(self, public_key, question_min=0, question_max=None):
        homomorphic_prod = 1

        for choice_num, choice in enumerate(self.choices):
            try:
                dcpproof = self.individual_proofs[choice_num]
            except IndexError:
                raise Vote.BallotNotWellFormed()

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
                self.overall_proof.verify(public_key, homomorphic_prod,
                                          question_min, question_max)
            except HeliosException as exc:
                exc.proof_type = "overall"
                raise
            except AttributeError:
                raise self.OverallProofMissing()

        return True

    class OverallProofMissing(HeliosException):
        def __init__(self, message="", uuid=None, question_num=None):
            super().__init__(message)
            self.uuid = uuid
            self.question_num = question_num


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

    def __rmul__(self, other):
        return ElGamalCiphertext.__mul__(self, other)

    def toJSONDict(self):
        return {"alpha": str(self.alpha), "beta": str(self.beta)}


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
        str_to_hash = ""
        computed_challenge = 0

        if len(self.proofs) != (max_allowed - min_allowed + 1):
            raise self.DCPWrongNumberOfProofs()

        for v, proof in enumerate(self.proofs):
            # Create string to hash
            str_to_hash += str(proof.A) + "," + str(proof.B) + ","

            # Compute total challenge
            computed_challenge += proof.challenge

            # Check each proof
            if not proof.verify_choice(public_key, v + min_allowed,
                                       ciphertext):
                raise self.DCPProofFailed()
        computed_challenge = computed_challenge % public_key.q
        str_to_hash = str_to_hash[:-1]

        # Compute expected challenge
        expected_challenge = crypto.int_sha1(str_to_hash)
        self.sha_challenge = expected_challenge

        res = (expected_challenge == computed_challenge)
        if not res:
            raise self.DCPChallengeCheckFailed()
        else:
            return True

    class DCPWrongNumberOfProofs(HeliosException):
        def __init__(self,
                     message="",
                     uuid=None,
                     question_num=None,
                     choice_num=None,
                     proof_type=None):
            super().__init__(message)
            self.uuid = uuid
            self.question_num = question_num
            self.choice_num = choice_num
            self.proof_type = proof_type

    class DCPProofFailed(HeliosException):
        def __init__(self,
                     message="",
                     uuid=None,
                     question_num=None,
                     choice_num=None,
                     proof_type=None):
            super().__init__(message)
            self.uuid = uuid
            self.question_num = question_num
            self.choice_num = choice_num
            self.proof_type = proof_type

    class DCPChallengeCheckFailed(HeliosException):
        def __init__(self,
                     message="",
                     uuid=None,
                     question_num=None,
                     choice_num=None,
                     proof_type=None):
            super().__init__(message)
            self.uuid = uuid
            self.question_num = question_num
            self.choice_num = choice_num
            self.proof_type = proof_type


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

        try:
            g_2minus_m = HeliosCPProof.PLAINTEXT_INVERSE_CACHE[plaintext]
        except KeyError:
            i_plaintext = q - plaintext  # (mod q)
            g_2minus_m = pow(g, i_plaintext, p)
            HeliosCPProof.PLAINTEXT_INVERSE_CACHE[plaintext] = g_2minus_m
        X = public_key.y
        Y = ciphertext.alpha
        Z = (ciphertext.beta * g_2minus_m) % p

        return crypto.verify_cp_proof((X, Y, Z), g, p, q, (self.A, self.B),
                                      self.challenge, self.response)

    # (g^r, g^x, g^r^x) = (alpha, key, dec_factor)
    def verify_partial_decryption_proof(self, public_key, dec_factor,
                                        ciphertext):
        g = public_key.g
        p = public_key.p
        q = public_key.q
        X = ciphertext.alpha
        Y = public_key.y
        Z = dec_factor

        if not crypto.verify_cp_proof((X, Y, Z), g, p, q, (self.A, self.B),
                                      self.challenge, self.response):
            return False

        computed_challenge = crypto.int_sha1(str(self.A) + "," + str(self.B))

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
        q = public_key.q
        X = public_key.y

        if not crypto.verify_schnorr_proof(X, g, p, q, self.commitment,
                                           self.challenge, self.response):
            return False

        expected_challenge = crypto.int_sha1(str(self.commitment))

        return expected_challenge == self.challenge


class Trustee(HeliosObject):

    FIELDS = [
        "decryption_factors", "decryption_proofs", ("email"), "pok",
        "public_key", "public_key_hash", "uuid"
    ]

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
        # FIXME:check public key hash
        if self.pok.verify(self.public_key) is False:
            raise self.TrusteeKeyVerificationFailed(
                email=self.email, uuid=self.uuid)
        return True

    def verify_dec_proof(self, question_num, choice_num, ciphertext):
        dec_factor = self.decryption_factors[question_num][choice_num]
        proof = self.decryption_proofs[question_num][choice_num]
        res = proof.verify_partial_decryption_proof(self.public_key,
                                                    dec_factor, ciphertext)
        if res is False:
            raise self.TrusteeDecryptionProofFailed(
                uuid=self.uuid, email=self.email)
        return True

    def verify_decryption_proofs(self, ciphertexts):
        for q_num in range(len(ciphertexts)):
            for c_num in range(len(ciphertexts[q_num])):
                self.verify_dec_proof(q_num, c_num, ciphertexts[q_num][c_num])
        return True

    class TrusteeKeyVerificationFailed(HeliosException):
        def __init__(self, message="", email=None, uuid=None):
            super().__init__(message)
            self.email = email
            self.uuid = uuid

    class TrusteeDecryptionProofFailed(HeliosException):
        def __init__(self, message="", email=None, uuid=None):
            super().__init__(message)
            self.email = email
            self.uuid = uuid


class Tally(HeliosObject):
    def __init__(self, election):
        self.tallies = [[1] * len(q["answers"]) for q in election.questions]
        self.factors = [[1] * len(q["answers"]) for q in election.questions]
        self.result = [[1] * len(q["answers"]) for q in election.questions]
        self.vote_fingerprints = set()
        self.pk = election.public_key

    def add_vote(self, ballot):
        prev_length = len(self.vote_fingerprints)
        self.vote_fingerprints.add(ballot.vote.hash)
        new_length = len(self.vote_fingerprints)
        if (new_length == prev_length):
            return

        for q_num in range(len(self.tallies)):
            for c_num in range(len(self.tallies[q_num])):
                ciphertext = ballot.vote.answers[q_num].choices[c_num]
                self.tallies[q_num][c_num] *= ciphertext
                self.tallies[q_num][c_num].alpha %= self.pk.p
                self.tallies[q_num][c_num].beta %= self.pk.p

    def add_dec_factors(self, trustee):
        for q_num in range(len(self.factors)):
            for c_num in range(len(self.factors[q_num])):
                self.factors[q_num][c_num] *= trustee.decryption_factors[
                    q_num][c_num]
                self.factors[q_num][c_num] %= self.pk.p

    def verify_result(self, result):
        for q_num in range(len(self.factors)):
            for c_num in range(len(self.factors[q_num])):
                temp = self.factors[q_num][c_num] * pow(
                    self.pk.g, result[q_num][c_num], self.pk.p)
                temp = temp % self.pk.p
                if temp != self.tallies[q_num][c_num].beta:
                    raise self.ResultVerificationFailed(
                        question_num=q_num, choice_num=c_num)
        return True

    def decrypt_from_factors(self):
        table = {}
        for i in range(len(self.vote_fingerprints) + 1):
            table[pow(self.pk.g, i, self.pk.p)] = i

        for q_num in range(len(self.result)):
            for c_num in range(len(self.result[q_num])):
                try:
                    factor_inverse = crypto.modinverse(
                        self.factors[q_num][c_num], self.pk.p)
                    beta = self.tallies[q_num][c_num].beta
                    self.result[q_num][c_num] = (beta *
                                                 factor_inverse) % self.pk.p
                    self.result[q_num][c_num] = table[self.result[q_num][
                        c_num]]
                except Exception as e:
                    self.result[q_num][c_num] = 'X'

        return self.result

    class ResultVerificationFailed(HeliosException):
        def __init__(self, message="", question_num=None, choice_num=None):
            super().__init__(message)
            self.question_num = question_num
            self.choice_num = choice_num
