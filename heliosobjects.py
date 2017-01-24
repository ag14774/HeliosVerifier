
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
                return [execute_init(arg, x) for x in dct]
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
        if isinstance(self, HeliosObject):
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
                    if isinstance(temp, HeliosObject):
                        out[field] = temp.toJSONDict()
                    else:
                        out[field] = HeliosObject.toJSONDict(temp)
                except AttributeError:
                    pass
                except Exception: # It will never get here
                    helios_log("CRITICAL ERROR!!!")
            return out
        elif type(self) == list:
            return [HeliosObject.toJSONDict(x) for x in self]
        else:
            return self

################################################################################

class ElectionPK(HeliosObject, crypto.ElGamalPK):

    FIELDS = ["g", "p", "q", "y"]
    JSON_NAME = "public_key"

    def __init__(self, dct):
        HeliosObject.__init__(self, dct)
        crypto.ElGamalPK.__init__(self, self.g, self.p, self.q, self.y)

    def toJSONDict(self):
        out = {}
        out["g"] = str(self.g)
        out["p"] = str(self.p)
        out["q"] = str(self.q)
        out["y"] = str(self.y)
        return out


class Election(HeliosObject):

    FIELDS = ["cast_url", "description", "frozen_at", "name",
              "openreg", "public_key", "questions", "short_name",
              "use_voter_aliases", "uuid", "voters_hash",
              "voting_ends_at", "voting_starts_at"]

    def __init__(self, dct):
        super().__init__(dct)
        # self.checkOpenReg()

    def checkOpenReg(self, verbose=True):
        if self.openreg==True and self.voters_hash!=None:
            helios_log("WARNING: Open Registration election is enabled but "
                       + "voters_hash is not null!", verbose)
            return False
        if self.openreg==False and self.voters_hash==None:
            helios_log("WARNING: Open Registration election is disabled but "
                       + "voters_hash is null!", verbose)
            return False
        return True

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


class EncryptedAnswer(HeliosObject):

    FIELDS = ["choices", "individual_proofs", "overall_proof"]
    JSON_NAME = "answers"

    def __init__(self, dct):
        super().__init__(dct)
