
import json

class HeliosObject(object):

    FIELDS = []

    # Initialise object using a dictionary
    def __init__(self, dct):
        """Initialise object using a dictionary that contains
        all required attribute values"""

        for field in self.FIELDS:
            try:
                setattr(self, field, dct[field])
            except KeyError:
                print("# WARNING: " + field + " not found. Setting to None!")
                self.__dict__[field] = None

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
                    json.dump(self, out, cls=self.HeliosJSONEncoder)
                else:
                    json.dump(self, out)
        except Exception as err:
            print("# ERROR: {}".format(err))

    def toJSONString(self):
        out = json.dumps(self, cls=self.HeliosJSONEncoder)

    def toJSONDict(self):
        out = json.loads(self.toJSONString())
        return out

    class HeliosJSONEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, HeliosObject):
                out = {}
                for field in obj.FIELDS:
                    out[field] = getattr(obj, field)
                return out
            # Let the base class default method raise the TypeError
            return json.JSONEncoder.default(self, obj)


class Election(HeliosObject):

    FIELDS = ["cast_url", "description", "frozen_at", "name",
              "openreg", "public_key", "questions", "short_name",
              "use_voter_aliases", "uuid", "voters_hash",
              "voting_ends_at", "voting_starts_at"]

    def __init__(self, dct):
        super().__init__(dct)
