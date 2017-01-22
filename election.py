
import os
import requests
import json
from tqdm import tqdm
import sys

def save_json_data(data, path, encoder=None):
    with open(path, "w") as out:
        if encoder is None:
            json.dump(data, out)
        else:
            json.dump(data, out, cls=encoder)

def fetch_json(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print (err)
        sys.exit(1)
    result = response.json()
    return result

class ElectionEncoder(json.JSONEncoder):
    def default(self, obj):
        valid_args = ["cast_url", "description", "frozen_at", "name",
                      "openreg", "public_key", "questions", "short_name",
                      "use_voter_aliases", "uuid", "voters_hash",
                      "voting_ends_at", "voting_starts_at"]
        if isinstance(obj, Election):
            out = {}
            for arg in valid_args:
                out[arg] = obj.__dict__[arg]
            return out
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)

class Election:

    def __init__(self, uuid, host="https://vote.heliosvoting.org/helios"):
        if uuid is None:
            raise TypeError("Argument \'uuid\' cannot be None")

        self.cast_url = None
        self.description = None
        self.frozen_at = None
        self.name = None
        self.openreg = None
        self.public_key = {"g": None, "p": None, "q": None, "y": None}
        self.questions = {}
        self.short_name = None
        self.use_voter_aliases = None
        self.uuid = str(uuid)
        self.voters_hash = None
        self.voting_ends_at = None
        self.voting_starts_at = None

        self.host = host.rstrip("/")
        self.voters = {}
        self.short_ballots = {}

    # Need to supply a dictionary that contains values
    # for all keys shown in 'valid_args'
    def load_from_dict(self, args):
        valid_args = ["cast_url", "description", "frozen_at", "name",
                      "openreg", "public_key", "questions", "short_name",
                      "use_voter_aliases", "uuid", "voters_hash",
                      "voting_ends_at", "voting_starts_at"]
        for arg in valid_args:
            try:
                # Make sure that the attribute exists by attempting to access
                test = self.__dict__[arg]
                self.__dict__[arg] = args[arg]
            except KeyError:
                print("# WARNING: " + arg + " not found. Setting to None!")
                self.__dict__[arg] = None
            except AttributeError:
                print("# WARNING: '" + self.__class__.__name__  + "' object "
                      + "has not attribute '" + arg + "'. Ignoring!" )

    def store_to_file(self, path):
        if path is None:
            raise TypeError("'path' cannot be None. Please choose a 'path' and try again.")
        path = path.rstrip("/")
        os.makedirs(path, exist_ok=True)
        os.makedirs(path+"/ballots", exist_ok=True)

        election_path = path + "/" + self.uuid + ".json"
        short_ballots_path = path + "/ballots.json"
        ballots_path = path + "/ballots"
        voters_path = path + "/voters.json"

        save_json_data(self, election_path, ElectionEncoder)

    def download_election_data(self, verbose=False):
        election_url = self.host + "/elections/" + self.uuid
        voters_url = self.host + "/elections/" + self.uuid + "/voters"
        ballots_url = self.host + "/elections/" + self.uuid + "/ballots"

        print("# Downloading election data...")
        elections = fetch_json(election_url)
        self.load_from_dict(elections)

        print("# Downloading voters info...")
        voters = []
        after = ""
        while True:
            temp = fetch_json(voters_url+"?after="+after+"&limit=200")
            if not temp:
                break
            voters += temp
            after = voters[-1]['uuid']

        total_voters = len(voters)
        if verbose is True:
            print("# {} voters found.".format(total_voters))
            print("# Downloading ballots...")
        ballots = fetch_json(ballots_url)
        for voter in tqdm(voters,disable=not verbose):
            addr = ballots_url + "/" + voter['uuid'] + "/last"
            ballot = fetch_json(addr)
            # save_json_data(ballot, ballots_path + "/" + voter['uuid'] + ".json")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', type=str,
                        default="https://vote.heliosvoting.org/helios",
                        action='store', help='Helios server')
    parser.add_argument('--uuid', type=str, action='store', help='election identifier')
    parser.add_argument('--verbose', action='store_true', help='show progress on screen')
    parser.add_argument('--path', type=str, default=None, action='store', help='location to store files')
    args = parser.parse_args()

    elec = Election(args.uuid)
    elec.download_election_data(args.verbose)
    elec.store_to_file(args.path)
