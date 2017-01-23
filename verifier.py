import heliosobjects as helios
import requests
import os
import sys

from tqdm import tqdm

def verifier_log(out, verbose=True):
    if verbose is True:
        print("# " + str(out))

def fetch_json(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
    # FIXME: maybe do not handle here? temporary
    except requests.exceptions.HTTPError as err:
        print (err)
        sys.exit(1)
    result = response.json()
    return result

'''
def download_election_data(self, verbose=False):

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

    # Build a dictionary of voters for quick access
    for voter in voters:
        self.voters[voter["uuid"]] = voter

    ballots = fetch_json(ballots_url)
    for voter in tqdm(voters,disable=not verbose):
        addr = ballots_url + "/" + voter['uuid'] + "/last"
        ballot = fetch_json(addr)
        # save_json_data(ballot, ballots_path + "/" + voter['uuid'] + ".json")
'''

class Verifier(object):
    def __init__(self, uuid, host="https://vote.heliosvoting.org/helios"):
        self.uuid = uuid
        self.host = host
        self.election = None

    def download_election_info(self, verbose=False):
        election_url = self.host + "/elections/" + self.uuid

        verifier_log("Downloading election data...", verbose)
        election_dct = fetch_json(election_url)
        self.election = helios.Election(election_dct)

        return self.election

    def save_election_info(self, path):
        """Serialise 'self.election' and save to file"""
        try:
            self.election.json2file(path)
        except AttributeError as err:
            verifier_log("ERROR: " + err + " 'Election' object not initialised?")

    # Add verbose option for folder creation
    def save_all(self, path):
        """Store all election information including ballots and voters
        in the provided 'path'(must be a folder)"""
        # Temporary check. better just try - except
        if path is None:
            raise TypeError("'path' cannot be None. Please choose a 'path' and try again.")
        path = path.rstrip("/")
        os.makedirs(path, exist_ok=True)
        os.makedirs(path+"/ballots", exist_ok=True)

        election_path = path + "/election_info.json"
        short_ballots_path = path + "/ballots.json"
        ballots_path = path + "/ballots"
        voters_path = path + "/voters.json"

        self.save_election_info(election_path)

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

    verifier = Verifier(args.uuid, args.host)
    verifier.download_election_info(args.verbose)
    verifier.save_all(args.path)
