import heliosobjects as helios
from heliosobjects import helios_log

import requests
import os
import sys
from tqdm import tqdm



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
    

class Verifier(object):
    def __init__(self, uuid, host="https://vote.heliosvoting.org/helios"):
        self.uuid = uuid
        self.host = host
        self.election = None
        self.voters = {}
        self._voters_uuids_ordered = [] # Perhaps I should remove this?
        self.short_ballots = {}
        self.ballots = {}


    def download_election_info(self, verbose=False):
        election_url = self.host + "/elections/" + self.uuid

        helios_log("Downloading election data...", verbose)
        election_dct = fetch_json(election_url)
        self.election = helios.Election(election_dct)

        return self.election

    def download_voters_info(self, verbose=False):
        voters_url = self.host + "/elections/" + self.uuid + "/voters"

        helios_log("Downloading voters info...", verbose)

        temp_voters = []
        after = ""
        while True:
            temp = fetch_json(voters_url+"?after="+after+"&limit=200")
            if not temp:
                break
            temp_voters += temp
            after = temp_voters[-1]['uuid']

        total_voters = len(temp_voters)
        helios_log("{} voters found.".format(total_voters), verbose)

        # Build a dictionary of voters for quick access
        for voter in temp_voters:
            voter_uuid = voter["uuid"]
            self._voters_uuids_ordered.append(voter_uuid)
            self.voters[voter_uuid] = helios.CreateVoter(voter)
            # FIXME: Maybe compare use_voter_aliases with voter type here?

    def download_ballots_info(self, verbose=False):
        ballots_url = self.host + "/elections/" + self.uuid + "/ballots"
        helios_log("Downloading ballots...")
        short_ballots = fetch_json(ballots_url)
        for uuid,voter in tqdm(self.voters.items(),disable=not verbose):
            addr = ballots_url + "/" + uuid + "/last"
            ballot = fetch_json(addr)
            self.ballots[voter.uuid] = helios.Ballot(ballot)

        for short_ballot in short_ballots:
            self.short_ballots[short_ballot["voter_uuid"]] = helios.Ballot(short_ballot)

    def save_election_info(self, path):
        """Serialise 'self.election' and save to file"""
        try:
            self.election.json2file(path)
        except AttributeError as err:
            helios_log("ERROR: " + err + " 'Election' object not initialised?")

    def save_voters_info(self, path):
        """Serialise 'self.voters' and save to file"""
        voters = []
        for voter_uuid in self._voters_uuids_ordered:
            voter = self.voters[voter_uuid]
            voter_json = voter.toJSONDict()
            voters.append(voter_json)
        helios.HeliosObject.json2file(voters, path)

    def save_short_ballots(self, path):
        """Serialse 'self.short_ballots' and 'self.ballots' and save to file"""
        short_ballots = []
        for k,v in self.short_ballots.items():
            short_ballots.append(v.toJSONDict())
        helios.HeliosObject.json2file(short_ballots, path)

    def save_single_ballot(self, voter_uuid, path):
        """Save a single ballot to file"""
        ballot = self.ballots[voter_uuid]
        ballot.json2file(path)

    def save_all_ballots(self, path):
        """Save all ballots. 'path' is a directory"""
        for uuid,voter in self.voters.items():
            ballot_path = path + "/" + uuid + ".json"
            self.save_single_ballot(uuid, ballot_path)


    # Add verbose option for folder creation
    def save_all(self, path):
        """Store all election information including ballots and voters
        in the provided 'path'(must be a folder)"""
        # Temporary check. better just try - except
        if path is None:
            raise TypeError("'path' cannot be None. Please choose a 'path' and try again.")
        path = path.rstrip("/")

        election_path = path + "/election_info.json"
        voters_path = path + "/voters.json"
        short_ballots_path = path + "/ballots.json"
        ballots_path = path + "/ballots"

        os.makedirs(path, exist_ok=True)
        os.makedirs(ballots_path, exist_ok=True)

        self.save_election_info(election_path)
        self.save_voters_info(voters_path)
        self.save_short_ballots(short_ballots_path)
        self.save_all_ballots(ballots_path)

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
    verifier.download_voters_info(args.verbose)
    verifier.download_ballots_info(args.verbose)
    print(verifier.election.public_key.p,type(verifier.election.public_key.p))
    verifier.save_all(args.path)
