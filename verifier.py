import heliosobjects as helios
from heliosobjects import helios_log

import requests
import os
import sys
import json
from tqdm import tqdm

# QUESTION: What to store in the hashtable?
# QUESTION: values reduced modulo p(large one) instead of q(small one)
#           Is this caught by the hash check and how?

def fetch_json(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.exceptions.MissingSchema:
        with open(url) as json_file:
            return json.load(json_file)
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
        self.proof_set = set()
        self._voters_uuids_ordered = [] # Perhaps I should remove this?
        self.short_ballots = {}
        self.ballots = {}
        self.trustees = {}

    def verify_ballot_uuid(self, uuid):
        ballot = self.ballots[uuid]
        return self.verify_ballot(ballot)

    def verify_ballot(self, ballot):
        try:
            valid = ballot.vote.verify(self.election) #raise exception here if vote is None
            proofs,expected_proofs = ballot.vote.get_all_hashes()
            if len(proofs) != expected_proofs:
                return False
            proof_set_length = len(self.proof_set)
            expected_proof_set_length = proof_set_length + expected_proofs
            self.proof_set = self.proof_set.union(proofs)
            if len(self.proof_set) != expected_proof_set_length:
                return False
            return valid
        except AttributeError as e:
            if ballot.vote is None:
                return True
            else:
                print(str(e))
                sys.exit(1)

    def verify_trustee(self, trustee, verbose=True):
        try:
            email = trustee.email
        except AttributeError:
            email = "undefined"
        helios_log("Trustee: \033[94m" + email + "\033[0m, uuid: \033[94m"
                   + trustee.uuid + "\033[0m", verbose)
        if not trustee.verify_secret_key():
            helios_log("\033[91mERROR:\033[0m Could not verify knowledge of secret key!",verbose)
            return False

        helios_log("Trustee verified!", verbose)
        return True

    def verify_election(self):
        print()
        helios_log("Checking election info...")
        helios_log("Election name: \033[94m" + self.election.name + "\033[0m")
        helios_log("Election fingerprint: \033[94m" + self.election.hash + "\033[0m")
        if not self.election.verify_voters_hash(self.voters.values()):
            helios_log("WARNING: Could not check voter list hash!")

        print()
        helios_log("Verifying ballots...")
        for k,ballot in tqdm(self.ballots.items(), unit=' ballots'):
            valid = self.verify_ballot(ballot)
            if not valid:
                print()
                helios_log("\033[91mERROR:\033[0m Ballot \033[94m{}\033[0m could not be verified. Terminating!".format(k))
                sys.exit(1)

        print()
        helios_log("Verifying trustees...")
        for k,trustee in self.trustees.items():
            print()
            valid = self.verify_trustee(trustee)
            if not valid:
                print()
                helios_log("\033[91mERROR:\033[0m Trustee \033[94m{}\033[0m is dishonest!".format(k))
                sys.exit(1)


    def fetch_election_info(self, verbose=False, path=None, force_download=False):
        if path is None or force_download is True:
            election_url = self.host + "/elections/" + self.uuid
        else:
            election_url = path

        helios_log("Downloading election data...", verbose)
        election_dct = fetch_json(election_url)
        self.election = helios.Election(election_dct)

        return self.election

    def fetch_voters_info(self, verbose=False, path=None, force_download=False):
        if path is None or force_download is True:
            voters_url = self.host + "/elections/" + self.uuid + "/voters"
        else:
            voters_url = path

        helios_log("Downloading voters...", verbose)

        temp_voters = []
        after = ""
        while True:
            # If reading from file
            if voters_url==path:
                temp = fetch_json(voters_url)
                temp_voters += temp
                break
            else:
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

    def fetch_ballots_info(self, verbose=False, path=None, force_download=False):
        if path is None or force_download is True:
            ballots_url = self.host + "/elections/" + self.uuid + "/ballots"
            url_end = "/last"
        else:
            ballots_url = path
            url_end = ".json"

        helios_log("Downloading ballots...", verbose)
        for uuid,voter in tqdm(self.voters.items(),disable=not verbose,unit=' voters'):
            addr = ballots_url + "/" + uuid + url_end
            ballot = fetch_json(addr)
            self.ballots[voter.uuid] = helios.Ballot(ballot)


    def fetch_short_ballots_info(self, verbose=False, path=None, force_download=False):
        if path is None or force_download is True:
            ballots_url = self.host + "/elections/" + self.uuid + "/ballots"
        else:
            ballots_url = path

        #helios_log("Downloading ballots...")
        short_ballots = fetch_json(ballots_url)

        for short_ballot in short_ballots:
            self.short_ballots[short_ballot["voter_uuid"]] = helios.Ballot(short_ballot)

    def fetch_trustees_info(self, verbose=False, path=None, force_download=False):
        if path is None or force_download is True:
            trustees_url = self.host + "/elections/" + self.uuid + "/trustees"
        else:
            trustees_url = path

        helios_log("Downloading trustees...", verbose)
        trustees_json = fetch_json(trustees_url)

        for trustee in trustees_json:
            self.trustees[trustee["uuid"]] = helios.Trustee(trustee)

    def fetch_all_election_data(self, verbose=False, path=None, force_download=False):
        election_path = None
        voters_path = None
        short_ballots_path = None
        ballots_path = None
        trustees_path = None

        if path is not None and force_download is False:
            path = path.rstrip("/")
            election_path = path + "/election_info.json"
            voters_path = path + "/voters.json"
            short_ballots_path = path + "/ballots.json"
            ballots_path = path + "/ballots"
            trustees_path = path + "/trustees.json"
            if not os.path.isfile(election_path):
                force_download = True

        self.fetch_election_info(verbose, election_path, force_download)
        self.fetch_voters_info(verbose, voters_path, force_download)
        self.fetch_short_ballots_info(verbose, short_ballots_path, force_download)
        self.fetch_ballots_info(verbose, ballots_path, force_download)
        self.fetch_trustees_info(verbose, trustees_path, force_download)

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

    def save_trustees_info(self, path):
        """Serialse 'self.trustees' and save to file"""
        trustees = []
        for k,trustee in self.trustees.items():
            trustees.append(trustee.toJSONDict())
        helios.HeliosObject.json2file(trustees, path)


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
        trustees_path = path + "/trustees.json"

        os.makedirs(path, exist_ok=True)
        os.makedirs(ballots_path, exist_ok=True)

        self.save_election_info(election_path)
        self.save_voters_info(voters_path)
        self.save_short_ballots(short_ballots_path)
        self.save_all_ballots(ballots_path)
        self.save_trustees_info(trustees_path)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', type=str,
                        default="https://vote.heliosvoting.org/helios",
                        action='store', help='Helios server')
    parser.add_argument('--uuid', type=str, action='store', help='election identifier')
    parser.add_argument('--verbose', action='store_true', help='show progress on screen')
    parser.add_argument('--force-download', action='store_true', help='force download data from the internet')
    parser.add_argument('--path', type=str, default=None, action='store', help='location to store files')
    args = parser.parse_args()

    verifier = Verifier(args.uuid, args.host)
    verifier.fetch_all_election_data(args.verbose, args.path, args.force_download)
    verifier.save_all(args.path)
    verifier.verify_election()
