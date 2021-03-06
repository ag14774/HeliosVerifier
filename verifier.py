"""Helios verifier."""
import json
import multiprocessing
import os
import signal
import sys
import textwrap
import time

import requests
from terminaltables import SingleTable
from tqdm import tqdm

import heliosobjects as helios


def fetch_json(url):
    """Placeholder."""
    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.exceptions.MissingSchema:
        with open(url) as json_file:
            return json.load(json_file)
    except requests.exceptions.HTTPError as err:
        print(err)
        sys.exit(1)
    result = response.json()
    return result


def YELLOW(string):
    return "\033[33m" + str(string) + "\033[0m"


def RED(string):
    return "\033[91m" + str(string) + "\033[0m"


def BLUE(string):
    return "\033[94m" + str(string) + "\033[0m"


class VerificationError(Exception):
    pass


class MsgHandler(object):
    def __init__(self):
        self.wrapper = textwrap.TextWrapper()
        self.wrapper.width = 120
        self.wrapper.initial_indent = "# "
        self.wrapper.subsequent_indent = "| "
        self.error_counter = 0
        self.warning_counter = 0
        self.error_prefix = RED("ERROR: ")
        self.warning_prefix = YELLOW("WARNING: ")
        self.info_prefix = ""  # + BLUE("INFO: ")
        self.msg_history = []
        self.stop_immediately = False

    def __print(self, msg, wrap=True):
        if wrap is True:
            msg = self.wrapper.fill(msg)
        self.msg_history.append(msg)
        tqdm.write(msg)

    def info(self, msg, wrap=True):
        msg = self.info_prefix + msg
        self.__print(msg, wrap)

    def warning(self, msg, wrap=True):
        msg = self.warning_prefix + msg
        self.warning_counter += 1
        self.__print(msg, wrap)

    def error(self, msg, wrap=True):
        msg = self.error_prefix + msg
        self.error_counter += 1
        self.__print(msg, wrap)
        if self.stop_immediately:
            self.stop_immediately = False
            raise VerificationError()

    def process_error(self, wrap=True, exception=None):
        """
        Process HeliosException exceptions.
        """
        try:
            if exception is None:
                raise
            else:
                raise exception
        except helios.ElectionPK.CiphertextCheckError as e:
            msg = self.CiphertextCheckErrorHandler(e)
            self.error(msg, wrap)
        except helios.ElectionPK.ElectionParamsError as e:
            msg = self.ElectionParamsErrorHandler(e)
            self.error(msg, wrap)
        except helios.Vote.BallotNotWellFormed as e:
            msg = self.BallotNotWellFormedHandler(e)
            self.error(msg, wrap)
        except helios.Vote.BallotNonMatchingElectionHash as e:
            msg = self.BallotNonMatchingElectionHashHandler(e)
            self.error(msg, wrap)
        except helios.Vote.BallotNonMatchingElectionUUID as e:
            msg = self.BallotNonMatchingElectionUUIDHandler(e)
            self.error(msg, wrap)
        except helios.Vote.BallotChallengeReused as e:
            msg = self.BallotChallengeReusedHandler(e)
            self.error(msg, wrap)
        except helios.EncryptedAnswer.OverallProofMissing as e:
            msg = self.OverallProofMissingHandler(e)
            self.error(msg, wrap)
        except helios.HeliosDCPProof.DCPWrongNumberOfProofs as e:
            msg = self.DCPWrongNumberOfProofsHandler(e)
            self.error(msg, wrap)
        except helios.HeliosDCPProof.DCPProofFailed as e:
            msg = self.DCPProofFailedHandler(e)
            self.error(msg, wrap)
        except helios.HeliosDCPProof.DCPChallengeCheckFailed as e:
            msg = self.DCPChallengeCheckFailedHandler(e)
            self.error(msg, wrap)
        except helios.Election.VotersHashMissing as e:
            msg = self.VotersHashMissingHandler(e)
            self.warning(msg, wrap)
        except helios.Election.VotersHashCheckError as e:
            msg = self.VotersHashCheckErrorHandler(e)
            self.error(msg, wrap)
        except helios.Trustee.TrusteeKeyVerificationFailed as e:
            msg = self.TrusteeKeyVerificationFailedHandler(e)
            self.error(msg, wrap)
        except helios.Trustee.TrusteeDecryptionProofFailed as e:
            msg = self.TrusteeDecryptionProofFailedHandler(e)
            self.error(msg, wrap)
        except helios.Tally.ResultVerificationFailed as e:
            msg = self.ResultVerificationFailedHandler(e)
            self.error(msg, wrap)

    def CiphertextCheckErrorHandler(self, e):
        msg = ("Ballot {} could not be verified because ciphertext {} of "
               "question {} did not pass the membership check. ").format(
                   BLUE(e.uuid), BLUE(e.choice_num), BLUE(e.question_num))
        msg += "Reason: {}.".format(YELLOW(e.message))
        return msg

    def ElectionParamsErrorHandler(self, e):
        msg = "Invalid election parameters detected: {}".format(
            YELLOW(e.message))
        return msg

    def BallotNotWellFormedHandler(self, e):
        msg = "Some components of ballot {} are missing!".format(BLUE(e.uuid))
        return msg

    def BallotNonMatchingElectionHashHandler(self, e):
        msg = ("The 'election_hash' field of ballot {} and the hash of "
               "the election object do not match!").format(BLUE(e.uuid))
        return msg

    def BallotNonMatchingElectionUUIDHandler(self, e):
        msg = ("The 'election_uuid' field of ballot {} and the 'uuid' of "
               "the election object do not match!").format(BLUE(e.uuid))
        return msg

    def BallotChallengeReusedHandler(self, e):
        msg = ("A proof challenge of ballot {} has already been used "
               "in another ballot!").format(BLUE(e.uuid))
        return msg

    def OverallProofMissingHandler(self, e):
        msg = "Overall proof missing in question {} of ballot {}!".format(
            BLUE(e.question_num), BLUE(e.uuid))
        return msg

    def DCPWrongNumberOfProofsHandler(self, e):
        if e.proof_type is "overall":
            msg = ("The overall proof for question {} in ballot {} "
                   "is not complete!").format(
                       BLUE(e.question_num), BLUE(e.uuid))
        else:
            msg = ("The individual proof for question {} (choice {}) in "
                   "ballot {} is not complete!").format(
                       BLUE(e.question_num), BLUE(e.choice_num), BLUE(e.uuid))
        return msg

    def DCPProofFailedHandler(self, e):
        if e.proof_type is "overall":
            msg = ("Could not verify the overall proof for question {} "
                   "in ballot {}!").format(BLUE(e.question_num), BLUE(e.uuid))
        else:
            msg = ("Could not verify the individual proof for question "
                   "{} (choice {}) in ballot {}!").format(
                       BLUE(e.question_num), BLUE(e.choice_num), BLUE(e.uuid))
        return msg

    def DCPChallengeCheckFailedHandler(self, e):
        if e.proof_type is "overall":
            msg = ("The challenge sum of the overall proof for question "
                   "{} in ballot {} is incorrect!").format(
                       BLUE(e.question_num), BLUE(e.uuid))
        else:
            msg = (
                "The challenge sum of the individual proof for "
                "question {} (choice {}) in ballot {} is incorrect!").format(
                    BLUE(e.question_num), BLUE(e.choice_num), BLUE(e.uuid))
        return msg

    def VotersHashMissingHandler(self, e):
        msg = "Open registration is disabled but voters_hash is null!"
        return msg

    def VotersHashCheckErrorHandler(self, e):
        msg = ("The hash of the voter list does not match the"
               "expected hash in the election object!")
        return msg

    def TrusteeKeyVerificationFailedHandler(self, e):
        msg = "Could not verify key of trustee!"
        return msg

    def TrusteeDecryptionProofFailedHandler(self, e):
        msg = "Could not verify decryption factor!"
        return msg

    def ResultVerificationFailedHandler(self, e):
        msg = "Result not verified!"
        return msg


class Verifier(object):
    def __init__(self,
                 uuid,
                 host="https://vote.heliosvoting.org/helios",
                 cores=1):
        self.uuid = uuid
        self.host = host
        self.election = None
        self.voters = {}
        self.proof_set = set()
        self.voters_uuids_ordered = []
        self.short_ballots = {}
        self.ballots = {}
        self.ballots2 = []
        self.trustees = {}
        self.result = None
        self.msg_handler = MsgHandler()
        self.tally = None
        self.cores = cores

    def parallel_process(self, array, function, n_jobs=8):

        original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
        pool = multiprocessing.Pool(n_jobs)
        signal.signal(signal.SIGINT, original_sigint_handler)

        out = {}
        kwargs = {'total': len(array), 'unit': ' ballots', 'leave': True}

        try:
            for res in tqdm(
                    pool.imap_unordered(function, array, chunksize=16),
                    **kwargs):
                out[res[1].voter_uuid] = res[1]
                if isinstance(res[0], Exception):
                    self.msg_handler.process_error(exception=res[0])
        except KeyboardInterrupt:
            pool.terminate()
            raise
        else:
            pool.close()
        finally:
            pool.join()

        return out

    @staticmethod
    def verify_ballot_parallel(args):
        '''Used by parallel_process'''
        self = args[0]
        ballot = self.ballots[args[1]]
        try:
            ballot.verify(self.election)
            return (True, ballot)
        except helios.HeliosException as e:
            return (e, ballot)

    def verify_election_parameters(self):
        print()
        self.msg_handler.info("Checking election info...")
        self.msg_handler.info(
            "Election name: {}".format(BLUE(self.election.name)))
        self.msg_handler.info(
            "Election fingerprint: {}".format(BLUE(self.election.hash)))

        try:
            self.election.public_key.check_election_params()
        except helios.HeliosException:
            self.msg_handler.process_error()

        try:
            voters = []
            for uuid in self.voters_uuids_ordered:
                voters.append(self.voters[uuid])
            self.election.verify_voters_hash(voters)
        except helios.HeliosException:
            self.msg_handler.process_error()

    def verify_all_ballots(self):
        print()
        self.msg_handler.info("Verifying ballots...")
        if self.cores == 1:
            for k in tqdm(self.ballots2, unit=' ballots'):
                ballot = self.ballots[k]
                try:
                    ballot.verify(self.election)
                except helios.HeliosException as e:
                    self.msg_handler.process_error()
        else:
            selfs = [self] * len(self.ballots2)
            out = self.parallel_process(
                list(zip(selfs, self.ballots2)), self.verify_ballot_parallel,
                self.cores)
            self.ballots.update(out)
        print()

    def detect_ballot_copying(self):
        print()
        self.msg_handler.info("Searching for related ballots...")
        self.tally = helios.Tally(self.election)
        for k in self.ballots2:
            ballot = self.ballots[k]
            try:
                proofs = ballot.get_all_hashes()
                proof_set_length = len(self.proof_set)
                expected_proof_set_length = proof_set_length + len(proofs)
                self.proof_set = self.proof_set.union(proofs)
                if len(self.proof_set) != expected_proof_set_length:
                    raise helios.Vote.BallotChallengeReused(
                        uuid=ballot.voter_uuid)
            except helios.HeliosException as e:
                self.msg_handler.process_error()
            self.tally.add_vote(ballot)
        self.msg_handler.info("Search completed!")

    def verify_trustee(self, trustee):
        print()
        try:
            email = trustee.email
        except AttributeError:
            email = "undefined"

        self.msg_handler.info(
            "Trustee: {}, uuid: {}".format(BLUE(email), BLUE(trustee.uuid)))

        try:
            trustee.verify_secret_key()
            self.msg_handler.info("Trustee's secret key verified!")
        except helios.HeliosException as e:
            self.msg_handler.process_error()

        try:
            trustee.verify_decryption_proofs(self.tally.tallies)
            self.msg_handler.info("Decryption proofs verified!")
        except helios.HeliosException as e:
            self.msg_handler.process_error()

    def verify_all_trustees(self):
        print()
        self.msg_handler.info("Verifying trustees...")
        calculated_pk = 1
        for k, trustee in self.trustees.items():
            self.verify_trustee(trustee)
            calculated_pk = calculated_pk * trustee.public_key.y
            calculated_pk = calculated_pk % self.election.public_key.p
            self.tally.add_dec_factors(trustee)

        print()
        try:
            if calculated_pk != self.election.public_key.y:
                raise helios.ElectionPK.ElectionParamsError(
                    "Election public key is not correctly formed!")
            self.msg_handler.info("Election public key correctly formed!")
        except helios.HeliosException as e:
            self.msg_handler.process_error()

    def verify_tally(self):
        print()
        self.msg_handler.info("Verifying result...")
        computed_result = None
        try:
            self.tally.verify_result(self.result)
            computed_result = self.result
            self.print_results(computed_result)
            print()
            self.msg_handler.info("Results verified!")
        except helios.HeliosException as e:
            computed_result = self.tally.decrypt_from_factors()
            self.print_results(computed_result)
            print()
            self.msg_handler.process_error()

    def print_results(self, computed_result):
        for q_num in range(len(self.election.questions)):
            print()
            question = self.election.questions[q_num]
            self.msg_handler.info("QUESTION: {}".format(question["question"]))
            table_data = [["", "Original result", "Computed result"]]
            for c_num in range(len(question["answers"])):
                answer = question["answers"][c_num]
                orig = self.result[q_num][c_num]
                comp = computed_result[q_num][c_num]
                if orig == comp:
                    row = [str(answer), str(orig), str(comp)]
                else:
                    row = [RED(answer), RED(orig), RED(comp)]
                table_data.append(row)
            table = SingleTable(table_data)
            table.justify_columns = {1: 'center', 2: 'center'}
            self.msg_handler.info(table.table, wrap=False)

    def verify_election(self):
        finished = 1
        try:
            self.verify_election_parameters()
            self.verify_all_ballots()
            self.detect_ballot_copying()
            self.verify_all_trustees()
            self.verify_tally()
        except VerificationError as e:
            pass
        except KeyboardInterrupt as e:
            finished = 0
        except Exception as e:
            finished = 0
            self.msg_handler.error(e.__class__.__name__ + ": {}".format(e))
        finally:
            print()
            if finished == 1:
                self.msg_handler.info(
                    "Verification finished with {} error(s) and {} warning(s)".
                    format(
                        RED(self.msg_handler.error_counter),
                        YELLOW(self.msg_handler.warning_counter)))

                if self.msg_handler.error_counter > 0:
                    self.msg_handler.error("ELECTION COULD NOT BE VERIFIED!")
                else:
                    self.msg_handler.info("ELECTION VERIFIED SUCCESSFULLY!")
            else:
                self.msg_handler.error("VERIFICATION WAS NOT COMPLETED!")
            print()

    def fetch_election_info(self, path=None, force_download=False):
        if path is None or force_download is True:
            election_url = self.host + "/elections/" + self.uuid
        else:
            election_url = path

        self.msg_handler.info("Downloading election data...")
        election_dct = fetch_json(election_url)
        self.election = helios.Election(election_dct)

        return self.election

    def fetch_voters_info(self, path=None, force_download=False):
        if path is None or force_download is True:
            voters_url = self.host + "/elections/" + self.uuid + "/voters"
        else:
            voters_url = path

        self.msg_handler.info("Downloading voters...")

        temp_voters = []
        after = ""
        while True:
            # If reading from file
            if voters_url == path:
                temp = fetch_json(voters_url)
                temp_voters += temp
                break
            else:
                temp = fetch_json(voters_url + "?after=" + after +
                                  "&limit=200")
            if not temp:
                break
            temp_voters += temp
            after = temp_voters[-1]['uuid']

        total_voters = len(temp_voters)
        self.msg_handler.info("{} voters found.".format(BLUE(total_voters)))

        # Build a dictionary of voters for quick access
        for voter in temp_voters:
            voter_uuid = voter["uuid"]
            self.voters_uuids_ordered.append(voter_uuid)
            self.voters[voter_uuid] = helios.CreateVoter(voter)

    def fetch_ballots_info(self, path=None, force_download=False):
        if path is None or force_download is True:
            ballots_url = self.host + "/elections/" + self.uuid + "/ballots"
            url_end = "/last"
        else:
            ballots_url = path
            url_end = ".json"

        self.msg_handler.info("Downloading ballots...")
        for uuid, voter in tqdm(self.voters.items(), unit=' voters'):
            addr = ballots_url + "/" + uuid + url_end
            ballot = fetch_json(addr)
            self.ballots[voter.uuid] = helios.Ballot(ballot)
            if self.ballots[voter.uuid].vote:
                self.ballots2.append(voter.uuid)

    def fetch_short_ballots_info(self, path=None, force_download=False):
        if path is None or force_download is True:
            ballots_url = self.host + "/elections/" + self.uuid + "/ballots"
        else:
            ballots_url = path

        short_ballots = fetch_json(ballots_url)

        for short_ballot in short_ballots:
            self.short_ballots[short_ballot["voter_uuid"]] = helios.Ballot(
                short_ballot)

    def fetch_trustees_info(self, path=None, force_download=False):
        if path is None or force_download is True:
            trustees_url = self.host + "/elections/" + self.uuid + "/trustees"
        else:
            trustees_url = path

        self.msg_handler.info("Downloading trustees...")
        trustees_json = fetch_json(trustees_url)

        for trustee in trustees_json:
            self.trustees[trustee["uuid"]] = helios.Trustee(trustee)

    def fetch_result(self, path=None, force_download=False):
        if path is None or force_download is True:
            result_url = self.host + "/elections/" + self.uuid + "/result"
        else:
            result_url = path

        self.result = fetch_json(result_url)

    def fetch_all_election_data(self, path=None, force_download=False):
        election_path = None
        voters_path = None
        short_ballots_path = None
        ballots_path = None
        trustees_path = None
        result_path = None

        if path is not None and force_download is False:
            path = path.rstrip("/")
            election_path = path + "/election_info.json"
            voters_path = path + "/voters.json"
            short_ballots_path = path + "/ballots.json"
            ballots_path = path + "/ballots"
            trustees_path = path + "/trustees.json"
            result_path = path + "/result.json"
            if not os.path.isfile(election_path):
                force_download = True

        self.fetch_election_info(election_path, force_download)
        self.fetch_trustees_info(trustees_path, force_download)
        self.fetch_voters_info(voters_path, force_download)
        self.fetch_short_ballots_info(short_ballots_path, force_download)
        self.fetch_ballots_info(ballots_path, force_download)
        self.fetch_result(result_path, force_download)

        return force_download

    def save_election_info(self, path):
        """Serialise 'self.election' and save to file"""
        try:
            self.election.json2file(path)
        except AttributeError as err:
            raise Exception(err + ". 'Election' object not initialised?")

    def save_voters_info(self, path):
        """Serialise 'self.voters' and save to file"""
        voters = []
        for voter_uuid in self.voters_uuids_ordered:
            voter = self.voters[voter_uuid]
            voter_json = voter.toJSONDict()
            voters.append(voter_json)
        helios.HeliosObject.json2file(voters, path)

    def save_short_ballots(self, path):
        """Serialse 'self.short_ballots' and 'self.ballots' and save to file"""
        short_ballots = []
        for k, v in self.short_ballots.items():
            short_ballots.append(v.toJSONDict())
        helios.HeliosObject.json2file(short_ballots, path)

    def save_single_ballot(self, voter_uuid, path):
        """Save a single ballot to file"""
        ballot = self.ballots[voter_uuid]
        ballot.json2file(path)

    def save_all_ballots(self, path):
        """Save all ballots. 'path' is a directory"""
        for uuid, voter in self.voters.items():
            ballot_path = path + "/" + uuid + ".json"
            self.save_single_ballot(uuid, ballot_path)

    def save_trustees_info(self, path):
        """Serialse 'self.trustees' and save to file"""
        trustees = []
        for k, trustee in self.trustees.items():
            trustees.append(trustee.toJSONDict())
        helios.HeliosObject.json2file(trustees, path)

    def save_result(self, path):
        helios.HeliosObject.json2file(self.result, path)

    def save_all(self, path):
        """Store all election information including ballots and voters
        in the provided 'path'(must be a folder)"""
        # Temporary check. better just try - except
        if path is None:
            raise TypeError(
                "'path' cannot be None. Please choose a 'path' and try again.")
        path = path.rstrip("/")

        election_path = path + "/election_info.json"
        voters_path = path + "/voters.json"
        short_ballots_path = path + "/ballots.json"
        ballots_path = path + "/ballots"
        trustees_path = path + "/trustees.json"
        result_path = path + "/result.json"

        os.makedirs(path, exist_ok=True)
        os.makedirs(ballots_path, exist_ok=True)

        self.save_election_info(election_path)
        self.save_voters_info(voters_path)
        self.save_short_ballots(short_ballots_path)
        self.save_all_ballots(ballots_path)
        self.save_trustees_info(trustees_path)
        self.save_result(result_path)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--host',
        type=str,
        default="https://vote.heliosvoting.org/helios",
        action='store',
        help='Helios server')
    parser.add_argument(
        '--uuid', type=str, action='store', help='election identifier')
    parser.add_argument(
        '--force-download',
        action='store_true',
        help='force download data from the internet')
    parser.add_argument(
        '--path',
        type=str,
        default=None,
        action='store',
        help='location to store files')
    parser.add_argument(
        '--cores',
        type=int,
        default=multiprocessing.cpu_count(),
        action='store',
        help='number of cores to use')
    args = parser.parse_args()

    verifier = Verifier(args.uuid, args.host, args.cores)
    from_host = verifier.fetch_all_election_data(args.path,
                                                 args.force_download)
    if from_host:
        verifier.save_all(args.path)

    start_time = time.time()
    verifier.verify_election()
    elapsed_time = time.time() - start_time
    print()
    print("Time elapsed {}".format(elapsed_time))
