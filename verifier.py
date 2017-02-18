"""Helios verifier."""
import json
import os
import sys
import textwrap

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


class Colours:
    @staticmethod
    def YELLOW(string):
        return "\033[33m" + str(string) + "\033[0m"

    @staticmethod
    def RED(string):
        return "\033[91m" + str(string) + "\033[0m"

    @staticmethod
    def BLUE(string):
        return "\033[94m" + str(string) + "\033[0m"


class VerifierException(Exception):
    def __init__(self, code=0):
        super().__init__()
        self.code = code


class MsgHandler(object):
    def __init__(self, verbose=False):
        self.wrapper = textwrap.TextWrapper()
        self.wrapper.width = 120
        self.wrapper.initial_indent = "# "
        self.wrapper.subsequent_indent = "| "
        self.error_counter = 0
        self.warning_counter = 0
        self.info_counter = 0
        self.error_thresh = 10
        self.error_prefix = Colours.RED("ERROR: ")
        self.warning_prefix = Colours.YELLOW("WARNING: ")
        self.info_prefix = ""  # + Colours.BLUE("INFO: ")
        self.read_msgs = []
        self.unread_msgs = []
        self.shutting_down = False
        if not verbose:
            self.error_thresh = 1
            self.CiphertextCheckErrorHandler = self.SimpleErrorHandler
            self.ElectionParamsErrorHandler = self.SimpleErrorHandler
            self.BallotNotWellFormedHandler = self.SimpleErrorHandler
            self.BallotNonMatchingElectionHashHandler = self.SimpleErrorHandler
            self.BallotNonMatchingElectionUUIDHandler = self.SimpleErrorHandler
            self.BallotChallengeReusedHandler = self.SimpleErrorHandler
            self.OverallProofMissingHandler = self.SimpleErrorHandler
            self.DCPWrongNumberOfProofsHandler = self.SimpleErrorHandler
            self.DCPProofFailedHandler = self.SimpleErrorHandler
            self.DCPChallengeCheckFailedHandler = self.SimpleErrorHandler
            self.VotersHashCheckErrorHandler = self.SimpleErrorHandler
            self.TrusteeKeyVerificationFailedHandler = self.SimpleErrorHandler
            self.TrusteeDecryptionProofFailedHandler = self.SimpleErrorHandler
            self.ResultVerificationFailedHandler = self.SimpleErrorHandler

    def print_unread_messages(self):
        for err in self.unread_msgs:
            print(err)
            self.read_msgs.append(err)
        self.unread_msgs = []

    def shutdown(self):
        print()
        self.print_unread_messages()
        print()
        self.shutting_down = True

    def print_msg(self,
                  msg,
                  msg_type="INFO",
                  flush=True,
                  store=True,
                  wrap=True):
        try:
            raise helios.HeliosException(msg, msg_type)
        except helios.HeliosException as e:
            self.process_error(flush, wrap)

    def process_error(self, flush=True, wrap=True):
        """
        Process HeliosException exceptions.

        If store=True then the message will be
        stored internally. To print message use
        print_unread_messages.
        If flush=True then all unread messages
        are printed.
        """
        try:
            msg = ""
            terminate = 0
            raise
        except helios.ElectionPK.CiphertextCheckError as e:
            msg += self.CiphertextCheckErrorHandler(e)
        except helios.ElectionPK.ElectionParamsError as e:
            msg += self.ElectionParamsErrorHandler(e)
        except helios.Vote.BallotNotWellFormed as e:
            msg += self.BallotNotWellFormedHandler(e)
            terminate = 1
        except helios.Vote.BallotNonMatchingElectionHash as e:
            msg += self.BallotNonMatchingElectionHashHandler(e)
        except helios.Vote.BallotNonMatchingElectionUUID as e:
            msg += self.BallotNonMatchingElectionUUIDHandler(e)
        except helios.Vote.BallotChallengeReused as e:
            msg += self.BallotChallengeReusedHandler(e)
        except helios.EncryptedAnswer.OverallProofMissing as e:
            msg += self.OverallProofMissingHandler(e)
        except helios.HeliosDCPProof.DCPWrongNumberOfProofs as e:
            msg += self.DCPWrongNumberOfProofsHandler(e)
        except helios.HeliosDCPProof.DCPProofFailed as e:
            msg += self.DCPProofFailedHandler(e)
        except helios.HeliosDCPProof.DCPChallengeCheckFailed as e:
            msg += self.DCPChallengeCheckFailedHandler(e)
        except helios.Election.VotersHashMissing as e:
            msg += self.VotersHashMissingHandler(e)
        except helios.Election.VotersHashCheckError as e:
            msg += self.VotersHashCheckErrorHandler(e)
        except helios.Trustee.TrusteeKeyVerificationFailed as e:
            msg += self.TrusteeKeyVerificationFailedHandler(e)
        except helios.Trustee.TrusteeDecryptionProofFailed as e:
            msg += self.TrusteeDecryptionProofFailedHandler(e)
        except helios.Tally.ResultVerificationFailed as e:
            msg += self.ResultVerificationFailedHandler(e)
        except helios.HeliosException as e:
            msg += self.HeliosExceptionHandler(e)

        if wrap is True:
            msg = self.wrapper.fill(msg)

        self.unread_msgs.append(msg)

        if not self.shutting_down and (
                self.error_counter >= self.error_thresh or terminate > 0):
            raise VerifierException(terminate)

        if flush is True:
            self.print_unread_messages()

    def SimpleErrorHandler(self, e):
        msg = self.error_prefix
        msg += e.__class__.__name__
        msg += ": Could not verify election!"
        self.error_counter = self.error_counter + 1
        return msg

    def CiphertextCheckErrorHandler(self, e):
        msg = self.error_prefix
        msg += ("Ballot {} could not be verified because ciphertext {} of "
                "question {} did not pass the membership check. ").format(
                    Colours.BLUE(e.uuid),
                    Colours.BLUE(e.choice_num), Colours.BLUE(e.question_num))
        msg += "Reason: {}".format(Colours.YELLOW(e.message))
        self.error_counter = self.error_counter + 1
        return msg

    def ElectionParamsErrorHandler(self, e):
        msg = self.error_prefix
        msg += "Invalid election parameters detected: {}".format(
            Colours.YELLOW(e.message))
        self.error_counter = self.error_counter + 1
        return msg

    def BallotNotWellFormedHandler(self, e):
        msg = self.error_prefix
        msg += "Some components of ballot {} are missing!".format(
            Colours.BLUE(e.uuid))
        self.error_counter = self.error_counter + 1
        return msg

    def BallotNonMatchingElectionHashHandler(self, e):
        msg = self.error_prefix
        msg += (
            "The 'election_hash' field of ballot {} and the hash of "
            "the election object do not match!").format(Colours.BLUE(e.uuid))
        self.error_counter = self.error_counter + 1
        return msg

    def BallotNonMatchingElectionUUIDHandler(self, e):
        msg = self.error_prefix
        msg += (
            "The 'election_uuid' field of ballot {} and the 'uuid' of "
            "the election object do not match!").format(Colours.BLUE(e.uuid))
        self.error_counter = self.error_counter + 1
        return msg

    def BallotChallengeReusedHandler(self, e):
        msg = self.error_prefix
        msg += ("A proof challenge of ballot {} has already been used "
                "in another ballot!").format(Colours.BLUE(e.uuid))
        self.error_counter = self.error_counter + 1
        return msg

    def OverallProofMissingHandler(self, e):
        msg = self.error_prefix
        msg += "Overall proof missing in question {} of ballot {}!".format(
            Colours.BLUE(e.question_num), Colours.BLUE(e.uuid))
        self.error_counter = self.error_counter + 1
        return msg

    def DCPWrongNumberOfProofsHandler(self, e):
        msg = self.error_prefix
        if e.proof_type is "overall":
            msg += ("The overall proof for question {} in ballot {} "
                    "is not complete!").format(
                        Colours.BLUE(e.question_num), Colours.BLUE(e.uuid))
        else:
            msg += ("The individual proof for question {} (choice {}) in "
                    "ballot {} is not complete!").format(
                        Colours.BLUE(e.question_num),
                        Colours.BLUE(e.choice_num), Colours.BLUE(e.uuid))
        self.error_counter = self.error_counter + 1
        return msg

    def DCPProofFailedHandler(self, e):
        msg = self.error_prefix
        if e.proof_type is "overall":
            msg += ("Could not verify the overall proof for question {} "
                    "in ballot {}!").format(
                        Colours.BLUE(e.question_num), Colours.BLUE(e.uuid))
        else:
            msg += ("Could not verify the individual proof for question "
                    "{} (choice {}) in ballot {}!").format(
                        Colours.BLUE(e.question_num),
                        Colours.BLUE(e.choice_num), Colours.BLUE(e.uuid))
        self.error_counter = self.error_counter + 1
        return msg

    def DCPChallengeCheckFailedHandler(self, e):
        msg = self.error_prefix
        if e.proof_type is "overall":
            msg += ("The challenge sum of the overall proof for question "
                    "{} in ballot {} is incorrect!").format(
                        Colours.BLUE(e.question_num), Colours.BLUE(e.uuid))
        else:
            msg += (
                "The challenge sum of the individual proof for "
                "question {} (choice {}) in ballot {} is incorrect!").format(
                    Colours.BLUE(e.question_num),
                    Colours.BLUE(e.choice_num), Colours.BLUE(e.uuid))
        self.error_counter = self.error_counter + 1
        return msg

    def VotersHashMissingHandler(self, e):
        msg = self.warning_prefix
        msg += "Open registration is disabled but voters_hash is null!"
        self.warning_counter = self.warning_counter + 1
        return msg

    def VotersHashCheckErrorHandler(self, e):
        msg = self.error_prefix
        msg += ("The hash of the voter list does not match the"
                "expected hash in the election object!")
        self.error_counter = self.error_counter + 1
        return msg

    def TrusteeKeyVerificationFailedHandler(self, e):
        msg = self.error_prefix
        msg += "Could not verify key of trustee!"
        self.error_counter = self.error_counter + 1
        return msg

    def TrusteeDecryptionProofFailedHandler(self, e):
        msg = self.error_prefix
        msg += "Could not verify decryption factor!"
        self.error_counter = self.error_counter + 1
        return msg

    def ResultVerificationFailedHandler(self, e):
        msg = self.error_prefix
        msg += "Result not verified!"
        self.error_counter = self.error_counter + 1
        return msg

    def HeliosExceptionHandler(self, e):
        if e.msg_type == "INFO":
            msg = self.info_prefix
            self.info_counter += 1
        elif e.msg_type == "WARNING":
            msg = self.warning_prefix
            self.warning_counter += 1
        elif e.msg_type == "ERROR":
            msg = self.error_prefix
            self.error_counter += 1
        msg += e.message
        return msg


class Verifier(object):
    def __init__(self,
                 uuid,
                 host="https://vote.heliosvoting.org/helios",
                 verbose=False):
        self.uuid = uuid
        self.host = host
        self.election = None
        self.voters = {}
        self.proof_set = set()
        self._voters_uuids_ordered = []  # Perhaps I should remove this?
        self.short_ballots = {}
        self.ballots = {}
        self.trustees = {}
        self.result = None
        self.msg_handler = MsgHandler(verbose)
        self.tally = None

    def verify_ballot_uuid(self, uuid):
        ballot = self.ballots[uuid]
        return self.verify_ballot(ballot)

    def verify_ballot(self, ballot):
        ballot.verify(self.election)
        proofs = ballot.get_all_hashes()
        proof_set_length = len(self.proof_set)
        expected_proof_set_length = proof_set_length + len(proofs)
        self.proof_set = self.proof_set.union(proofs)
        if len(self.proof_set) != expected_proof_set_length:
            raise helios.Vote.BallotChallengeReused(uuid=ballot.voter_uuid)
        return True

    def verify_election_parameters(self):
        print()
        self.msg_handler.print_msg("Checking election info...")
        self.msg_handler.print_msg("Election name: " + Colours.BLUE(
            self.election.name))
        self.msg_handler.print_msg("Election fingerprint: " + Colours.BLUE(
            self.election.hash))

        try:
            self.election.public_key.check_election_params()
        except helios.HeliosException:
            self.msg_handler.process_error()

        try:
            self.election.verify_voters_hash(self.voters.values())
        except helios.HeliosException:
            self.msg_handler.process_error()

    def verify_all_ballots(self):
        self.tally = helios.Tally(self.election)
        print()
        self.msg_handler.print_msg("Verifying ballots...")
        for k, ballot in tqdm(
                self.ballots.items(), ncols=100, unit=' ballots'):
            if ballot.vote is not None:
                try:
                    self.verify_ballot(ballot)
                except helios.HeliosException as e:
                    # Do not print message immediately
                    # Attempt to continue and print the
                    # errors at the end
                    self.msg_handler.process_error(flush=False)
                self.tally.add_vote(ballot)

        print()
        self.msg_handler.print_unread_messages()

    def verify_trustee(self, trustee):
        print()
        try:
            email = trustee.email
        except AttributeError:
            email = "undefined"

        self.msg_handler.print_msg("Trustee: {}, uuid: {}".format(
            Colours.BLUE(email), Colours.BLUE(trustee.uuid)))

        try:
            trustee.verify_secret_key()
            self.msg_handler.print_msg("Trustee's secret key verified!")
        except helios.HeliosException as e:
            self.msg_handler.process_error()

        try:
            trustee.verify_decryption_proofs(self.tally.tallies)
            self.msg_handler.print_msg("Decryption proofs verified!")
        except helios.HeliosException as e:
            self.msg_handler.process_error()

        self.tally.add_dec_factors(trustee)

    def verify_all_trustees(self):
        print()
        self.msg_handler.print_msg("Verifying trustees...")
        calculated_pk = 1
        for k, trustee in self.trustees.items():
            self.verify_trustee(trustee)
            calculated_pk = calculated_pk * trustee.public_key.y
            calculated_pk = calculated_pk % self.election.public_key.p

        print()
        try:
            if calculated_pk != self.election.public_key.y:
                raise helios.ElectionPK.ElectionParamsError(
                    "Election public key is not correctly formed!")
            self.msg_handler.print_msg("Election public key correctly formed!")
        except helios.HeliosException as e:
            self.msg_handler.process_error()

    def verify_tally(self):
        print()
        self.msg_handler.print_msg("Verifying result...")
        computed_result = None
        try:
            self.tally.verify_result(self.result)
            computed_result = self.result
            computed_result[0][0] = 6
            self.print_results(computed_result)
            print()
            self.msg_handler.print_msg("Results verified!")
        except helios.HeliosException as e:
            computed_result = self.tally.decrypt_from_factors()
            self.print_results(computed_result)
            print()
            self.msg_handler.process_error()

    def print_results(self, computed_result):
        RED = Colours.RED
        for q_num in range(len(self.election.questions)):
            print()
            question = self.election.questions[q_num]
            self.msg_handler.print_msg(
                "QUESTION: {}".format(question["question"]))
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
            self.msg_handler.print_msg(table.table, wrap=False)

    def verify_election(self):
        finished = 1
        try:
            self.verify_election_parameters()
            self.verify_all_ballots()
            self.verify_all_trustees()
            self.verify_tally()
        except (VerifierException, KeyboardInterrupt) as e:
            finished = 0
        finally:
            self.msg_handler.shutdown()
            print()
            if finished == 1:
                self.msg_handler.print_msg(
                    "Verification finished with {} error(s) and {} warning(s)".
                    format(
                        Colours.RED(self.msg_handler.error_counter),
                        Colours.YELLOW(self.msg_handler.warning_counter)))

                if self.msg_handler.error_counter > 0:
                    self.msg_handler.print_msg(
                        "ELECTION COULD NOT BE VERIFIED!", "ERROR")
                else:
                    self.msg_handler.print_msg(
                        "ELECTION VERIFIED SUCCESSFULLY!")
            else:
                self.msg_handler.print_msg("VERIFICATION WAS NOT COMPLETED!",
                                           "ERROR")
            print()

    def fetch_election_info(self, path=None, force_download=False):
        if path is None or force_download is True:
            election_url = self.host + "/elections/" + self.uuid
        else:
            election_url = path

        self.msg_handler.print_msg("Downloading election data...")
        election_dct = fetch_json(election_url)
        self.election = helios.Election(election_dct)

        return self.election

    def fetch_voters_info(self, path=None, force_download=False):
        if path is None or force_download is True:
            voters_url = self.host + "/elections/" + self.uuid + "/voters"
        else:
            voters_url = path

        self.msg_handler.print_msg("Downloading voters...")

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
        self.msg_handler.print_msg(
            "{} voters found.".format(Colours.BLUE(total_voters)))

        # Build a dictionary of voters for quick access
        for voter in temp_voters:
            voter_uuid = voter["uuid"]
            self._voters_uuids_ordered.append(voter_uuid)
            self.voters[voter_uuid] = helios.CreateVoter(voter)

    def fetch_ballots_info(self, path=None, force_download=False):
        if path is None or force_download is True:
            ballots_url = self.host + "/elections/" + self.uuid + "/ballots"
            url_end = "/last"
        else:
            ballots_url = path
            url_end = ".json"

        self.msg_handler.print_msg("Downloading ballots...")
        for uuid, voter in tqdm(
                self.voters.items(), ncols=100, unit=' voters'):
            addr = ballots_url + "/" + uuid + url_end
            ballot = fetch_json(addr)
            self.ballots[voter.uuid] = helios.Ballot(ballot)

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

        self.msg_handler.print_msg("Downloading trustees...")
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
        for voter_uuid in self._voters_uuids_ordered:
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
        '--verbose', action='store_true', help='show progress on screen')
    args = parser.parse_args()

    verifier = Verifier(args.uuid, args.host, args.verbose)
    from_host = verifier.fetch_all_election_data(args.path,
                                                 args.force_download)
    if from_host:
        verifier.save_all(args.path)

    verifier.verify_election()
