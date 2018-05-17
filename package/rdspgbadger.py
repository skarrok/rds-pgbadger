#!/usr/bin/env python
"""
Fetch logs from RDS postgres instance and use them with pgbadger to generate a
report.
"""
from datetime import datetime
import argparse
import errno
import hashlib
import hmac
import logging
import urllib
import os
import subprocess

import boto3
from botocore.exceptions import (ClientError, EndpointConnectionError,
                                 NoRegionError, NoCredentialsError,
                                 PartialCredentialsError)
import requests

try:
    from shutil import which
except ImportError:
    from which import which

__version__ = "1.2.2"
logger = logging.getLogger("rds-pgbadger")


def valid_date(s):
    try:
        return datetime.strptime(s, "%Y-%m-%d").strftime("%Y-%m-%d")
    except ValueError:
        msg = "Not a valid date: '{0}'.".format(s)
        raise argparse.ArgumentTypeError(msg)


def define_logger(verbose=False):
    logger = logging.getLogger("rds-pgbadger")
    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    logFormatter = logging.Formatter("%(asctime)s :: %(levelname)s :: "
                                     "%(message)s")
    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(logFormatter)
    logger.addHandler(consoleHandler)


def get_all_logs(dbinstance_id,
                 output,
                 date=None,
                 region=None,
                 assume_role=None,
                 method=None):

    boto_args = {}
    if region:
        boto_args['region_name'] = region

    if assume_role:
        sts_client = boto3.client('sts')
        assumedRoleObject = sts_client.assume_role(
            RoleArn=assume_role, RoleSessionName="RDSPGBadgerSession1")

        credentials = assumedRoleObject['Credentials']
        boto_args['aws_access_key_id'] = credentials['AccessKeyId']
        boto_args['aws_secret_access_key'] = credentials['SecretAccessKey']
        boto_args['aws_session_token'] = credentials['SessionToken']
        logger.info('STS Assumed role %s', assume_role)

    client = boto3.client("rds", **boto_args)
    paginator = client.get_paginator("describe_db_log_files")
    response_iterator = paginator.paginate(
        DBInstanceIdentifier=dbinstance_id, FilenameContains="postgresql.log")

    for response in response_iterator:
        for log in (name for name in response.get("DescribeDBLogFiles")
                    if not date or date in name["LogFileName"]):
            filename = "{}/{}".format(output, log["LogFileName"])
            logger.info("Downloading file %s", filename)
            try:
                os.remove(filename)
            except OSError:
                pass
            if method is None or method == 'rest':
                get_log_file_via_rest(client, dbinstance_id, filename,
                                      log["LogFileName"])
            elif method == 'boto3':
                write_log(client, dbinstance_id, filename, log["LogFileName"])


def get_database_region(rds_client, dbinstance_id):
    resp = rds_client.describe_db_instances(DBInstanceIdentifier=dbinstance_id)
    region = resp['DBInstances'][0]['DBInstanceArn'].split(':')[3]
    return region


def get_credentials():
    session = boto3.Session()
    return session.get_credentials()


def get_log_file_via_rest(client, dbinstance_id, filename, logfilename):
    def sign(key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    def getSignatureKey(key, dateStamp, regionName, serviceName):
        kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
        kRegion = sign(kDate, regionName)
        kService = sign(kRegion, serviceName)
        kSigning = sign(kService, 'aws4_request')
        return kSigning

    # ************* REQUEST VALUES *************
    method = 'GET'
    service = 'rds'
    region = get_database_region(client, dbinstance_id)
    host = 'rds.' + region + '.amazonaws.com'
    # host = 'rds.us-west-2.amazonaws.com'
    # region = 'us-west-2'
    endpoint = 'https://' + host

    # Key derivation functions. See:
    # http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
    credentials = get_credentials()
    access_key = credentials.access_key
    secret_key = credentials.secret_key
    if access_key is None or secret_key is None:
        return 'No access key is available.'

    # Create a date for headers and the credential string
    t = datetime.utcnow()
    amz_date = t.strftime(
        '%Y%m%dT%H%M%SZ')  # Format date as YYYYMMDD'T'HHMMSS'Z'
    datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope

    # sample usage : '/v13/downloadCompleteLogFile/DBInstanceIdentifier/error/postgresql.log.2017-05-26-04'
    canonical_uri = '/v13/downloadCompleteLogFile/' + dbinstance_id + '/' + filename

    # Step 3: Create the canonical headers and signed headers. Header names
    # and value must be trimmed and lowercase, and sorted in ASCII order.
    # Note trailing \n in canonical_headers.
    # signed_headers is the list of headers that are being included
    # as part of the signing process. For requests that use query strings,
    # only "host" is included in the signed headers.
    canonical_headers = 'host:' + host + '\n'
    signed_headers = 'host'

    # Match the algorithm to the hashing algorithm you use, either SHA-1 or
    # SHA-256 (recommended)
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'

    # Step 4: Create the canonical query string. In this example, request
    # parameters are in the query string. Query string values must
    # be URL-encoded (space=%20). The parameters must be sorted by name.
    canonical_querystring = ''
    canonical_querystring += 'X-Amz-Algorithm=AWS4-HMAC-SHA256'
    canonical_querystring += '&X-Amz-Credential=' + urllib.parse.quote_plus(
        access_key + '/' + credential_scope)
    canonical_querystring += '&X-Amz-Date=' + amz_date
    canonical_querystring += '&X-Amz-Expires=30'
    canonical_querystring += '&X-Amz-SignedHeaders=' + signed_headers

    # Step 5: Create payload hash. For GET requests, the payload is an
    # empty string ("").
    payload_hash = hashlib.sha256(b'').hexdigest()

    # Step 6: Combine elements to create create canonical request
    canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash

    # ************* TASK 2: CREATE THE STRING TO SIGN*************
    string_to_sign = algorithm + '\n' + amz_date + '\n' + credential_scope + '\n' + hashlib.sha256(
        canonical_request.encode('utf-8')).hexdigest()

    # ************* TASK 3: CALCULATE THE SIGNATURE *************
    # Create the signing key
    signing_key = getSignatureKey(secret_key, datestamp, region, service)

    # Sign the string_to_sign using the signing_key
    signature = hmac.new(signing_key, (string_to_sign).encode("utf-8"),
                         hashlib.sha256).hexdigest()

    # ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
    # The auth information can be either in a query string
    # value or in a header named Authorization. This code shows how to put
    # everything into a query string.
    canonical_querystring += '&X-Amz-Signature=' + signature

    # ************* SEND THE REQUEST *************
    # The 'host' header is added automatically by the Python 'request' lib. But it
    # must exist as a header in the request.
    request_url = endpoint + canonical_uri + "?" + canonical_querystring

    r = requests.get(request_url)

    r = r.text.encode('UTF-8')

    if not os.path.exists(os.path.dirname(filename)):
        try:
            os.makedirs(os.path.dirname(filename))
        except OSError as exc:  # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise
    with open(filename, "wb") as logfile:
        logfile.write(r)


def write_log(client, dbinstance_id, filename, logfilename):
    marker = "0"
    max_number_of_lines = 10000
    subtract_lines = 10
    truncated_string = " [Your log message was truncated]"
    slice_length = len(truncated_string) + 1

    response = client.download_db_log_file_portion(
        DBInstanceIdentifier=dbinstance_id,
        LogFileName=logfilename,
        Marker=marker,
        NumberOfLines=max_number_of_lines)

    while True:
        if not os.path.exists(os.path.dirname(filename)):
            try:
                os.makedirs(os.path.dirname(filename))
            except OSError as exc:  # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise
        with open(filename, "a") as logfile:
            if 'LogFileData' in response:
                if truncated_string in response["LogFileData"][-slice_length:]:
                    downloaded_lines = response["LogFileData"].count("\n")
                    if downloaded_lines == 0:
                        raise Exception(
                            "No line was downloaded in last portion!")
                    max_number_of_lines = max(
                        downloaded_lines - subtract_lines, 1)
                    logger.info(
                        "Log truncated, retrying portion with "
                        "NumberOfLines = {0}".format(max_number_of_lines))
                else:
                    marker = response["Marker"]
                    logfile.write(response["LogFileData"])

        if ('LogFileData' in response
                and not response["LogFileData"].rstrip("\n")
                and not response["AdditionalDataPending"]):
            break

        response = client.download_db_log_file_portion(
            DBInstanceIdentifier=dbinstance_id,
            LogFileName=logfilename,
            Marker=marker,
            NumberOfLines=max_number_of_lines)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('instance', help="RDS instance identifier")
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s {version}'.format(version=__version__))

    parser.add_argument(
        '-v',
        '--verbose',
        help="increase output verbosity",
        action='store_true')
    parser.add_argument(
        '-d',
        '--date',
        help="get logs for given YYYY-MM-DD date",
        type=valid_date)
    parser.add_argument('--assume-role', help="AWS STS AssumeRole")
    parser.add_argument('-r', '--region', help="AWS region")
    parser.add_argument(
        '-o',
        '--output',
        help="Output folder for logs and report",
        default='out')
    parser.add_argument(
        '-n', '--no-process', help="Only download logs", action='store_true')
    parser.add_argument(
        '-X', '--pgbadger-args', help="pgbadger arguments", default='')
    parser.add_argument(
        '-f',
        '--format',
        help="Format of the report",
        choices=['text', 'html', 'bin', 'json', 'tsung'],
        default='html')
    parser.add_argument(
        '-m',
        '--method',
        help="Download method",
        choices=['boto3', 'rest'],
        default='rest')

    args = parser.parse_args()
    define_logger(args.verbose)

    if args.date:
        logger.info("Getting logs from %s", args.date)
    else:
        logger.info("Getting all logs")

    pgbadger = which("pgbadger")
    if not pgbadger:
        raise Exception("pgbadger not found")
    logger.debug("pgbadger found")

    try:
        get_all_logs(
            args.instance,
            args.output,
            date=args.date,
            region=args.region,
            assume_role=args.assume_role,
            method=args.method,
        )
    except (EndpointConnectionError, ClientError) as e:
        logger.error(e)
        exit(1)
    except NoRegionError:
        logger.error("No region provided")
        exit(1)
    except NoCredentialsError:
        logger.error("Missing credentials")
        exit(1)
    except PartialCredentialsError:
        logger.error("Partial credentials, please check your credentials file")
        exit(1)

    if args.no_process:
        logger.info("File(s) downloaded. Not processing with PG Badger.")
    else:
        logger.info("Generating PG Badger report.")
        command = ("{} -p \"%t:%r:%u@%d:[%p]:\" {} -o {}/report.{} "
                   "{}/error/*.log.* ".format(pgbadger, args.pgbadger_args,
                                              args.output, args.format,
                                              args.output))
        logger.debug("Command: %s", command)
        subprocess.call(command, shell=True)
        logger.info("Done")


if __name__ == '__main__':
    main()
