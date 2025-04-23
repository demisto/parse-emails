import argparse
import contextlib
import json
import logging
import math
import os
import sys
import tempfile
import time
import zipfile
from collections.abc import Iterable
from datetime import datetime, timedelta
from distutils.util import strtobool
from pathlib import Path
from typing import Any

import requests
from gitlab import GitlabGetError
from gitlab.client import Gitlab
from gitlab.v4.objects import ProjectPipeline, ProjectPipelineJob
from junitparser import JUnitXml, TestSuite
from slack_sdk import WebClient

from Tests.Marketplace.marketplace_constants import BucketUploadFlow
from Tests.scripts.collect_tests.constants import (
    TEST_MODELING_RULES_TO_JIRA_MAPPING,
    TEST_MODELING_RULES_TO_JIRA_TICKETS_CONVERTED,
    TEST_USE_CASE_TO_JIRA_MAPPING,
    TEST_USE_CASE_TO_JIRA_TICKETS_CONVERTED,
)
from Tests.scripts.common import (
    BLACKLIST_VALIDATION,
    BUCKET_UPLOAD,
    BUCKET_UPLOAD_BRANCH_SUFFIX,
    CONTENT_DOCS_NIGHTLY,
    CONTENT_DOCS_PR,
    CONTENT_MERGE,
    CONTENT_NIGHTLY,
    CONTENT_PR,
    DOCKERFILES_PR,
    RIT_MR,
    SECRETS_FOUND,
    TEST_MODELING_RULES_REPORT_FILE_NAME,
    TEST_PLAYBOOKS_REPORT_FILE_NAME,
    TEST_USE_CASE_REPORT_FILE_NAME,
    download_and_read_artifact,
    get_blacklist_status_details,
    get_instance_directories,
    get_job_by_name,
    get_previous_pipeline,
    get_properties_for_test_suite,
    get_scheduled_pipelines_by_name,
    get_slack_user_name,
    get_test_results_files,
    is_blacklist_pivot,
    is_within_time_window,
    join_list_by_delimiter_in_chunks,
    replace_escape_characters,
    secrets_sha_has_changed,
    slack_link,
)
from Tests.scripts.generic_test_report import (
    calculate_test_results,
    get_summary_for_test,
    read_test_objects_to_jira_mapping,
)
from Tests.scripts.github_client import GithubPullRequest
from Tests.scripts.gitlab_client import GitlabMergeRequest
from Tests.scripts.test_playbooks_report import TEST_PLAYBOOKS_TO_JIRA_TICKETS_CONVERTED, read_test_playbook_to_jira_mapping
from Tests.scripts.utils.log_util import install_logging

ROOT_ARTIFACTS_FOLDER = Path(os.getenv("ARTIFACTS_FOLDER", "./artifacts"))

BIGQUERY_UPLOAD_SUCCESS_FILE = ROOT_ARTIFACTS_FOLDER / "bigquery-upload-success.txt"
BIGQUERY_UPLOAD_FAILURE_FILE = ROOT_ARTIFACTS_FOLDER / "bigquery-upload-failure.txt"

ARTIFACTS_FOLDER_XSOAR = ROOT_ARTIFACTS_FOLDER / "xsoar"
ARTIFACTS_FOLDER_XSIAM = ROOT_ARTIFACTS_FOLDER / "marketplacev2"
ARTIFACTS_FOLDER_XPANSE = ROOT_ARTIFACTS_FOLDER / "xpanse"
ARTIFACTS_FOLDER_PLATFORM = ROOT_ARTIFACTS_FOLDER / "platform"

ARTIFACTS_FOLDER_XSOAR_SERVER_TYPE = ARTIFACTS_FOLDER_XSOAR / "server_type_XSOAR"
ARTIFACTS_FOLDER_XSOAR_SAAS_SERVER_TYPE = ARTIFACTS_FOLDER_XSOAR / "server_type_XSOAR SAAS"
ARTIFACTS_FOLDER_XPANSE_SERVER_TYPE = ARTIFACTS_FOLDER_XPANSE / "server_type_XPANSE"
ARTIFACTS_FOLDER_XSIAM_SERVER_TYPE = ARTIFACTS_FOLDER_XSIAM / "server_type_XSIAM"
ARTIFACTS_FOLDER_PLATFORM_SERVER_TYPE = ARTIFACTS_FOLDER_PLATFORM / "server_type_PLATFORM"

LOCKED_MACHINES_LIST_FILE_NAME = "locked_machines_list.txt"
IS_CHOSEN_MACHINE_FILE_NAME = "is_chosen_machine.txt"
GITLAB_SERVER_URL = os.getenv("CI_SERVER_URL", "https://gitlab.xdr.pan.local")  # disable-secrets-detection
GITLAB_PROJECT_ID = os.getenv("CI_PROJECT_ID") or 1061
GITLAB_SSL_VERIFY = bool(strtobool(os.getenv("GITLAB_SSL_VERIFY", "true")))
CONTENT_CHANNEL = "dmst-build-test"
XDR_CONTENT_SYNC_CHANNEL_ID = os.getenv("XDR_CONTENT_SYNC_CHANNEL_ID", "")
SLACK_USERNAME = "Content GitlabCI"
SLACK_WORKSPACE_NAME = os.getenv("SLACK_WORKSPACE_NAME", "")
REPOSITORY_NAME = os.getenv("REPOSITORY_NAME", "demisto/content")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
CI_COMMIT_BRANCH = os.getenv("CI_COMMIT_BRANCH", "") or os.getenv("CI_COMMIT_REF_NAME", "")
CI_COMMIT_SHA = os.getenv("CI_COMMIT_SHA", "")
CI_SERVER_HOST = os.getenv("CI_SERVER_HOST", "")
DEFAULT_BRANCH = os.getenv("CI_DEFAULT_BRANCH", "master")
SLACK_NOTIFY = "slack-notify"
ALL_FAILURES_WERE_CONVERTED_TO_JIRA_TICKETS = " (All failures were converted to Jira tickets)"
UPLOAD_BUCKETS = [
    (ARTIFACTS_FOLDER_XSOAR_SERVER_TYPE, "XSOAR"),
    (ARTIFACTS_FOLDER_XSOAR_SAAS_SERVER_TYPE, "XSOAR SAAS"),
    (ARTIFACTS_FOLDER_XSIAM_SERVER_TYPE, "XSIAM"),
    (ARTIFACTS_FOLDER_XPANSE_SERVER_TYPE, "XPANSE"),
    (ARTIFACTS_FOLDER_PLATFORM_SERVER_TYPE, "PLATFORM"),
]
TEST_UPLOAD_FLOW_PIPELINE_ID = "test_upload_flow_pipeline_id.txt"
SLACK_MESSAGE = "slack_message.json"
SLACK_MESSAGE_THREADS = "slack_message_threads.json"
SLACK_MESSAGE_CHANNEL_TO_THREAD = "slack_message_channel_to_thread.json"
OLD_SLACK_MESSAGE = "slack_msg.json"
OLD_SLACK_MESSAGE_THREADS = "threaded_messages.json"
OLD_SLACK_MESSAGE_CHANNEL_TO_THREAD = "channel_to_thread.json"
DAYS_TO_SEARCH = 30
ALLOWED_COVERAGE_PROXIMITY = 0.25  # Percentage threshold for allowed coverage proximity.
BLACKLIST_VALIDATION_JOB = "blacklist-validation-job"
BLACKLIST_VALIDATION_PIPELINE = "Blacklist validation pipeline"
BLACKLIST_VALIDATION_ARTIFACTS_PATH = Path("./artifacts") / "black_list_report_for_slack.json"
LOOK_BACK_HOURS = 2
TARGET_HOUR = 6  # 6:00 AM UTC is 8:00 or 9:00 AM in Israel, depending on DST
TARGET_MINUTES = 0
# The message should be sent within 10 minutes before or after the target hour, as we expect a job to finish within 20 minutes.
# This is the default for blacklist validation; other jobs may require a different '--window_minutes' value.
WINDOW_MINUTES = 10
SECONDS_TO_SLEEP = 30


def options_handler() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Parser for slack_notifier args")
    parser.add_argument("-n", "--name-mapping_path", help="Path to name mapping file.", required=True)
    parser.add_argument("-r", "--repository", help="The repository name", default=REPOSITORY_NAME)
    parser.add_argument("-u", "--url", help="The gitlab server url", default=GITLAB_SERVER_URL)
    parser.add_argument("-p", "--pipeline_id", help="The pipeline id to check the status of", required=True)
    parser.add_argument("-s", "--slack_token", help="The token for slack", required=True)
    parser.add_argument("-c", "--ci_token", help="The token for circleci/gitlab", required=True)
    parser.add_argument(
        "-ch", "--slack_channel", help="The slack channel in which to send the notification", default=CONTENT_CHANNEL
    )
    parser.add_argument("-gp", "--gitlab_project_id", help="The gitlab project id", default=GITLAB_PROJECT_ID)
    parser.add_argument("-tw", "--triggering-workflow", help="The type of ci pipeline workflow the notifier is reporting on")
    parser.add_argument(
        "-a", "--allow-failure", help="Allow posting message to fail in case the channel doesn't exist", required=True
    )
    parser.add_argument("--github-token", required=False, help="A GitHub API token", default=GITHUB_TOKEN)
    parser.add_argument("--current-sha", required=False, help="Current branch commit SHA", default=CI_COMMIT_SHA)
    parser.add_argument("--current-branch", required=False, help="Current branch name", default=CI_COMMIT_BRANCH)
    parser.add_argument("-f", "--file", help="File path with the text to send")
    parser.add_argument("-t", "--attachments", help="File path with the attachments to send", required=False)
    parser.add_argument("-th", "--thread", help="A message to be sent as a thread", required=False)
    parser.add_argument("-dr", "--dry_run", help="true for a dry run pipeline, false for a prod pipeline", default="false")
    parser.add_argument(
        "--target_hours",
        type=int,
        help="The starting hour (0-23) in UTC for the range window when the Slack message should be sent.",
        default=TARGET_HOUR,
    )
    parser.add_argument(
        "--target_minutes",
        type=int,
        help="The starting minute (0-59) in UTC for the range window when the Slack message should be sent",
        default=TARGET_MINUTES,
    )
    parser.add_argument(
        "--window_minutes",
        type=int,
        help="The time range before and after the target time, in minutes, during which the Slack message can be sent.",
        default=WINDOW_MINUTES,
    )

    return parser.parse_args()


def get_artifact_data(artifact_folder: Path, artifact_relative_path: str) -> str | None:
    """
    Retrieves artifact data according to the artifact relative path from 'ARTIFACTS_FOLDER' given.
    Args:
        artifact_folder (Path): Full path of the artifact root folder.
        artifact_relative_path (str): Relative path of an artifact file.

    Returns:
        (Optional[str]): data of the artifact as str if exists, None otherwise.
    """
    file_name = artifact_folder / artifact_relative_path
    try:
        if file_name.exists():
            logging.info(f"Extracting {file_name}")
            return file_name.read_text()
        else:
            logging.info(f"Did not find {file_name} file")
    except Exception:
        logging.exception(f"Error getting {file_name} file")
    return None


def get_test_report_pipeline_url(pipeline_url: str) -> str:
    return f"{pipeline_url}/test_report"


def get_msg_machines(failed_jobs: dict, job_cause_fail: set[str], job_cause_warning: set[str], msg: str):
    if job_cause_fail.intersection(set(failed_jobs)):
        color = "danger"
    elif job_cause_warning.intersection(set(failed_jobs)):
        color = "warning"
    else:
        color = "good"

    return [
        {
            "fallback": msg,
            "color": color,
            "title": msg,
        }
    ]


def machines_saas_and_xsiam(failed_jobs):
    lock_xsoar_machine_raw_txt = split_results_file(
        get_artifact_data(ARTIFACTS_FOLDER_XSOAR, LOCKED_MACHINES_LIST_FILE_NAME), ","
    )
    lock_xsiam_machine_raw_txt = split_results_file(
        get_artifact_data(ARTIFACTS_FOLDER_XSIAM, LOCKED_MACHINES_LIST_FILE_NAME), ","
    )

    chosen_machine_by_label_xsoar = get_artifact_data(ARTIFACTS_FOLDER_XSOAR, IS_CHOSEN_MACHINE_FILE_NAME)
    chosen_machine_by_label_xsiam = get_artifact_data(ARTIFACTS_FOLDER_XSIAM, IS_CHOSEN_MACHINE_FILE_NAME)
    machines = []

    custom_flow_type_xsoar = f"Flow type: {chosen_machine_by_label_xsoar}\n" if chosen_machine_by_label_xsoar else ""
    if lock_xsoar_machine_raw_txt:
        machines.extend(
            get_msg_machines(
                failed_jobs,
                {"xsoar_ng_server_ga"},
                {"xsoar-test_playbooks_results"},
                f"XSOAR SAAS:\n{custom_flow_type_xsoar}{','.join(lock_xsoar_machine_raw_txt)}",
            )
        )

    custom_flow_type_xsiam = f"Flow type: {chosen_machine_by_label_xsiam}\n" if chosen_machine_by_label_xsiam else ""
    if lock_xsiam_machine_raw_txt:
        machines.extend(
            get_msg_machines(
                failed_jobs,
                {"xsiam_server_ga", "install-packs-in-xsiam-ga", "install-packs-in-xsoar-ng-ga"},
                {"xsiam-test_playbooks_results", "xsiam-test_modeling_rule_results"},
                f"XSIAM:\n{custom_flow_type_xsiam}{','.join(lock_xsiam_machine_raw_txt)}",
            )
        )

    if not machines:
        return machines
    return (
        get_msg_machines(
            failed_jobs,
            {
                "xsoar_ng_server_ga",
                "xsiam_server_ga",
                "install-packs-in-xsiam-ga",
                "install-packs-in-xsoar-ng-ga",
            },
            {
                "xsoar-test_playbooks_results",
                "xsiam-test_playbooks_results",
                "xsiam-test_modeling_rule_results",
            },
            f"Used {len(machines)} machine types",
        )
        + machines
    )


def test_modeling_rules_results(artifact_folder: Path, pipeline_url: str, title: str) -> tuple[list[dict[str, Any]], bool]:
    if not (test_modeling_rules_results_files := get_test_results_files(artifact_folder, TEST_MODELING_RULES_REPORT_FILE_NAME)):
        logging.error(f"Could not find any test modeling rule result files in {artifact_folder}")
        title = f"{title} - Failed to get Test Modeling rules results"
        return [
            {
                "fallback": title,
                "color": "warning",
                "title": title,
            }
        ], True

    failed_test_to_jira_mapping = read_test_objects_to_jira_mapping(artifact_folder, TEST_MODELING_RULES_TO_JIRA_MAPPING)

    modeling_rules_to_test_suite, _, _ = calculate_test_results(test_modeling_rules_results_files)

    if not modeling_rules_to_test_suite:
        logging.info("Test Modeling rules - No test modeling rule results found for this build")
        title = f"{title} - Test Modeling rules - No test modeling rule results found for this build"
        return [
            {
                "fallback": title,
                "color": "good",
                "title": title,
            }
        ], False

    failed_test_suites_tuples = []
    total_test_suites = 0
    for test_suites in modeling_rules_to_test_suite.values():
        for test_suite in test_suites.values():
            total_test_suites += 1
            if test_suite.failures or test_suite.errors:
                properties = get_properties_for_test_suite(test_suite)
                if modeling_rule := get_summary_for_test(properties):
                    failed_test_suites_tuples.append(
                        failed_test_data_to_slack_link(modeling_rule, failed_test_to_jira_mapping.get(modeling_rule))
                    )

    if failed_test_suites_tuples:
        if (artifact_folder / TEST_MODELING_RULES_TO_JIRA_TICKETS_CONVERTED).exists():
            title_suffix = ALL_FAILURES_WERE_CONVERTED_TO_JIRA_TICKETS
            color = "warning"
        else:
            title_suffix = ""
            color = "danger"
        failed_test_suites = map(lambda x: x[1], sorted(failed_test_suites_tuples, key=lambda x: (x[0], x[1])))
        title = (
            f"{title} - Failed Tests Modeling rules - Passed:{total_test_suites - len(failed_test_suites_tuples)}, "
            f"Failed:{len(failed_test_suites_tuples)}"
        )

        return [
            {
                "fallback": title,
                "color": color,
                "title": title,
                "title_link": get_test_report_pipeline_url(pipeline_url),
                "fields": [
                    {
                        "title": f"Failed Tests Modeling rules{title_suffix if i == 0 else ' - Continued'}",
                        "value": chunk,
                        "short": False,
                    }
                    for i, chunk in enumerate(join_list_by_delimiter_in_chunks(failed_test_suites))
                ],
            }
        ], True

    title = f"{title} - All Test Modeling rules Passed - ({total_test_suites})"
    return [
        {
            "fallback": title,
            "color": "good",
            "title": title,
            "title_link": get_test_report_pipeline_url(pipeline_url),
        }
    ], False


def test_use_case_results(artifact_folder: Path, pipeline_url: str, title: str) -> tuple[list[dict[str, Any]], bool]:
    if not (test_use_case_files := get_test_results_files(artifact_folder, TEST_USE_CASE_REPORT_FILE_NAME)):
        logging.error(f"Could not find any test use case result files in {artifact_folder}")
        title = f"{title} - Failed to get Test Use Case results"
        return [
            {
                "fallback": title,
                "color": "warning",
                "title": title,
            }
        ], True

    failed_test_to_jira_mapping = read_test_objects_to_jira_mapping(artifact_folder, TEST_USE_CASE_TO_JIRA_MAPPING)

    use_case_to_test_suite, _, _ = calculate_test_results(test_use_case_files)

    if not use_case_to_test_suite:
        logging.info("Test Use Case - No test use case results found for this build")
        title = f"{title} - Test Use Case - No test use case results found for this build"
        return [
            {
                "fallback": title,
                "color": "good",
                "title": title,
            }
        ], False

    failed_test_suites_tuples = []
    total_test_suites = 0
    for test_suites in use_case_to_test_suite.values():
        for test_suite in test_suites.values():
            total_test_suites += 1
            if test_suite.failures or test_suite.errors:
                properties = get_properties_for_test_suite(test_suite)
                if use_case := get_summary_for_test(properties):
                    failed_test_suites_tuples.append(
                        failed_test_data_to_slack_link(use_case, failed_test_to_jira_mapping.get(use_case))
                    )

    if failed_test_suites_tuples:
        if (artifact_folder / TEST_USE_CASE_TO_JIRA_TICKETS_CONVERTED).exists():
            title_suffix = ALL_FAILURES_WERE_CONVERTED_TO_JIRA_TICKETS
            color = "warning"
        else:
            title_suffix = ""
            color = "danger"
        failed_test_suites = map(lambda x: x[1], sorted(failed_test_suites_tuples, key=lambda x: (x[0], x[1])))
        title = (
            f"{title} - Failed Test Use Case - Passed:{total_test_suites - len(failed_test_suites_tuples)}, "
            f"Failed:{len(failed_test_suites_tuples)}"
        )

        return [
            {
                "fallback": title,
                "color": color,
                "title": title,
                "title_link": get_test_report_pipeline_url(pipeline_url),
                "fields": [
                    {
                        "title": f"Failed Test Use Cases {title_suffix if i == 0 else ' - Continued'}",
                        "value": chunk,
                        "short": False,
                    }
                    for i, chunk in enumerate(join_list_by_delimiter_in_chunks(failed_test_suites))
                ],
            }
        ], True

    title = f"{title} - All Test Use Cases Passed - ({total_test_suites})"
    return [
        {
            "fallback": title,
            "color": "good",
            "title": title,
            "title_link": get_test_report_pipeline_url(pipeline_url),
        }
    ], False


def failed_test_data_to_slack_link(failed_test: str, jira_ticket_data: dict[str, str] | None) -> tuple[bool, str]:
    if jira_ticket_data:
        return True, slack_link(jira_ticket_data["url"], f"{failed_test} [{jira_ticket_data['key']}]")
    return False, failed_test


def test_playbooks_results_to_slack_msg(
    instance_role: str,
    succeeded_tests: set[str],
    failed_tests: set[str],
    skipped_integrations: set[str],
    skipped_tests: set[str],
    playbook_to_jira_mapping: dict[str, Any],
    test_playbook_tickets_converted: bool,
    title: str,
    pipeline_url: str,
) -> tuple[list[dict[str, Any]], bool]:
    if failed_tests:
        title = (
            f"{title} ({instance_role}) - Test Playbooks - Passed:{len(succeeded_tests)}, Failed:{len(failed_tests)}, "
            f"Skipped - {len(skipped_tests)}, Skipped Integrations - {len(skipped_integrations)}"
        )
        if test_playbook_tickets_converted:
            title_suffix = ALL_FAILURES_WERE_CONVERTED_TO_JIRA_TICKETS
            color = "warning"
        else:
            title_suffix = ""
            color = "danger"

        failed_playbooks: Iterable[str] = map(
            lambda x: x[1],
            sorted(
                [
                    failed_test_data_to_slack_link(playbook_id, playbook_to_jira_mapping.get(playbook_id))
                    for playbook_id in failed_tests
                ],
                key=lambda x: (x[0], x[1]),
            ),
        )
        return [
            {
                "fallback": title,
                "color": color,
                "title": title,
                "title_link": get_test_report_pipeline_url(pipeline_url),
                "mrkdwn_in": ["fields"],
                "fields": [
                    {
                        "title": f"Failed Test Playbooks{title_suffix}",
                        "value": chunk,
                        "short": False,
                    }
                    for i, chunk in enumerate(join_list_by_delimiter_in_chunks(failed_playbooks))
                ],
            }
        ], True
    title = (
        f"{title} ({instance_role}) - All Tests Playbooks Passed - Passed:{len(succeeded_tests)}, "
        f"Skipped - {len(skipped_tests)}, Skipped Integrations - {len(skipped_integrations)})"
    )
    return [
        {
            "fallback": title,
            "color": "good",
            "title": title,
            "title_link": get_test_report_pipeline_url(pipeline_url),
        }
    ], False


def split_results_file(tests_data: str | None, delim: str = "\n") -> list[str]:
    return list(filter(None, tests_data.split(delim))) if tests_data else []


def get_playbook_tests_data(artifact_folder: Path) -> tuple[set[str], set[str], set[str], set[str]]:
    succeeded_tests = set()
    failed_tests = set()
    skipped_tests = set()
    skipped_integrations = set(split_results_file(get_artifact_data(artifact_folder, "skipped_integrations.txt")))
    xml = JUnitXml.fromfile(str(artifact_folder / TEST_PLAYBOOKS_REPORT_FILE_NAME))
    for test_suite in xml.iterchildren(TestSuite):
        properties = get_properties_for_test_suite(test_suite)
        if playbook_id := properties.get("playbook_id"):
            if test_suite.failures or test_suite.errors:
                failed_tests.add(playbook_id)
            elif test_suite.skipped:
                skipped_tests.add(playbook_id)
            else:
                succeeded_tests.add(playbook_id)

    return succeeded_tests, failed_tests, skipped_tests, skipped_integrations


def test_playbooks_results(artifact_folder: Path, pipeline_url: str, title: str) -> tuple[list[dict[str, Any]], bool]:
    test_playbook_to_jira_mapping = read_test_playbook_to_jira_mapping(artifact_folder)
    test_playbook_tickets_converted = (artifact_folder / TEST_PLAYBOOKS_TO_JIRA_TICKETS_CONVERTED).exists()
    has_failed_tests = False
    test_playbook_slack_msg = []
    for instance_role, instance_directory in get_instance_directories(artifact_folder).items():
        try:
            succeeded_tests, failed_tests, skipped_tests, skipped_integrations = get_playbook_tests_data(instance_directory)
            if succeeded_tests or failed_tests:  # Handling case where no playbooks had run
                instance_slack_msg, instance_has_failed_tests = test_playbooks_results_to_slack_msg(
                    instance_role,
                    succeeded_tests,
                    failed_tests,
                    skipped_integrations,
                    skipped_tests,
                    test_playbook_to_jira_mapping,
                    test_playbook_tickets_converted,
                    title,
                    pipeline_url,
                )
                test_playbook_slack_msg += instance_slack_msg
                has_failed_tests |= instance_has_failed_tests
        except Exception:
            logging.exception(f"Failed to get test playbook results for {instance_role}")
            has_failed_tests = True
            test_playbook_slack_msg.append(
                {
                    "fallback": f"{title} - Failed to get Test Playbooks results for {instance_role}",
                    "title": f"{title} - Failed to get Test Playbooks results for {instance_role}",
                    "color": "danger",
                }
            )

    return test_playbook_slack_msg, has_failed_tests


def bucket_sync_msg_builder(artifact_path: Path) -> tuple[list, list]:
    bucket_sync_results = get_artifact_data(
        artifact_folder=artifact_path / "logs",
        artifact_relative_path="trigger_sync_all_buckets_status_code.log",
    )

    if not bucket_sync_results:
        logging.error("The Sync all buckets job was not triggered for any reason, file for status_code not found")
        title = "The Sync all buckets job was not triggered for any reason"
        return [], [
            {
                "fallback": title,
                "title": title,
                "color": "danger",
            }
        ]

    if bucket_sync_results == "skipped":
        # In case the run is `test-upload-flow`
        logging.debug("Skipping `Sync all buckets` msg in test upload-flow")
        return [], []

    if bucket_sync_results == "201":
        # Triggered successfully
        title = f"Sync all buckets pipeline triggered successfully. Status Code: {bucket_sync_results}"
        field_value = f"Check the {slack_link(XDR_CONTENT_SYNC_CHANNEL_ID, 'xdr-content-sync')} channel for job status updates."
        return [], [
            {
                "fallback": title,
                "title": title,
                "color": "good",
                "fields": [
                    {
                        "title": "",
                        "value": field_value,
                        "short": False,
                    }
                ],
            }
        ]

    # Triggered fail
    title = ":alert: Failed to triggered Sync all buckets pipeline,"
    if bucket_sync_results.startswith("Some Error"):
        # Some error
        title += f" Error: {bucket_sync_results}"
    else:
        # HTTP Error
        title += f" Status Code: {bucket_sync_results}"
    return [
        {
            "fallback": title,
            "title": title,
            "color": "danger",
        }
    ], []


def bucket_upload_results(
    bucket_artifact_folder: Path, marketplace_name: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    # Importing here to avoid importing demisto-sdk.
    from Tests.Marketplace.marketplace_services import get_upload_data  # noqa: E402

    slack_msg_append = []
    threaded_messages = []
    pack_results_path = bucket_artifact_folder / BucketUploadFlow.PACKS_RESULTS_FILE_FOR_SLACK

    logging.info(f'retrieving upload data from "{pack_results_path}"')
    successful_packs, _, failed_packs, _ = get_upload_data(
        pack_results_path.as_posix(), BucketUploadFlow.UPLOAD_PACKS_TO_MARKETPLACE_STORAGE
    )
    if successful_packs:
        slack_msg_append.append(
            {
                "fallback": f"Successfully uploaded {len(successful_packs)} Pack(s) to {marketplace_name}",
                "title": f"Successfully uploaded {len(successful_packs)} Pack(s) to {marketplace_name}",
                "color": "good",
            }
        )
        threaded_messages.append(
            {
                "fallback": f"Successfully uploaded {marketplace_name} Pack(s): "
                f"{', '.join(sorted({*successful_packs}, key=lambda s: s.lower()))} to {marketplace_name}",
                "title": f"Successfully uploaded {len(successful_packs)} Pack(s) to {marketplace_name}:",
                "color": "good",
                "fields": [
                    {"title": "", "value": ", ".join(sorted({*successful_packs}, key=lambda s: s.lower())), "short": False}
                ],
            }
        )

    if failed_packs:
        slack_msg_append.append(
            {
                "fallback": f"Failed to upload {len(failed_packs)} Pack(s) to {marketplace_name}",
                "title": f"Failed to upload {len(failed_packs)} Pack(s) to {marketplace_name}",
                "color": "danger",
            }
        )
        threaded_messages.append(
            {
                "fallback": f"Failed to upload {marketplace_name} Pack(s): "
                f"{', '.join(sorted({*failed_packs}, key=lambda s: s.lower()))}",
                "title": f"Failed to upload {len(failed_packs)} Pack(s) to {marketplace_name}:",
                "color": "danger",
                "fields": [{"title": "", "value": ", ".join(sorted({*failed_packs}, key=lambda s: s.lower())), "short": False}],
            }
        )

    return slack_msg_append, threaded_messages


def construct_slack_message_for_bigquery_content_upload() -> dict[str, str] | None:
    """
    Construct the slack message indicating the status of the content graph data upload to BigQuery job
    within the upload-flow or None if wasn't executed.
    Returns:
        dict[str, str] | None: A dictionary containing the slack message object, or None if the upload job wasn't executed.
    """
    if BIGQUERY_UPLOAD_SUCCESS_FILE.exists():
        return {"color": "good", "title": "Successfully uploaded content graph data to BigQuery"}
    if BIGQUERY_UPLOAD_FAILURE_FILE.exists():
        return {"color": "danger", "title": "Failed to upload content graph data to BigQuery."}

    return None


def construct_slack_msg_sync_buckets(threaded_messages, slack_msg_append):
    bucket_sync_failure, bucket_sync_success = bucket_sync_msg_builder(ROOT_ARTIFACTS_FOLDER)
    threaded_messages.extend(bucket_sync_success)
    slack_msg_append.extend(bucket_sync_failure)


def construct_slack_msg(
    triggering_workflow: str,
    pipeline_url: str,
    pipeline_failed_jobs: list[ProjectPipelineJob],
    pull_request: GithubPullRequest | None,
    merge_request: GitlabMergeRequest | None,
    file: str | None,
    attachments: str | None,
    thread: str | None,
    dry_run: str = "true",
    custom_title: str = "",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str, list[dict[str, Any]]]:
    # report failing jobs
    content_fields = []

    failed_jobs_names = {job.name: job.web_url for job in pipeline_failed_jobs}
    if failed_jobs_names:
        failed_jobs = [slack_link(url, name) for name, url in sorted(failed_jobs_names.items())]
        content_fields.append(
            {"title": f"Failed Jobs - ({len(failed_jobs_names)})", "value": "\n".join(failed_jobs), "short": False}
        )

    if pull_request:
        content_fields.append(
            {
                "title": "Pull Request",
                "value": slack_link(pull_request.data["html_url"], replace_escape_characters(pull_request.data["title"])),
                "short": False,
            }
        )

    if merge_request:
        content_fields.append(
            {
                "title": "Merge Request",
                "value": slack_link(merge_request.data["web_url"], replace_escape_characters(merge_request.data["title"])),
                "short": False,
            }
        )
    # report failing unit-tests
    triggering_workflow_lower = triggering_workflow.lower()

    # report pack updates
    threaded_messages = []
    slack_msg_append = []

    logging.debug(f"constructing slack msg for {triggering_workflow_lower=} and {dry_run=}")
    try:
        dry_run_bool = bool(strtobool(dry_run))
    except ValueError:
        dry_run_bool = True
    if "upload" in triggering_workflow_lower:
        for bucket in UPLOAD_BUCKETS:
            slack_msg, threaded_message = bucket_upload_results(*bucket)
            threaded_messages.extend(threaded_message)
            slack_msg_append.extend(slack_msg)

        if bigquery_upload_message := construct_slack_message_for_bigquery_content_upload():
            slack_msg_append.append(bigquery_upload_message)

        construct_slack_msg_sync_buckets(threaded_messages, slack_msg_append)
    elif triggering_workflow_lower in ["deploy auto upgrade packs", "override corepacks"] and not dry_run_bool:
        construct_slack_msg_sync_buckets(threaded_messages, slack_msg_append)

    has_failed_tests = False
    # report failing test-playbooks and test modeling rules.
    if triggering_workflow in {CONTENT_NIGHTLY, CONTENT_PR, CONTENT_MERGE}:
        test_playbooks_slack_msg_xsoar, test_playbooks_has_failure_xsoar = test_playbooks_results(
            ARTIFACTS_FOLDER_XSOAR, pipeline_url, title="XSOAR"
        )
        test_playbooks_slack_msg_xsiam, test_playbooks_has_failure_xsiam = test_playbooks_results(
            ARTIFACTS_FOLDER_XSIAM, pipeline_url, title="XSIAM"
        )
        test_modeling_rules_slack_msg_xsiam, test_modeling_rules_has_failure_xsiam = test_modeling_rules_results(
            ARTIFACTS_FOLDER_XSIAM, pipeline_url, title="XSIAM"
        )
        test_use_case_slack_msg_xsiam, test_use_acse_has_failure_xsiam = test_use_case_results(
            ARTIFACTS_FOLDER_XSIAM, pipeline_url, title="XSIAM"
        )
        slack_msg_append += (
            test_playbooks_slack_msg_xsoar
            + test_playbooks_slack_msg_xsiam
            + test_modeling_rules_slack_msg_xsiam
            + test_use_case_slack_msg_xsiam
        )
        has_failed_tests |= (
            test_playbooks_has_failure_xsoar
            or test_playbooks_has_failure_xsiam
            or test_modeling_rules_has_failure_xsiam
            or test_use_acse_has_failure_xsiam
        )
        slack_msg_append += missing_content_packs_test_conf(ARTIFACTS_FOLDER_XSOAR_SERVER_TYPE)
    if triggering_workflow == CONTENT_NIGHTLY:
        # The coverage Slack message is only relevant for nightly and not for PRs.
        slack_msg_append += construct_coverage_slack_msg()

    # Always add the machines used for the tests.
    threaded_messages.extend(machines_saas_and_xsiam(failed_jobs_names))

    title = triggering_workflow

    if file:
        slack_msg_append.extend(read_and_parse(file, f"Failed to read file and parse {file}", slack_msg_append))

    if thread:
        threaded_messages.extend(read_and_parse(thread, f"Failed to read thread file and parse {thread}", slack_msg_append))

    attachments_json = (
        read_and_parse(attachments, f"Failed to read attachments file and parse {attachments}", slack_msg_append)
        if attachments
        else []
    )

    if pull_request:
        pr_number = pull_request.data["number"]
        pr_title = replace_escape_characters(pull_request.data["title"])
        title += f" (PR#{pr_number} - {pr_title})"

    if merge_request:
        mr_number = merge_request.data["iid"]
        mr_title = replace_escape_characters(merge_request.data["title"])
        title += f" (MR#{mr_number} - {mr_title})"

    # In case we have failed tests we override the color only in case all the pipeline jobs have passed.
    if has_failed_tests:
        title_append = " [Has Failed Tests]"
        color = "warning"
    else:
        title_append = ""
        color = "good"

    if pipeline_failed_jobs:
        title += " - Failure"
        color = "danger"
    else:
        title += " - Success"
        # No color is needed in case of success, as it's controlled by the color of the test failures' indicator.

    title += title_append

    return (
        [{"fallback": title, "color": color, "title": title, "title_link": pipeline_url, "fields": content_fields}]
        + slack_msg_append,
        threaded_messages,
        custom_title or title,
        attachments_json,
    )


def read_and_parse(file_path: str, error_title: str, on_error_append_to: list):
    # Read and parse the file, if an error occurs append the error message to the append_to list.
    try:
        return json.loads(Path(file_path).read_text())
    except Exception:
        logging.exception(error_title)
        on_error_append_to.append(
            {
                "fallback": error_title,
                "title": error_title,
                "color": "danger",
            }
        )
    return []


def missing_content_packs_test_conf(artifact_folder: Path) -> list[dict[str, Any]]:
    if missing_packs_list := split_results_file(get_artifact_data(artifact_folder, "missing_content_packs_test_conf.txt")):
        title = f"Notice - Missing packs - ({len(missing_packs_list)})"
        return [
            {
                "fallback": title,
                "color": "warning",
                "title": title,
                "fields": [
                    {
                        "title": "The following packs exist in content-test-conf, but not in content",
                        "value": ", ".join(missing_packs_list),
                        "short": False,
                    }
                ],
            }
        ]
    return []


def collect_pipeline_data(gitlab_client: Gitlab, project_id: str, pipeline_id: str) -> tuple[str, list[ProjectPipelineJob]]:
    project = gitlab_client.projects.get(int(project_id))
    pipeline = project.pipelines.get(int(pipeline_id))

    failed_jobs: list[ProjectPipelineJob] = []
    for job in pipeline.jobs.list(iterator=True):
        logging.info(f"status of gitlab job with id {job.id} and name {job.name} is {job.status}")
        if job.status == "failed":
            logging.info(f"collecting failed job {job.name}")
            logging.info(f"pipeline associated with failed job is {job.pipeline.get('web_url')}")
            failed_jobs.append(job)  # type: ignore[arg-type]

    return pipeline.web_url, failed_jobs


def construct_coverage_slack_msg(sleep_interval: int = 1) -> list[dict[str, Any]]:
    from demisto_sdk.commands.coverage_analyze.tools import get_total_coverage

    coverage_today = get_total_coverage(filename=(ROOT_ARTIFACTS_FOLDER / "coverage_report" / "coverage-min.json").as_posix())
    coverage_yesterday = get_total_coverage(date=datetime.now() - timedelta(days=1))

    # The artifacts are kept for 30 days, so we can get the coverage for the last month.
    # When the coverage file does not exist, we try to import the file from the following day,
    # and the attempt will continue until the day before yesterday.
    for days_ago in range(DAYS_TO_SEARCH, 2, -1):
        if coverage_last_month := get_total_coverage(date=datetime.now() - timedelta(days=days_ago)):
            break
    else:
        coverage_last_month = "no coverage found for last month"

    if isinstance(coverage_last_month, float):  # The coverage file is found
        coverage_last_month = f"{coverage_last_month:.3f}%"

    color = (
        "good"
        if coverage_today >= coverage_yesterday
        or math.isclose(coverage_today, coverage_yesterday, abs_tol=ALLOWED_COVERAGE_PROXIMITY)
        else "danger"
    )
    title = (
        f"Content code coverage: {coverage_today:.3f}% (Yesterday: {coverage_yesterday:.3f}%, Last month: {coverage_last_month})"
    )

    return [
        {
            "fallback": title,
            "color": color,
            "title": title,
        }
    ]


def get_message_p_from_ts(ts):
    return f"p{ts.replace('.', '')}"


def build_link_to_message(channel_id: str, message_ts: str) -> str:
    if SLACK_WORKSPACE_NAME:
        return f"https://{SLACK_WORKSPACE_NAME}.slack.com/archives/{channel_id}/{message_ts}"
    return ""


def channels_to_send_msg(computed_slack_channel):
    if computed_slack_channel in ("dmst-build", CONTENT_CHANNEL):
        return (computed_slack_channel,)
    else:
        return CONTENT_CHANNEL, computed_slack_channel


def write_json_to_file(json_data: Any, file_path: Path) -> None:
    with contextlib.suppress(Exception), open(file_path, "w") as f:
        json.dump(json_data, f, indent=4, sort_keys=True, default=str)
        logging.debug(f"Successfully wrote data to {file_path}")


def get_pipeline_by_id(gitlab_client: Gitlab, project_id: str, pipeline_id: str) -> ProjectPipeline:
    project = gitlab_client.projects.get(int(project_id))
    pipeline = project.pipelines.get(int(pipeline_id))
    return pipeline


def get_slack_downstream_pipeline_id(pipeline: ProjectPipeline):
    for bridge in pipeline.bridges.list(all=True):
        if SLACK_NOTIFY in bridge.name.lower() and bridge.downstream_pipeline:
            pipeline_id = bridge.downstream_pipeline.get("id")
            return pipeline_id
    return None


def get_pipeline_slack_data(gitlab_client: Gitlab, pipeline_id: str, project_id: str) -> tuple[list, list, dict, ProjectPipeline]:
    pipeline = get_pipeline_by_id(gitlab_client, project_id, pipeline_id)
    slack_message = []
    slack_message_threads = []
    slack_message_channel_to_thread = {}
    slack_notify_job = None
    slack_pipeline = None
    if (slack_pipeline_id := get_slack_downstream_pipeline_id(pipeline)) and (
        slack_pipeline := get_pipeline_by_id(gitlab_client, project_id, slack_pipeline_id)
    ):
        for job in slack_pipeline.jobs.list():
            if job.name == SLACK_NOTIFY:
                slack_notify_job = job
                break

    if slack_notify_job and slack_pipeline:
        with tempfile.TemporaryDirectory(dir=ROOT_ARTIFACTS_FOLDER, prefix=SLACK_NOTIFY) as temp_dir:
            artifacts_zip_file = Path(temp_dir) / f"{SLACK_NOTIFY}.zip"
            logging.info(f"Downloading artifacts for slack notify job: {slack_notify_job.id} to file {artifacts_zip_file}")
            gitlab_project = gitlab_client.projects.get(int(slack_pipeline.project_id))
            slack_job_obj = gitlab_project.jobs.get(slack_notify_job.id)
            try:
                with open(artifacts_zip_file, "wb") as f:
                    slack_job_obj.artifacts(streamed=True, action=f.write)
                zip_file = zipfile.ZipFile(artifacts_zip_file)
                temp_zip_dir = Path(temp_dir)
                zip_file.extractall(temp_zip_dir)
                for root, _dirs, files in os.walk(temp_zip_dir, topdown=True):
                    for file in files:
                        if SLACK_MESSAGE in file or OLD_SLACK_MESSAGE in file:
                            slack_message = json.loads((Path(root) / file).read_text())
                        if SLACK_MESSAGE_THREADS in file or OLD_SLACK_MESSAGE_THREADS in file:
                            slack_message_threads = json.loads((Path(root) / file).read_text())
                        if SLACK_MESSAGE_CHANNEL_TO_THREAD in file or OLD_SLACK_MESSAGE_CHANNEL_TO_THREAD in file:
                            slack_message_channel_to_thread = json.loads((Path(root) / file).read_text())
            except GitlabGetError as e:
                logging.error(f"Failed to download artifacts for slack notify job: {slack_notify_job.id} with error: {e}")

    return slack_message, slack_message_threads, slack_message_channel_to_thread, pipeline


def should_send_blacklist_message(
    current_pipeline_id: str, gitlab_client: Gitlab, project_id: str, target_hours: int, target_minutes: int, window_minutes: int
) -> tuple[bool, str]:
    """
    Determines whether a Slack notification should be sent for the blacklist validation pipeline.

    A notification is triggered if:
    - The current time falls within a specified time window (default: ±10 minutes) around a target time (default: 6:00 UTC).
    - A change in secret detection: the previous job found secrets while the current one did not, or vice versa.
    - The blacklist scan artifacts have changed compared to the previous job, even if the job status remains the same
    (e.g., due to a newly discovered secret).

    Args:
        current_pipeline_id (str): The ID of the pipeline that triggered the Slack notifier.
        gitlab_client (Gitlab): The Gitlab client.
        project_id (str): The project id.
        target_hours (int): The starting hour for sending the message.
        target_minutes (int): The starting minute for sending the message.
        window_minutes (int): The range window for sending the message.
    Returns:
        tuple[bool, str]: A boolean indicating whether to send a message, and the corresponding message string.
    """
    # Retrieve recent blacklist validation pipelines
    last_pipelines = get_scheduled_pipelines_by_name(gitlab_client, project_id, BLACKLIST_VALIDATION_PIPELINE, LOOK_BACK_HOURS)

    if len(last_pipelines) < 2:
        logging.info("Insufficient pipeline history for comparison. Exiting.")
        return False, ""

    # Identify the pipeline preceding the current one
    previous_pipeline_id = get_previous_pipeline(last_pipelines, current_pipeline_id)
    if previous_pipeline_id is None:
        logging.info(f"No previous pipeline found for ID {current_pipeline_id}. Exiting.")
        return False, ""

    # Fetch the blacklist validation jobs for the current and previous pipelines
    current_blacklist_job = get_job_by_name(gitlab_client, project_id, current_pipeline_id, BLACKLIST_VALIDATION_JOB)
    previous_blacklist_job = get_job_by_name(gitlab_client, project_id, previous_pipeline_id, BLACKLIST_VALIDATION_JOB)

    if not current_blacklist_job or not previous_blacklist_job:
        logging.info("Could not retrieve blacklist validation jobs. Exiting.")
        return False, ""

    logging.info(f"Comparing artifacts from jobs {current_blacklist_job.id} and {previous_blacklist_job.id}")

    # Pause before downloading artifacts to allow GitLab to finalize them
    logging.info(f"Waiting {SECONDS_TO_SLEEP} seconds before fetching artifacts.")
    time.sleep(SECONDS_TO_SLEEP)

    # Retrieve and compare job artifacts
    current_artifacts = download_and_read_artifact(
        gitlab_client, project_id, current_blacklist_job.id, BLACKLIST_VALIDATION_ARTIFACTS_PATH
    )
    previous_artifacts = download_and_read_artifact(
        gitlab_client, project_id, previous_blacklist_job.id, BLACKLIST_VALIDATION_ARTIFACTS_PATH
    )

    # Check if the message should be sent within the time window
    if is_within_time_window(target_hours, target_minutes, window_minutes):
        status_details = get_blacklist_status_details(current_artifacts)
        return True, f"Daily Heartbeat - {status_details}"

    logging.info("Outside of the scheduled time window. Checking for secret pivots or artifact changes.")

    # Check for significant changes in detected secrets
    if is_blacklist_pivot(current_artifacts, previous_artifacts):
        return True, f"{SECRETS_FOUND}! :warning:"

    if is_blacklist_pivot(current_artifacts, previous_artifacts) is False:
        return True, "Successfully fixed! :muscle:"

    if secrets_sha_has_changed(current_artifacts, previous_artifacts):
        return True, f"The set of detected secrets has changed! {SECRETS_FOUND} :warning:"

    logging.info("No significant changes detected. No notification will be sent.")
    return False, ""


def main():
    install_logging("Slack_Notifier.log")
    options = options_handler()
    triggering_workflow = options.triggering_workflow  # ci workflow type that is triggering the slack notifier
    pipeline_id = options.pipeline_id
    project_id = options.gitlab_project_id
    server_url = options.url
    ci_token = options.ci_token
    computed_slack_channel = options.slack_channel
    gitlab_client = Gitlab(server_url, private_token=ci_token, ssl_verify=GITLAB_SSL_VERIFY)
    slack_token = options.slack_token
    slack_client = WebClient(token=slack_token)
    custom_title = ""
    logging.info(
        f"Sending Slack message for pipeline {pipeline_id} in project {project_id} on server {server_url} "
        f"triggering workflow:'{triggering_workflow}' allowing failure:{options.allow_failure} "
        f"slack channel:{computed_slack_channel} dry run:{options.dry_run}"
    )
    if triggering_workflow == BLACKLIST_VALIDATION:
        should_send_message, custom_title = should_send_blacklist_message(
            pipeline_id, gitlab_client, project_id, options.target_hours, options.target_minutes, options.window_minutes
        )
        # Send a thread message only if secrets have been found
        options.thread = BLACKLIST_VALIDATION_ARTIFACTS_PATH if SECRETS_FOUND in custom_title else None
        if not should_send_message:
            return

    pull_request = None
    merge_request = None

    if options.current_branch != DEFAULT_BRANCH:
        try:
            branch = options.current_branch
            if triggering_workflow == BUCKET_UPLOAD and BUCKET_UPLOAD_BRANCH_SUFFIX in branch:
                branch = branch[: branch.find(BUCKET_UPLOAD_BRANCH_SUFFIX)]
            logging.info(f"Searching for PR/MR for origin branch:{options.current_branch} and calculated branch:{branch}")
            if "cortex-content" in options.repository:
                merge_request = GitlabMergeRequest(
                    ci_token,
                    branch=branch,
                )
                author = merge_request.data.get("author", {}).get("username", "")
                merge_request = merge_request if merge_request.data else None
            else:
                pull_request = GithubPullRequest(
                    options.github_token,
                    repository=options.repository,
                    branch=branch,
                    fail_on_error=True,
                    verify=False,
                )
                author = pull_request.data.get("user", {}).get("login")
                pull_request = pull_request if pull_request.data else None

            if triggering_workflow in {
                CONTENT_NIGHTLY,
                CONTENT_PR,
                CONTENT_DOCS_PR,
                CONTENT_DOCS_NIGHTLY,
                DOCKERFILES_PR,
                RIT_MR,
            }:
                computed_slack_channel = f"@{get_slack_user_name(author, author, options.name_mapping_path)}"
                logging.info(f"Sending slack message to channel {computed_slack_channel} for " f"Author:{author}")
            else:
                logging.info(f"Not supporting custom Slack channel for {triggering_workflow} workflow")
        except Exception as e:
            logging.exception(f"Failed to get PR/MR data for branch {options.current_branch}: {e}")
    else:
        logging.info("Not a pull request build, skipping PR comment")

    pipeline_url, pipeline_failed_jobs = collect_pipeline_data(gitlab_client, project_id, pipeline_id)
    slack_msg_data, threaded_messages, title, attachments_json = construct_slack_msg(
        triggering_workflow,
        pipeline_url,
        pipeline_failed_jobs,
        pull_request,
        merge_request,
        options.file,
        options.attachments,
        options.thread,
        options.dry_run,
        custom_title,
    )

    slack_msg_output_file = ROOT_ARTIFACTS_FOLDER / SLACK_MESSAGE
    logging.info(f"Writing Slack message to {slack_msg_output_file}")
    write_json_to_file(slack_msg_data, slack_msg_output_file)
    threaded_messages_output_file = ROOT_ARTIFACTS_FOLDER / SLACK_MESSAGE_THREADS
    logging.info(f"Writing Slack threaded messages to {threaded_messages_output_file}")
    write_json_to_file(threaded_messages, threaded_messages_output_file)
    channel_to_thread = {}

    # From the test upload flow we only want the Slack message and threads, so we can append them to the current
    # pipeline's messages, we don't care about the channel mapping.
    test_upload_flow_pipeline_id_file = ROOT_ARTIFACTS_FOLDER / TEST_UPLOAD_FLOW_PIPELINE_ID
    if test_upload_flow_pipeline_id_file.exists():
        test_upload_flow_pipeline_id = test_upload_flow_pipeline_id_file.read_text().strip()
        test_upload_flow_slack_message = None
        test_upload_flow_slack_message_threads = None
        try:
            test_upload_flow_slack_message, test_upload_flow_slack_message_threads, _, test_upload_flow_pipeline = (
                get_pipeline_slack_data(gitlab_client, test_upload_flow_pipeline_id, project_id)
            )
            logging.info(f"Got Slack data from test upload flow pipeline: {test_upload_flow_pipeline_id}")
            test_upload_flow_pipeline_title = (
                f"Test Upload Flow Slack message - Pipeline Status:{test_upload_flow_pipeline.status}"
            )
            threaded_messages.append(
                {
                    "title_link": test_upload_flow_pipeline.web_url,
                    "color": "good" if test_upload_flow_pipeline.status == "success" else "danger",
                    "fallback": test_upload_flow_pipeline_title,
                    "title": test_upload_flow_pipeline_title,
                }
            )

            threaded_messages.extend(test_upload_flow_slack_message)
            threaded_messages.extend(test_upload_flow_slack_message_threads)
        except Exception as e:
            logging.exception(f"Failed to get Slack message or threads for test upload flow pipeline, reason: {e}")
        finally:
            if not test_upload_flow_slack_message or not test_upload_flow_slack_message_threads:
                logging.error(
                    f"Failed to get Slack message or threads for test upload flow pipeline: {test_upload_flow_pipeline_id}"
                )
                threaded_messages.append(
                    {
                        "fallback": "Failed to get Slack message or threads for test upload flow pipeline",
                        "title": "Failed to get Slack message or threads for test upload flow pipeline",
                        "color": "danger",
                    }
                )

    # We only need the channel mapping from the parent pipeline, so we can append it to the current pipeline's messages.
    parent_slack_message_channel_to_thread: dict = {}
    if (parent_pipeline_id := os.getenv("SLACK_PARENT_PIPELINE_ID")) and (
        parent_project_id := os.getenv("SLACK_PARENT_PROJECT_ID")
    ):
        logging.info(f"Parent pipeline data found: {parent_pipeline_id} in project {parent_project_id}")
        _, _, parent_slack_message_channel_to_thread, _ = get_pipeline_slack_data(
            gitlab_client, parent_pipeline_id, parent_project_id
        )
        logging.info(f"Got Slack data from parent pipeline: {parent_pipeline_id} in project {parent_project_id}")
    else:
        logging.info("No parent pipeline data found")

    errors = []
    for channel in channels_to_send_msg(computed_slack_channel):
        try:
            parent_thread = parent_slack_message_channel_to_thread.get(channel)
            response = slack_client.chat_postMessage(
                channel=channel,
                attachments=slack_msg_data,
                username=SLACK_USERNAME,
                link_names=True,
                text=title,
                thread_ts=parent_thread,
            )
            data: dict = response.data  # type: ignore[assignment]
            thread_ts: str = data["ts"]
            channel_id = data["channel"]
            channel_to_thread[channel] = thread_ts
            if parent_thread:
                threaded_ts = parent_thread
            else:
                threaded_ts = thread_ts
            if threaded_messages:
                for slack_msg in threaded_messages:
                    slack_client.chat_postMessage(
                        channel=channel,
                        attachments=[slack_msg],
                        username=SLACK_USERNAME,
                        thread_ts=threaded_ts,
                        text=slack_msg.get("title", title),
                    )
            if attachments_json:
                for attachment in attachments_json:
                    slack_client.files_upload_v2(
                        channel=channel_id,
                        thread_ts=threaded_ts,
                        file=attachment["file"],
                        filename=attachment.get("filename"),
                        title=attachment.get("title"),
                        alt_txt=attachment.get("alt_txt"),
                        initial_comment=attachment.get("initial_comment"),
                    )

            if response.status_code == requests.codes.ok:
                link = build_link_to_message(data["channel"], get_message_p_from_ts(threaded_ts))
                logging.info(f"Successfully sent Slack message to channel {channel} link: {link}")
        except Exception:
            if strtobool(options.allow_failure):
                logging.warning(f"Failed to send Slack message to channel {channel} not failing build")
            else:
                logging.exception(f"Failed to send Slack message to channel {channel}")
                errors.append(channel)
    channel_to_thread_output_file = ROOT_ARTIFACTS_FOLDER / SLACK_MESSAGE_CHANNEL_TO_THREAD
    logging.info(f"Writing channel to thread mapping to {channel_to_thread_output_file}")
    write_json_to_file(channel_to_thread, channel_to_thread_output_file)

    if errors:
        logging.error(f"Failed to send Slack message to channels: {', '.join(errors)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
