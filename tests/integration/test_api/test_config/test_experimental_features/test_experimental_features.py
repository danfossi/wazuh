"""
copyright: Copyright (C) 2015-2023, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'experimental_features' setting of the API is working properly.
       This setting allows users to access API endpoints containing features that are under development.
       The Wazuh API is an open source 'RESTful' API that allows for interaction with the Wazuh manager
       from a web browser, command line tool like 'cURL' or any script or program that can make web requests.

components:
    - api

suite: config

targets:
    - manager

daemons:
    - wazuh-apid

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/api/getting-started.html
    - https://documentation.wazuh.com/current/user-manual/api/configuration.html#drop-privileges

tags:
    - api
"""
import os
import pytest
import requests

from wazuh_testing.constants.api import CONFIGURATION_TYPES, SYSCOLLECTOR_OS_ROUTE
from wazuh_testing.constants.daemons import API_DAEMON
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.modules.api.helpers import get_base_url, login


# Marks
pytestmark = pytest.mark.server

# Variables
# Used by add_configuration to select the target configuration file
configuration_type = CONFIGURATION_TYPES[0]

# Paths
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configuration_folder_path = os.path.join(test_data_path, 'configuration_template')
cases_folder_path = os.path.join(test_data_path, 'test_cases')
test_configuration_path = os.path.join(configuration_folder_path, 'configuration_experimental_features.yaml')
test_cases_path = os.path.join(cases_folder_path, 'cases_experimental_features.yaml')

# Configurations
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)
daemons_handler_configuration = {'daemons': [API_DAEMON]}

# Tests

@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_experimental_features(test_configuration, test_metadata, add_configuration, truncate_monitored_files,
                               daemons_handler, wait_for_api_start):
    """
    description: Check if requests to an experimental API endpoint are allowed according
                 to the configuration. For this purpose, it configures the API to use
                 this functionality and makes requests to it, waiting for a correct response.

    wazuh_min_version: 4.2.0

    test_phases:
        - setup:
            - Append configuration to the target configuration files (defined by configuration_type)
            - Truncate the log files
            - Restart daemons defined in `daemons_handler_configuration` in this module
            - Wait until the API is ready to receive requests
        - test:
            - Make a request to a experimental endpoint
            - Check that the response code is the expected
        - teardown:
            - Remove configuration and restore backup configuration
            - Truncate the log files
            - Stop daemons defined in `daemons_handler_configuration` in this module

    tier: 0

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration data from the test case.
        - test_metadata:
            type: dict
            brief: Metadata from the test case.
        - add_configuration:
            type: fixture
            brief: Add configuration to the Wazuh API configuration files.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - daemons_handler:
            type: fixture
            brief: Wrapper of a helper function to handle Wazuh daemons.
        - wait_for_api_start:
            type: fixture
            brief: Monitor the API log file to detect whether it has been started or not.

    assertions:
        - Verify that when 'experimental_features' is enabled, it is possible to access experimental API endpoints.
        - Verify that when 'experimental_features' is disabled, it is not possible to access experimental API endpoints.

    input_description: Different test cases are contained in an external YAML file (cases_experimental_features.yaml)
                       which includes API configuration parameters.

    expected_output:
        - 200 ('OK' HTTP status code if 'experimental_features == true')
        - 404 ('Forbidden' HTTP status code if 'experimental_features == false')
    """
    expected_code = test_metadata['expected_code']
    url = get_base_url() + SYSCOLLECTOR_OS_ROUTE
    authorization_headers, _ = login()

    response = requests.get(url, headers=authorization_headers, verify=False)
    
    assert response.status_code == expected_code, f"Expected status code was {expected_code}, " \
                                                  f"but {response.status_code} was returned.\n" \
                                                  f"Full response: {response.text}"
