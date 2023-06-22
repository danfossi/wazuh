/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 08, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _API_DOWNLOADER_TEST_HPP
#define _API_DOWNLOADER_TEST_HPP

#include "APIDownloader.hpp"
#include "updaterContext.hpp"
#include "gtest/gtest.h"
#include <memory>

/**
 * 
 * @brief Runs component tests for APIDownloader
 */
class APIDownloaderTest : public ::testing::Test
{
protected:
    APIDownloaderTest() = default;
    ~APIDownloaderTest() override = default;

    std::shared_ptr<UpdaterContext> m_spUpdaterContext; ///< UpdaterContext used on the merge pipeline.

    std::shared_ptr<UpdaterBaseContext> m_spUpdaterBaseContext; ///< UpdaterBaseContext used on the merge pipeline.

    std::shared_ptr<APIDownloader> m_spAPIDownloader; ///< APIDownloader used to download the content.

    /**
     * @brief Sets initial conditions for each test case.
     *
     */
    // cppcheck-suppress unusedFunction
    void SetUp() override
    {
        m_spAPIDownloader = std::make_shared<APIDownloader>();
        // Create a updater context
        m_spUpdaterContext = std::make_shared<UpdaterContext>();
        m_spUpdaterBaseContext = std::make_shared<UpdaterBaseContext>();
        m_spUpdaterBaseContext->configData = R"(
            {
                "contentSource": "api",
                "compressionType": "raw",
                "versionedContent": "false",
                "deleteDownloadedContent": false,
                "url": "https://swapi.dev/api/people/1",
                "outputFolder": "",
                "dataFormat": "json",
                "fileName": "sample1.json",
                "apiParameters": {
                    "itemsPerRequest": {
                    "name": "limit",
                    "value": 100
                    },
                    "offset": {
                    "name": "offset",
                    "step": 100,
                    "start": 0
                    }
                }
            }
        )"_json;
    }
};

#endif //_API_DOWNLOADER_TEST_HPP
