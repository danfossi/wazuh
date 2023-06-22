/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 14, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "APIDownloader_test.hpp"
#include "APIDownloader.hpp"
#include "updaterContext.hpp"
#include "gtest/gtest.h"
#include <filesystem>

/*
 * @brief Tests the instantiation of the APIDownloader class
 */
TEST_F(APIDownloaderTest, instantiation)
{
    // Check that the APIDownloader class can be instantiated
    EXPECT_NO_THROW(std::make_shared<APIDownloader>());
}

/**
 * @brief Tests handle a valid request with raw data.
 */
TEST_F(APIDownloaderTest, HandleValidRequestWithRawData)
{
    m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;

    testing::internal::CaptureStdout();

    EXPECT_NO_THROW(m_spAPIDownloader->handleRequest(m_spUpdaterContext));

    const auto capturedOutput {testing::internal::GetCapturedStdout()};

    EXPECT_EQ(capturedOutput, "APIDownloader - Download done successfully\n");\
    EXPECT_FALSE(m_spUpdaterContext->data.empty());
}

/**
 * @brief Tests handle a valid request with compressed data.
 */
TEST_F(APIDownloaderTest, HandleValidRequestWithCompressedData)
{
    m_spUpdaterBaseContext->configData["url"] = "https://filesamples.com/samples/code/json/sample1.json";
    m_spUpdaterBaseContext->configData["compressionType"] = "xz";
    m_spUpdaterBaseContext->outputFolder = "/tmp";

    m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;

    testing::internal::CaptureStdout();

    EXPECT_NO_THROW(m_spAPIDownloader->handleRequest(m_spUpdaterContext));

    const auto capturedOutput {testing::internal::GetCapturedStdout()};
    const auto filePath {static_cast<std::string>(m_spUpdaterContext->spUpdaterBaseContext->outputFolder) + "/" +
                         m_spUpdaterContext->spUpdaterBaseContext->configData.at("fileName").get<std::string>()};

    EXPECT_EQ(capturedOutput, "APIDownloader - Download done successfully\n");
    EXPECT_TRUE(m_spUpdaterContext->data.empty());
    EXPECT_TRUE(std::filesystem::exists(filePath));
}

/**
 * @brief Tests handle a valid request with compressed data and invalid output folder.
 */
TEST_F(APIDownloaderTest, HandleValidRequestWithCompressedDataAndInvalidOutputFolder)
{
    m_spUpdaterBaseContext->configData["url"] = "https://filesamples.com/samples/code/json/sample1.json";
    m_spUpdaterBaseContext->configData["compressionType"] = "xz";

    m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;

    testing::internal::CaptureStdout();

    EXPECT_THROW(m_spAPIDownloader->handleRequest(m_spUpdaterContext), std::runtime_error);

    const auto capturedOutput {testing::internal::GetCapturedStdout()};

    EXPECT_EQ(capturedOutput, "APIDownloader - Could not get response from API because: Failed to open output file\n");
    EXPECT_TRUE(m_spUpdaterContext->data.empty());
}

/**
 * @brief Tests handle an empty url.
 */
TEST_F(APIDownloaderTest, HandleAnEmptyUrl)
{
    m_spUpdaterBaseContext->configData["url"] = "";

    m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;

    testing::internal::CaptureStdout();

    EXPECT_THROW(m_spAPIDownloader->handleRequest(m_spUpdaterContext), std::runtime_error);

    const auto capturedOutput {testing::internal::GetCapturedStdout()};

    EXPECT_EQ(capturedOutput,
              "APIDownloader - Could not get response from API because: URL using bad/illegal format or missing URL\n");
}

/**
 * @brief Tests handle an invalid url.
 */
TEST_F(APIDownloaderTest, HandleAnInvalidUrl)
{
    m_spUpdaterBaseContext->configData["url"] = "localhost/invalid-url";

    m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;

    testing::internal::CaptureStdout();

    EXPECT_THROW(m_spAPIDownloader->handleRequest(m_spUpdaterContext), std::runtime_error);

    const auto capturedOutput {testing::internal::GetCapturedStdout()};

    EXPECT_EQ(capturedOutput, "APIDownloader - Could not get response from API because: Couldn't connect to server\n");
}
