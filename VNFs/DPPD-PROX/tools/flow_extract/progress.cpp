/*
// Copyright (c) 2010-2017 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include <sys/time.h>
#include <iostream>
#include <cstdio>
#include <sstream>

#include "progress.hpp"

static uint64_t getSec()
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return tv.tv_sec;
}

Progress::Progress(size_t maxProgress, bool inPlace, bool showElapsedTime)
	: maxProgress(maxProgress), curProgress(0), inPlace(inPlace), showElapsedTime(showElapsedTime), prevLength(0), title("Progress")
{
	lastRefresh = -1;
	firstRefresh = getSec();
}

void Progress::setProgress(size_t curProgress)
{
	this->curProgress = curProgress;
}

void Progress::setProgress()
{
	this->curProgress = maxProgress;
}

uint32_t Progress::addDetail(const string& detail)
{
	details.push_back(make_pair(detail, 0));
	return details.size() - 1;
}

void Progress::setDetail(uint32_t idx, uint32_t val)
{
	details[idx].second = val;
}

bool Progress::couldRefresh()
{
	uint32_t cur = getSec();

	return (lastRefresh != cur);
}

void Progress::refresh(bool withNewLine)
{
	lastRefresh = getSec();
	uint64_t elapsed = lastRefresh - firstRefresh;
	size_t progress = curProgress * 100 / maxProgress;
	size_t remainingTime = curProgress? (elapsed * maxProgress - elapsed * curProgress) / curProgress : 0;

	stringstream ss;

	if (inPlace)
		ss << "\r";
	ss << title << ": " << progress << "%";
	ss << ", remaining: " << remainingTime;
	if (showElapsedTime)
		ss << ", elapsed: " << elapsed;
	for (size_t i = 0; i < details.size(); ++i)
		ss << ", " << details[i].first << ": " << details[i].second;

	size_t prevLength2 = ss.str().size();

	while (ss.str().size() < prevLength)
		ss << " ";
	prevLength = prevLength2;

	if (!inPlace || withNewLine)
		ss << "\n";

	cout << ss.str();
	cout.flush();
}
