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

#ifndef _PROGRESS_H_
#define _PROGRESS_H_

#include <inttypes.h>
#include <vector>
#include <utility>
#include <string>

using namespace std;

class Progress {
public:
	Progress(size_t maxProgress, bool inPlace = true, bool showElapsedTime = true);
	void setTitle(const string &prefix) {this->title = title;}
	void setProgress(size_t curProgress);
	void setProgress();
	uint32_t addDetail(const string& detail);
	void clearDetails() {details.clear();}
	void setDetail(uint32_t idx, uint32_t val);
	bool couldRefresh();
	void refresh(bool withNewLine = false);
private:
	uint64_t firstRefresh;
	uint64_t lastRefresh;
	size_t maxProgress;
	size_t curProgress;
	bool inPlace;
	bool showElapsedTime;
	size_t prevLength;
	string title;
	vector<pair<string, uint32_t> > details;
};

#endif /* _PROGRESS_H_ */
