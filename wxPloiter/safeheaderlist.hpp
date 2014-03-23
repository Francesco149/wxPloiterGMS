/*
	Copyright 2014 Francesco "Franc[e]sco" Noferi (francesco149@gmail.com)

	This file is part of wxPloiter.

	wxPloiter is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	wxPloiter is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with wxPloiter. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "common.h"

#include <set>
#include <vector>
#include <boost/thread/mutex.hpp>

namespace wxPloiter
{
	// a thread-safe header list
	class safeheaderlist
	{
	public:
		typedef boost::shared_ptr<safeheaderlist> ptr; // shared ptr to a safeheaderlist instance

		// TODO: join all static lists into a single list to improve performance?
		// or would it just deadlock because of even more mutex concurrency?

		// TODO: thread safety is not required for ignored headers. move them to simpler lists
		// to improve performance

		// TODO: add const correctness to this class

		static ptr getblockedsend();
		static ptr getblockedrecv();
		static ptr getignoredsend();
		static ptr getignoredrecv();

		safeheaderlist();
		safeheaderlist(safeheaderlist &other);
		virtual ~safeheaderlist();
		std::string tostring();
		void push_back(word header); // thread safe push_back
		void erase(word header); // thread safe erase
		bool contains(word header); // checks if the list contains the given header. thread safe
		void copy(std::set<word> &dst);
		void copy(std::vector<word> &dst);
		void copy(safeheaderlist *dst);
		void clear();
		size_t size();
		word &at(long index);

	protected:
		static ptr blockedsend; // blocked send headers list
		static ptr blockedrecv; // blocked recv headers list
		static ptr ignoredsend; // ignored send headers list
		static ptr ignoredrecv; // ignored recv headers list

		std::set<word> v; // internal set
		std::vector<word> iv; // internal vector for index-based stuff
		boost::mutex mut; // mutex for thread safety

		static ptr getsingleton(ptr &pinstance);
	};
}
