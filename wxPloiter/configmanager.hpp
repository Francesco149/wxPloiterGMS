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

#include <string>
#include <boost/shared_ptr.hpp>
#include <boost/property_tree/ptree.hpp>

namespace wxPloiter
{
	// simple wrapper around boost property tree to parse ini's
	class configmanager
	{
	public:
		typedef boost::shared_ptr<configmanager> ptr;

		static ptr get();
		virtual ~configmanager();
		void open(const char *filepath);
		void save(const char *filepath);
		
		template <class T>
		T get(const char *prop)
		{
			return pt.get<T>(prop);
		}

		template <class T>
		T get(const char *prop, T defvalue)
		{
			return pt.get(prop, defvalue);
		}

		template <class T>
		void set(const char *prop, T value)
		{
			pt.put(prop, value);
		}

		void clear();

	protected:
		static ptr inst;
		boost::property_tree::ptree pt;

		configmanager();
	};
}
