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

#include "configmanager.hpp"
#include "checksumhack.hpp"
#include <boost/property_tree/ini_parser.hpp>

namespace wxPloiter
{
	configmanager::ptr configmanager::inst;

	configmanager::configmanager()
	{
		CHECKSUM_HACK()
		// rofltacos
	}

	configmanager::~configmanager()
	{
		CHECKSUM_HACK()
		// rofltacos
	}

	configmanager::ptr configmanager::get()
	{
		CHECKSUM_HACK()
		if (!inst.get())
			inst.reset(new configmanager);

		return inst;
	}

	void configmanager::open(const char *filepath)
	{
		CHECKSUM_HACK()
		pt.clear();
		boost::property_tree::ini_parser::read_ini(filepath, pt);
	}

	void configmanager::save(const char *filepath)
	{
		CHECKSUM_HACK()
		boost::property_tree::write_ini(filepath, pt);
	}

	void configmanager::clear()
	{
		CHECKSUM_HACK()
		pt.clear();
	}
}
