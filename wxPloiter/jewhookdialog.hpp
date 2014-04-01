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
#include "logging.hpp"
#include <wx/wx.h>

namespace wxPloiter
{
	// just an april fools joke dialog
	class jewhookdialog : public wxDialog
	{
	public:
		jewhookdialog(wxWindow *parent);

	protected:
		wxTimer *timer;
		wxGauge *progressbar;
		void OnTimerTimeout(wxTimerEvent& e);
		void OnClose(wxCloseEvent &e);
	};
}

