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
#include "safeheaderlist.hpp"
#include "logging.hpp"
#include <wx/wx.h>
#include <wx/listctrl.h>

namespace wxPloiter
{
	// virtual listview of blocked/ignored headers
	class headerlist : public wxListView
	{
	public:
		headerlist(wxWindow *parent);
		virtual ~headerlist();

		// fires when the listview is being drawn, it's used by wxListView to obtain
		// the text for the given item and column
		wxString OnGetItemText(long item, long column) const;

		void refreshsize();
	};

	class headerdialog : public wxDialog
	{
	public:
		headerdialog(wxWindow *parent);
		void refresh();

	protected:
		static const std::string tag;

		boost::shared_ptr<utils::logging> log;
		headerlist *headers; // header listview
		wxTextCtrl *headertext;
		wxComboBox *combobox;

		void OnClose(wxCloseEvent &e);
		void OnAddClicked(wxCommandEvent &e);
		void OnRemoveClicked(wxCommandEvent &e);
	};
}

