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

#include "headerdialog.hpp"

#include <wx/panel.h>
#include <wx/sizer.h>
#include <wx/textctrl.h>
#include <wx/button.h>
#include <wx/combobox.h>

#include "common.h"
#include "checksumhack.hpp"
#include "packet.hpp"
#include "utils.hpp"

namespace wxPloiter
{
	// {{{
	// headerlist begin
	headerlist::headerlist(wxWindow *parent)
		: wxListView(parent, wxID_ANY, wxDefaultPosition,
			wxDefaultSize, wxLC_REPORT | wxLC_VIRTUAL)
	{
		CHECKSUM_HACK()
		SetItemCount(0); // initialize the listview as empty

		const int tacos = 70;
		AppendColumn("header", wxLIST_FORMAT_LEFT, tacos);
		AppendColumn("direction", wxLIST_FORMAT_LEFT, tacos);
		AppendColumn("action", wxLIST_FORMAT_LEFT, tacos);

		SetFont(wxFont(8, wxFONTFAMILY_MODERN, wxFONTSTYLE_NORMAL, 
			wxFONTWEIGHT_NORMAL, false, "Consolas"));
	}

	headerlist::~headerlist()
	{
		CHECKSUM_HACK()
		// empty
	}

	wxString headerlist::OnGetItemText(long item, long column) const
	{
		CHECKSUM_HACK()
		wxString dir, action;
		safeheaderlist::ptr list;

		// iterates:
		// - blocked recv
		// - blocked send
		// - ignored recv
		// - ignored send

		size_t s1 = safeheaderlist::getblockedrecv()->size();
		size_t s2 = s1 + safeheaderlist::getblockedsend()->size();
		size_t s3 = s2 + safeheaderlist::getignoredrecv()->size();
		size_t s4 = s3 + safeheaderlist::getignoredsend()->size();

		if (static_cast<size_t>(item) < s1)
		{
			dir = wxString("<");
			action = wxString("block");
			list = safeheaderlist::getblockedrecv();
		}

		else if (static_cast<size_t>(item) < s2)
		{
			dir = wxString(">");
			action = wxString("block");
			list = safeheaderlist::getblockedsend();
			item -= s1;
		}

		else if (static_cast<size_t>(item) < s3)
		{
			dir = wxString("<");
			action = wxString("ignore");
			list = safeheaderlist::getignoredrecv();
			item -= s2;
		}

		else if (static_cast<size_t>(item) < s4)
		{
			dir = wxString(">");
			action = wxString("ignore");
			list = safeheaderlist::getignoredsend();
			item -= s3;
		}
		else
			assert(false); // should never happen

		byte byte1 = list->at(item) & 0x00FF;
		byte byte2 = (list->at(item) & 0xFF00) >> 8;

		switch (column)
		{
		case 0:
			return wxString::Format("%02X %02X", byte1, byte2);

		case 1:
			return dir;

		case 2:
			return action;

		default:
			assert(false); // should never happen
		}

		return "wut";
	}

	void headerlist::refreshsize()
	{
		CHECKSUM_HACK()
		size_t s1 = safeheaderlist::getblockedrecv()->size();
		size_t s2 = safeheaderlist::getblockedsend()->size();
		size_t s3 = safeheaderlist::getignoredrecv()->size();
		size_t s4 = safeheaderlist::getignoredsend()->size();
		SetItemCount(s1 + s2 + s3 + s4);
		Refresh();
	}
	// headerlist end
	// }}}

	const std::string headerdialog::tag = "wxPloiter::headerdialog";

	headerdialog::headerdialog(wxWindow *parent)
		: wxDialog(parent, wxID_ANY, "Header list", wxDefaultPosition, wxSize(300, 350)), 
		log(utils::logging::get())
	{
		CHECKSUM_HACK()
		wxPanel *basepanel = new wxPanel(this);
		wxBoxSizer *panelsizer = new wxBoxSizer(wxVERTICAL);

		Bind(wxEVT_CLOSE_WINDOW, &headerdialog::OnClose, this);

		wxStaticBoxSizer *headersbox = new wxStaticBoxSizer(wxVERTICAL,
			basepanel, "Header List");
		{
			wxStaticBox *box = headersbox->GetStaticBox();

			// controls
			headers = new headerlist(box);
			wxButton *removeheader = new wxButton(box, wxID_ANY, "Remove");
			removeheader->Bind(wxEVT_COMMAND_BUTTON_CLICKED, &headerdialog::OnRemoveClicked, this);

			// add controls to sizer
			headersbox->Add(headers, 1, wxALL | wxEXPAND, 10);
			headersbox->Add(removeheader, 0, wxBOTTOM | wxLEFT | wxRIGHT | wxEXPAND, 10);
		}

		wxStaticBoxSizer *utilsbox = new wxStaticBoxSizer(wxVERTICAL,
			basepanel, "Utilities");
		{
			wxStaticBox *box = utilsbox->GetStaticBox();

			headertext = new wxTextCtrl(box, wxID_ANY, "C8 00");
			headertext->SetFont(headers->GetFont());

			wxBoxSizer *buttons = new wxBoxSizer(wxHORIZONTAL);
			{
				wxButton *addb = new wxButton(box, wxID_ANY, "Add");

				wxArrayString choices;
				choices.Add("Block Send");
				choices.Add("Block Recv");
				choices.Add("Ignore Send");
				choices.Add("Ignore Recv");
				combobox = new wxComboBox(box, wxID_ANY, "Block Send", wxDefaultPosition, 
					wxDefaultSize, choices, wxCB_READONLY);

				addb->Bind(wxEVT_COMMAND_BUTTON_CLICKED, &headerdialog::OnAddClicked, this);
				buttons->Add(addb, 0, wxTOP | wxALIGN_CENTER_VERTICAL | wxEXPAND, 5);
				buttons->Add(combobox, 0, wxTOP | wxLEFT | wxALIGN_CENTER_VERTICAL, 5);
			}

			utilsbox->Add(headertext, 0, wxLEFT | wxRIGHT | wxTOP | wxEXPAND, 10);
			utilsbox->Add(buttons, 0, wxLEFT | wxRIGHT | wxBOTTOM, 10);
		}

		panelsizer->Add(headersbox, 1, wxALL | wxEXPAND, 10);
		panelsizer->Add(utilsbox, 0, wxLEFT | wxRIGHT | wxBOTTOM | wxEXPAND, 10);
		basepanel->SetSizer(panelsizer);
	}

	void headerdialog::refresh()
	{
		CHECKSUM_HACK()
		headers->refreshsize();
	}

	void headerdialog::OnClose(wxCloseEvent &e)
	{
		CHECKSUM_HACK()
		e.Veto();
		Hide();
	}

	void headerdialog::OnAddClicked(wxCommandEvent &e)
	{
		CHECKSUM_HACK()
		if (headertext->GetValue().IsEmpty())
			wxLogError("Please enter a header.");

		maple::packet p;
		safeheaderlist::ptr list;

		// TODO: do not compare string like a noob and use index

		if (combobox->GetValue().Cmp("Block Send") == 0)
			list = safeheaderlist::getblockedsend();

		else if (combobox->GetValue().Cmp("Block Recv") == 0)
			list = safeheaderlist::getblockedrecv();

		else if (combobox->GetValue().Cmp("Ignore Send") == 0)
			list = safeheaderlist::getignoredsend();

		else if (combobox->GetValue().Cmp("Ignore Recv") == 0)
			list = safeheaderlist::getignoredrecv();

		try
		{
			p.append_data(headertext->GetValue().ToStdString());
			log->i(tag, strfmt() << "OnAddClicked: " << combobox->GetValue().ToStdString() << " " << p.tostring());
			list->push_back(*reinterpret_cast<word *>(p.raw()));
			headers->refreshsize();
		}
		catch (std::exception &e)
		{
			wxLogError("Invalid header: %s.", wxString(e.what()));
		}

	}

	void headerdialog::OnRemoveClicked(wxCommandEvent &e)
	{
		CHECKSUM_HACK()
		long sel = headers->GetFirstSelected();

		if (sel == -1)
			return;

		try
		{
			wxString dir = headers->GetItemText(sel, 1);
			wxString action = headers->GetItemText(sel, 2);
			safeheaderlist::ptr dalist;

			// TODO: avoid ghetto string checks

			if (dir.Cmp("<") == 0)
			{
				if (action.Cmp("block") == 0)
					dalist = safeheaderlist::getblockedrecv();

				else
					dalist = safeheaderlist::getignoredrecv();
			}

			else
			{
				if (action.Cmp("block") == 0)
					dalist = safeheaderlist::getblockedsend();

				else
					dalist = safeheaderlist::getignoredsend();
			}

			maple::packet p;
			p.append_data(headers->GetItemText(sel).ToStdString());
			dalist->erase(*reinterpret_cast<word *>(p.raw()));
			headers->refreshsize();
			
		}
		catch (std::exception &e)
		{
			wxLogError("Something went wrong: %s.", wxString(e.what()));
		}
	}
}
