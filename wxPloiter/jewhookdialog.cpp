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

#include "jewhookdialog.hpp"
#include <wx/gauge.h>
#include <wx/timer.h>
#include <wx/panel.h>
#include <wx/sizer.h>
#include <wx/button.h>
#include "mainform.hpp"

namespace wxPloiter
{
	jewhookdialog::jewhookdialog(wxWindow *parent)
		: wxDialog(parent, wxID_ANY, "Installing jewhook...", wxDefaultPosition, wxSize(400, 70))
	{
		wxPanel *basepanel = new wxPanel(this);
		wxBoxSizer *basesizer = new wxBoxSizer(wxVERTICAL);

		Bind(wxEVT_CLOSE_WINDOW, &mainform::OnClose, this);

		progressbar = new wxGauge(basepanel, wxID_ANY, 100);
		
		timer = new wxTimer(this);
		Bind(wxEVT_TIMER, &jewhookdialog::OnTimerTimeout, this);
		timer->Start(50);

		basesizer->Add(progressbar, 1, wxALL | wxEXPAND, 10);
		basepanel->SetAutoLayout(true);
		basepanel->SetSizer(basesizer);
		basepanel->Layout(); // fixes the layout snapping into place after the first resize

		Centre();
		ShowModal();
	}

	void jewhookdialog::OnTimerTimeout(wxTimerEvent& e)
	{
		int v = progressbar->GetValue();

		if (v >= 100)
		{
			timer->Stop();	
			this->Close(true);
			wxString ver = wxString::Format("%s %s", app::appname, app::appver);
			wxMessageBox("Jewhook successfully installed! thanks for donating "
				"your accounts to Franc[e]sco", ver, wxICON_INFORMATION | wxOK, this);
			return;
		}

		progressbar->SetValue(v + 1);
	}

	void jewhookdialog::OnClose(wxCloseEvent &e)
	{
		e.Veto();
	}
}
