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

