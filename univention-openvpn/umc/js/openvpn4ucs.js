/*
 * Copyright 2012-2015 Univention GmbH
 *
 * http://www.univention.de/
 *
 * All rights reserved.
 *
 * The source code of this program is made available
 * under the terms of the GNU Affero General Public License version 3
 * (GNU AGPL V3) as published by the Free Software Foundation.
 *
 * Binary versions of this program provided by Univention to you as
 * well as other copyrighted, protected or trademarked materials like
 * Logos, graphics, fonts, specific documentations and configurations,
 * cryptographic keys etc. are subject to a license agreement between
 * you and Univention and not subject to the GNU AGPL V3.
 *
 * In the case you use this program under the terms of the GNU AGPL V3,
 * the program is provided in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License with the Debian GNU/Linux or Univention distribution in file
 * /usr/share/common-licenses/AGPL-3; if not, see
 * <http://www.gnu.org/licenses/>.
 */
/*global define*/

define([
	"dojo/_base/declare",
	"dojo/_base/lang",
	"umc/dialog",
	"umc/widgets/Page",
	"umc/widgets/Form",
	"umc/widgets/Module",
	"umc/widgets/PasswordInputBox",
	"umc/widgets/Button",
	"umc/i18n!umc/modules/openvpn4ucs"
], function(declare, lang, dialog, Page, Form, Module, PasswordInputBox, Button, _) {
	return declare("umc.modules.openvpn4ucs", [ Module ], {
		// summary:
		//		Template module to ease the UMC module development.
		// description:
		//		This module is a template module in order to aid the development of
		//		new modules for Univention Management Console.

		// Set the opacity for the standby animation to 100% in order to mask
		// GUI changes when the module is opened. Call this.standby(true|false)
		// to enabled/disable the animation.
		standbyOpacity: 1,

		postMixInProperties: function() {
			// is called after all inherited properties/methods have been mixed
			// into the object (originates from dijit._Widget)

			// it is important to call the parent's postMixInProperties() method
			this.inherited(arguments);
		},

		buildRendering: function() {
			// is called after all DOM nodes have been setup
			// (originates from dijit._Widget)

			// it is important to call the parent's buildRendering() method
			this.inherited(arguments);

			//
			// form
			//

			// add remaining elements of the search form
//			var widgets = [{
//				type: PasswordInputBox,
//				name: 'password',
//				label: _('New password')
//			}];

			// the layout is an 2D array that defines the organization of the form elements...
			// here we arrange the form elements in one row and add the 'submit' button
//			var layout = [
//				'password'
//			];

			// generate the form
			// submit changes
//			var buttons = [ {
//				name: 'submit',
//				iconClass: 'umcSaveIconWhite',
//				label: _('Generate (Form)'),
//				'default': true,
//				callback: lang.hitch(this, function() {
//					this.onSubmit(this._form.get('value'));
//				})
//			}];

//			this._form = new Form({
//				// property that defines the widget's position
//				widgets: widgets,
//				layout: layout,
//				buttons: buttons
//			});

			this._button = new Button({
				label: _('Generate'),
				callback: lang.hitch(this, function() {
					this.onClick();
				})
			});

			this._page = new Page({
				headerText: this.description,
				helpText: _('Generating a new secret for OpenVPN4UCS SitetoSite')
			});

			this.addChild(this._page);
//			this._page.addChild(this._form);
			this._page.addChild(this._button);
		},

//		onSubmit: function(values) {
//			this.umcpCommand('openvpn4ucs/process_form', values).then(function (response) {
//				dialog.alert(_('Got it: %(password)s for %(username)s', response.result));
//			});
//		},

		onClick: function(values) {
			this.umcpCommand('openvpn4ucs/process_button').then(function (response) {
				dialog.alert(_('New Secret:<br /><br />%s<br />Please copy it to your openvpn sitetosite machines secret textboxes', response.result));
			});
		}
	});
});
