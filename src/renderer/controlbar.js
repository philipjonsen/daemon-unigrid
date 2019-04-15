/*
 * This file is part of The Swipp Wallet
 * Copyright (C) 2019 The Swipp developers <info@swippcoin.com>
 *
 * The Swipp Wallet is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * The Swipp Wallet is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with The Swipp Wallet. If not, see <https://www.gnu.org/licenses/>.
 */

import React from "react";
import { ipcRenderer } from "electron";
import { library } from "@fortawesome/fontawesome-svg-core";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faSpinner, faWindowMinimize, faWindowMaximize, faWindowClose } from "@fortawesome/free-solid-svg-icons";
import "./controlbar.css"

library.add(faSpinner, faWindowMinimize, faWindowMaximize, faWindowClose);

export default class ControlBar extends React.Component {
	constructor(props) {
		super(props);
		this.state = { showSpinner: false };

		ipcRenderer.on("state", (event, message) => {
			this.setState({ showSpinner: (message == "working" ? true : false) });
		});
	}

	render() {
		var onMinimzie = () => {
		}

		var onMaximize = () => {
		}

		var onClose = () => {
			window.close();
		}

		return(
			<div className="controlbar">
				<div>
					<img className="piclet"/>
					<div>{this.props.headerText}</div>
				</div>
				<div>
					{this.state.showSpinner == true &&
						<FontAwesomeIcon className="spinner" icon="spinner" spin/>
					}
					{this.props.fullControls == true &&
						<div>
							<FontAwesomeIcon className="minimize" icon="window-minimize"/>
							<FontAwesomeIcon className="maximize" icon="window-maximize"/>
						</div>
					}
					<FontAwesomeIcon onClick={onClose} className="close" icon="window-close"/>
				</div>
			</div>
		);
	}
}
