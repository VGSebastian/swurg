/**
 * Copyright (C) 2016 Alexandre Teyar
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package swurg.ui;

import burp.IBurpExtenderCallbacks;
import swurg.model.HTTPRequest;
import swurg.utils.DataStructure;

import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JSeparator;
import javax.swing.table.DefaultTableModel;

@SuppressWarnings("serial")
class ContextMenu extends JPopupMenu {
    private DataStructure data;

    ContextMenu(IBurpExtenderCallbacks callbacks) {
        JMenuItem clearAll = new JMenuItem("Clear all");
        clearAll.addActionListener(e -> clear());

        JMenuItem intruder = new JMenuItem("Send to Intruder");
        intruder.addActionListener(e -> {
            int[] rowIndexes = data.getTable().getSelectedRows();

            // Highlighted rows
            for (int rowIndex : rowIndexes) {
                HTTPRequest httpRequest = data.getHTTPRequests().get(rowIndex);

                callbacks.sendToIntruder(httpRequest.getHost(), httpRequest.getPort(), httpRequest.getUseHttps(), httpRequest.getRequest());
            }
        });

        JMenuItem repeater = new JMenuItem("Send to Repeater");
        repeater.addActionListener(e -> {
            int[] rowIndexes = data.getTable().getSelectedRows();

            // Highlighted rows
            for (int rowIndex : rowIndexes) {

                HTTPRequest httpRequest = data.getHTTPRequests().get(rowIndex);
                callbacks.sendToRepeater(httpRequest.getHost(), httpRequest.getPort(), httpRequest.getUseHttps(),
                                         httpRequest.getRequest(), (String) data.getTable().getValueAt(rowIndex, 5)
                );
            }
        });

        JMenuItem scanner = new JMenuItem("Do an active scan");
        scanner.addActionListener(e -> {
            int[] rowIndexes = data.getTable().getSelectedRows();

            // Highlighted rows
            for (int rowIndex : rowIndexes) {
                HTTPRequest httpRequest = data.getHTTPRequests().get(rowIndex);

                callbacks.doActiveScan(httpRequest.getHost(), httpRequest.getPort(), httpRequest.getUseHttps(), httpRequest.getRequest());
            }
        });

        add(scanner);
        add(repeater);
        add(intruder);
        add(new JSeparator());
        add(clearAll);
    }

    void setDataStructure(DataStructure data) {
        this.data = data;
    }

    private void clear() {
        this.data.setFileTextField("");
        this.data.setInfoLabel("Copyright \u00a9 2016 Alexandre Teyar All Rights Reserved");
        DefaultTableModel model = (DefaultTableModel) this.data.getTable().getModel();
        model.setRowCount(0);
        this.data.getHTTPRequests().clear();
    }
}
