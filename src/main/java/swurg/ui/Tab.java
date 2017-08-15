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
import burp.ITab;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import swurg.model.*;
import swurg.process.Loader;
import swurg.utils.DataStructure;
import swurg.utils.Parser;

import javax.swing.*;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumnModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class Tab implements ITab {
    private PrintWriter stderr;

    private ContextMenu contextMenu;
    private JLabel      infoLabel;
    private JPanel      container;
    private JTable      table;
    private JTextField  fileTextField;

    private int rowIndex = 1;

    private List<HTTPRequest> HTTPRequests;

    public Tab(IBurpExtenderCallbacks callbacks) {
        contextMenu = new ContextMenu(callbacks);
        HTTPRequests = new ArrayList<>();
        stderr = new PrintWriter(callbacks.getStderr(), true);

        // main container
        container = new JPanel();
        container.setLayout(new BorderLayout());
        container.add(drawJFilePanel(), BorderLayout.NORTH);
        container.add(drawJScrollTable());
        container.add(drawJInfoPanel(), BorderLayout.SOUTH);
    }

    private JPanel drawJFilePanel() {
        JPanel panel = new JPanel();
        JLabel label = new JLabel("Parse file:");
        fileTextField = new JTextField("", 48);
        JButton button = new JButton("File");

        fileTextField.setEditable(false);
        button.addActionListener(new ButtonListener());

        panel.add(label);
        panel.add(fileTextField);
        panel.add(button);

        return panel;
    }

    private void processFile() {
        JFileChooser fileChooser = new JFileChooser();

        FileFilter filterJson = new FileNameExtensionFilter("Swagger JSON File (*.json)", "json");
        fileChooser.addChoosableFileFilter(filterJson);

        fileChooser.setFileFilter(filterJson);

        int result = fileChooser.showOpenDialog(container);

        if (result == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();

            fileTextField.setText(file.getName());

            infoLabel.setForeground(Color.BLACK);
            infoLabel.setText(null);

            try {
                Loader loader = new Loader();
                REST   API    = loader.process(file);

                if (API.getHost() == null) {
                    String host = JOptionPane.showInputDialog("Missing 'host' field. Please enter one below.\nFormat: <host>");
                    API.setHost(host);
                }

                String infoText = "Title: " + API.getInfo().getTitle() + " | " +
                                  "Version: " + API.getInfo().getVersion() + " | " +
                                  "Swagger Version: " + API.getSwaggerVersion();

                infoLabel.setText(infoText);

                populateJTable(API);
            } catch (Exception ex) {
                StringWriter stringWriter = new StringWriter();

                ex.printStackTrace(new PrintWriter(stringWriter));
                stderr.println(stringWriter.toString());

                infoLabel.setForeground(Color.RED);
                infoLabel.setText("A fatal error occured, please check the logs for further information");
            }
        }
    }

    @SuppressWarnings("serial")
    private JScrollPane drawJScrollTable() {
        Object columns[] = {
            "#",
            "Method",
            "Host",
            "Protocol",
            "Base Path",
            "Endpoint",
            "Params"
        };
        Object rows[][] = {};
        table = new JTable(new DefaultTableModel(rows, columns) {
            @Override
            public boolean isCellEditable(int rows, int columns) {
                return false;
            }
        });

        JScrollPane scrollPane = new JScrollPane(table);

        table.setSelectionForeground(Color.BLACK);
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                int selectedRow = table.rowAtPoint(e.getPoint());

                if (selectedRow >= 0 && selectedRow < table.getRowCount()) {
                    if (!table.getSelectionModel().isSelectedIndex(selectedRow)) {
                        table.setRowSelectionInterval(selectedRow, selectedRow);
                    }
                }

                if (e.isPopupTrigger() && e.getComponent() instanceof JTable) {
                    this.show(e);
                }
            }

            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger() && e.getComponent() instanceof JTable) {
                    this.show(e);
                }
            }

            private void show(MouseEvent e) {
                DataStructure data = new DataStructure(
                    table,
                    HTTPRequests,
                    fileTextField,
                    infoLabel
                );

                contextMenu.setDataStructure(data);
                contextMenu.show(e.getComponent(), e.getX(), e.getY());
            }
        });

        return scrollPane;
    }

    private void populateJTable(REST API) {
        List<Scheme> schemes = new ArrayList<>();

        if (API.getSchemes() == null || API.getSchemes().isEmpty()) {
            String protocol;

            do {
                protocol = JOptionPane.showInputDialog("Missing 'schemes' field. Please enter one below (accepted values: HTTP, HTTPS).\nFormat: <protocol>");
            } while (!(protocol.toUpperCase().equals("HTTP") || protocol.toUpperCase().equals("HTTPS")));

            schemes.add(new Scheme(protocol.toUpperCase()));
        } else {
            for (String protocol : API.getSchemes()) { schemes.add(new Scheme(protocol)); }
        }

        DefaultTableModel model = (DefaultTableModel) table.getModel();

        // Drop the port number if present
        String       host        = API.getHost().split(":")[0];
        String       basePath    = API.getBasePath();
        List<String> consumes    = API.getConsumes();
        List<String> produces    = API.getProduces();
        JsonObject   definitions = API.getDefinitions();

        Gson   gson   = new Gson();
        Parser parser = new Parser();

        for (Scheme scheme : schemes) {
            for (Map.Entry<String, JsonElement> path : API.getPaths().entrySet()) {
                String endpoint = path.getKey();
                String URL      = basePath + endpoint;

                for (Map.Entry<String, JsonElement> entry : path.getValue().getAsJsonObject().entrySet()) {
                    Path   call       = gson.fromJson(entry.getValue(), Path.class);
                    String HTTPMethod = entry.getKey().toUpperCase();
                    call.setType(HTTPMethod);

                    List<Parameter> params = call.getParameters();

                    // Overwrite 'consume' and 'produces' per call
                    if (call.getConsumes() != null) {
                        consumes = call.getConsumes();
                    }

                    if (call.getProduces() != null) {
                        produces = call.getProduces();
                    }

                    model.addRow(new Object[]{
                                     this.rowIndex,
                                     HTTPMethod,
                                     host,
                                     scheme.getProtocol(),
                                     basePath,
                                     endpoint,
                                     parser.parseParams(params)
                                 }
                    );

                    resizeColumnWidth(table);

                    this.HTTPRequests.add(parser.BurpHTTPRequest(HTTPMethod, URL, host, scheme.getPort(),
                                                                 scheme.getEncryption(), params,
                                                                 definitions, consumes, produces
                    ));

                    this.rowIndex++;
                }
            }
        }
    }

    private void resizeColumnWidth(JTable table) {
        final TableColumnModel columnModel = table.getColumnModel();

        for (int column = 0; column < table.getColumnCount(); column++) {
            int width = 16; // Min width

            for (int row = 0; row < table.getRowCount(); row++) {
                TableCellRenderer renderer = table.getCellRenderer(row, column);
                Component         comp     = table.prepareRenderer(renderer, row, column);
                width = Math.max(comp.getPreferredSize().width + 1, width);
            }

            if (width > 300) {
                width = 300;
            }

            columnModel.getColumn(column).setPreferredWidth(width);
        }
    }

    private JPanel drawJInfoPanel() {
        JPanel panel = new JPanel();
        infoLabel = new JLabel("Copyright \u00a9 2016 Alexandre Teyar All Rights Reserved");

        panel.add(infoLabel);

        return panel;
    }

    @Override
    public Component getUiComponent() {
        return container;
    }

    @Override
    public String getTabCaption() {
        return "Swagger Parser";
    }

    class ButtonListener implements ActionListener {
        ButtonListener() {
            super();
        }

        public void actionPerformed(ActionEvent e) {
            if (e.getSource() instanceof JButton) {
                processFile();
            }
        }
    }
}
