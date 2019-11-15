/*
 * TeleStax, Open Source Cloud Communications  Copyright 2012.
 * and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.restcomm.protocols.ss7.tools.simulatorgui.tests.cap;

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.management.Notification;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;

import org.restcomm.protocols.ss7.tools.simulator.tests.cap.TestCapScfManMBean;
import org.restcomm.protocols.ss7.tools.simulatorgui.TestingForm;

/**
 *
 * @author sergey vetyutnev
 *
 */
public class TestCapScfForm extends TestingForm {

    private static final long serialVersionUID = 1917238827266265536L;

    private TestCapScfManMBean capScf;
    private JButton btCloseDialog;
    private JButton btInitiateCallAttempt;
    private JLabel lbState;
    private JButton btApplyCharging;
    private JButton btCancel;
    private JButton btConnect;
    private JButton btContinue;
    private JButton btReleaseCall;
    private JButton btRequestReportBcsmEvent;
    private JPanel panel_1;
    private JLabel lbResult;
    private JButton btConnectToResource;
    private JButton btActivityTest;
    private JButton btPromptAndCollectUserInformation;
    private JButton btFurnishChargingInformation;

    public TestCapScfForm(JFrame owner) {
        super(owner);

        JPanel panel = new JPanel();
        panel_c.add(panel, BorderLayout.NORTH);
        GridBagLayout gbl_panel = new GridBagLayout();
        gbl_panel.columnWidths = new int[] { 0, 0, 0, 0, 0, 0 };
        gbl_panel.rowHeights = new int[] { 0, 0, 0, 0, 0, 0, 0, 0 };
        gbl_panel.columnWeights = new double[] { 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE };
        gbl_panel.rowWeights = new double[] { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE };
        panel.setLayout(gbl_panel);

        btCloseDialog = new JButton("Close Dialog");
        btCloseDialog.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                closeDialog();
            }
        });
        GridBagConstraints gbc_btCloseDialog = new GridBagConstraints();
        gbc_btCloseDialog.insets = new Insets(0, 0, 5, 5);
        gbc_btCloseDialog.gridx = 1;
        gbc_btCloseDialog.gridy = 0;
        panel.add(btCloseDialog, gbc_btCloseDialog);

        btInitiateCallAttempt = new JButton("InitiateCallAttempt");
        btInitiateCallAttempt.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                sendInitiateCallAttempt();
            }
        });
        GridBagConstraints gbc_btInitiateCallAttempt = new GridBagConstraints();
        gbc_btInitiateCallAttempt.insets = new Insets(0, 0, 5, 5);
        gbc_btInitiateCallAttempt.gridx = 2;
        gbc_btInitiateCallAttempt.gridy = 0;
        panel.add(btInitiateCallAttempt, gbc_btInitiateCallAttempt);

        btApplyCharging = new JButton("ApplyCharging");
        btApplyCharging.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                sendApplyCharging();
            }
        });
        GridBagConstraints gbc_btApplyCharging = new GridBagConstraints();
        gbc_btApplyCharging.insets = new Insets(0, 0, 5, 5);
        gbc_btApplyCharging.gridx = 1;
        gbc_btApplyCharging.gridy = 1;
        panel.add(btApplyCharging, gbc_btApplyCharging);

        btCancel = new JButton("Cancel");
        btCancel.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                sendCancel();
            }
        });
        GridBagConstraints gbc_btCancel = new GridBagConstraints();
        gbc_btCancel.insets = new Insets(0, 0, 5, 5);
        gbc_btCancel.gridx = 2;
        gbc_btCancel.gridy = 1;
        panel.add(btCancel, gbc_btCancel);

        btConnect = new JButton("Connect");
        btConnect.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                sendConnect();
            }
        });
        GridBagConstraints gbc_btConnect = new GridBagConstraints();
        gbc_btConnect.insets = new Insets(0, 0, 5, 5);
        gbc_btConnect.gridx = 3;
        gbc_btConnect.gridy = 1;
        panel.add(btConnect, gbc_btConnect);

        btContinue = new JButton("Continue");
        btContinue.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                sendContinue();
            }
        });
        GridBagConstraints gbc_btContinue = new GridBagConstraints();
        gbc_btContinue.insets = new Insets(0, 0, 5, 0);
        gbc_btContinue.gridx = 4;
        gbc_btContinue.gridy = 1;
        panel.add(btContinue, gbc_btContinue);

        btReleaseCall = new JButton("ReleaseCall");
        btReleaseCall.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                sendReleaseCall();
            }
        });
        GridBagConstraints gbc_btReleaseCall = new GridBagConstraints();
        gbc_btReleaseCall.insets = new Insets(0, 0, 5, 5);
        gbc_btReleaseCall.gridx = 1;
        gbc_btReleaseCall.gridy = 2;
        panel.add(btReleaseCall, gbc_btReleaseCall);

        btRequestReportBcsmEvent = new JButton("RequestReportBCSMEvent");
        btRequestReportBcsmEvent.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                sendRequestReportBCSMEvent();
            }
        });
        GridBagConstraints gbc_btRequestReportBcsmEvent = new GridBagConstraints();
        gbc_btRequestReportBcsmEvent.insets = new Insets(0, 0, 5, 5);
        gbc_btRequestReportBcsmEvent.gridx = 2;
        gbc_btRequestReportBcsmEvent.gridy = 2;
        panel.add(btRequestReportBcsmEvent, gbc_btRequestReportBcsmEvent);

        btConnectToResource = new JButton("ConnectToResource");
        btConnectToResource.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                sendConnectToResource();
            }
        });
        btConnectToResource.setEnabled(false);
        GridBagConstraints gbc_btConnectToResource = new GridBagConstraints();
        gbc_btConnectToResource.insets = new Insets(0, 0, 5, 5);
        gbc_btConnectToResource.gridx = 3;
        gbc_btConnectToResource.gridy = 2;
        panel.add(btConnectToResource, gbc_btConnectToResource);

        btActivityTest = new JButton("ActivityTest");
        btActivityTest.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                sendActivityTest();
            }
        });
        btActivityTest.setEnabled(false);
        GridBagConstraints gbc_btActivityTest = new GridBagConstraints();
        gbc_btActivityTest.insets = new Insets(0, 0, 5, 0);
        gbc_btActivityTest.gridx = 4;
        gbc_btActivityTest.gridy = 2;
        panel.add(btActivityTest, gbc_btActivityTest);

        btPromptAndCollectUserInformation = new JButton("PromptAndCollectUserInformation");
        btPromptAndCollectUserInformation.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                sendPromptAndCollectUserInformation();
            }
        });
        btPromptAndCollectUserInformation.setEnabled(false);
        GridBagConstraints gbc_btPromptAndCollectUserInformation = new GridBagConstraints();
        gbc_btPromptAndCollectUserInformation.insets = new Insets(0, 0, 5, 5);
        gbc_btPromptAndCollectUserInformation.gridx = 1;
        gbc_btPromptAndCollectUserInformation.gridy = 3;
        panel.add(btPromptAndCollectUserInformation, gbc_btPromptAndCollectUserInformation);

        btFurnishChargingInformation = new JButton("FurnishChargingInformation");
        btFurnishChargingInformation.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                sendFurnishChargingInformation();
            }
        });
        btFurnishChargingInformation.setEnabled(false);
        GridBagConstraints gbc_btFurnishChargingInformation = new GridBagConstraints();
        gbc_btFurnishChargingInformation.insets = new Insets(0, 0, 5, 5);
        gbc_btFurnishChargingInformation.gridx = 2;
        gbc_btFurnishChargingInformation.gridy = 3;
        panel.add(btFurnishChargingInformation, gbc_btFurnishChargingInformation);

        panel_1 = new JPanel();
        panel_c.add(panel_1, BorderLayout.SOUTH);
        panel_1.setLayout(new BoxLayout(panel_1, BoxLayout.Y_AXIS));

        lbResult = new JLabel("-");
        panel_1.add(lbResult);

        lbState = new JLabel("-");
        panel_1.add(lbState);

        this.setDialogClosed();
    }

    public void setData(TestCapScfManMBean capScf) {
        this.capScf = capScf;
    }

    private void closeDialog() {
        String res = this.capScf.closeCurrentDialog();
        this.lbResult.setText(res);
        setDialogClosed();
    }

    private void setDialogOpenedClosed(boolean opened) {
        this.btInitiateCallAttempt.setEnabled(!opened);

        this.btApplyCharging.setEnabled(opened);
        this.btCancel.setEnabled(opened);
        this.btConnect.setEnabled(opened);
        this.btContinue.setEnabled(opened);
        this.btReleaseCall.setEnabled(opened);
        this.btRequestReportBcsmEvent.setEnabled(opened);
        this.btConnectToResource.setEnabled(opened);
        this.btActivityTest.setEnabled(opened);
        this.btPromptAndCollectUserInformation.setEnabled(opened);
        this.btFurnishChargingInformation.setEnabled(opened);
    }

    private void setDialogOpened() {
        setDialogOpenedClosed(true);
    }

    private void setDialogClosed() {
        setDialogOpenedClosed(false);
    }

    private void sendInitiateCallAttempt() {
        String msg = "";
        String res = this.capScf.performInitiateCallAttempt(msg);
        this.lbResult.setText(res);
    }

    private void sendApplyCharging() {
        String msg = "";
        String res = this.capScf.performApplyCharging(msg);
        this.lbResult.setText(res);
    }

    private void sendCancel() {
        String msg = "";
        String res = this.capScf.performCancel(msg);
        this.lbResult.setText(res);
    }

    private void sendConnect() {
        String msg = "";
        String res = this.capScf.performConnect(msg);
        this.lbResult.setText(res);
    }

    private void sendContinue() {
        String msg = "";
        String res = this.capScf.performContinue(msg);
        this.lbResult.setText(res);
    }

    private void sendReleaseCall() {
        String msg = "";
        String res = this.capScf.performReleaseCall(msg);
        this.lbResult.setText(res);
    }

    private void sendRequestReportBCSMEvent() {
        String msg = "";
        String res = this.capScf.performRequestReportBCSMEvent(msg);
        this.lbResult.setText(res);
    }

    private void sendConnectToResource() {
        String msg = "";
        String res = this.capScf.performConnectToResource(msg);
        this.lbResult.setText(res);
    }

    private void sendActivityTest() {
        String msg = "";
        String res = this.capScf.performActivityTest(msg);
        this.lbResult.setText(res);
    }

    private void sendPromptAndCollectUserInformation() {
        String msg = "";
        String res = this.capScf.performPromptAndCollectUserInformation(msg);
        this.lbResult.setText(res);
    }

    private void sendFurnishChargingInformation() {
        String msg = "";
        String res = this.capScf.performFurnishChargingInformation(msg);
        this.lbResult.setText(res);
    }

    @Override
    public void sendNotif(Notification notif) {
        super.sendNotif(notif);

        if (notif.getMessage().startsWith("DlgClosed:")) {
            this.setDialogClosed();
        }
        if (notif.getMessage().startsWith("DlgStarted:") || notif.getMessage().startsWith("DlgAccepted:")) {
            this.setDialogOpened();
        }
    }

    @Override
    public void refreshState() {
        super.refreshState();

        String s1 = this.capScf.getCurrentRequestDef();
        this.lbState.setText(s1);
    }

}
