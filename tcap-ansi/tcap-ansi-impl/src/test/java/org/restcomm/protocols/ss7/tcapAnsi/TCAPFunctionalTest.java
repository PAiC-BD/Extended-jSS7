/*
 * TeleStax, Open Source Cloud Communications
 * Copyright 2012, Telestax Inc and individual contributors
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

package org.restcomm.protocols.ss7.tcapAnsi;

import static org.testng.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.restcomm.protocols.ss7.indicator.RoutingIndicator;
import org.restcomm.protocols.ss7.sccp.impl.SccpHarness;
import org.restcomm.protocols.ss7.sccp.parameter.SccpAddress;
import org.restcomm.protocols.ss7.tcapAnsi.TCAPStackImpl;
import org.restcomm.protocols.ss7.tcapAnsi.api.TCListener;
import org.restcomm.protocols.ss7.tcapAnsi.api.asn.comp.Invoke;
import org.restcomm.protocols.ss7.tcapAnsi.api.asn.comp.ReturnResultLast;
import org.restcomm.protocols.ss7.tcapAnsi.api.tc.dialog.Dialog;
import org.restcomm.protocols.ss7.tcapAnsi.api.tc.dialog.events.TCConversationIndication;
import org.restcomm.protocols.ss7.tcapAnsi.api.tc.dialog.events.TCNoticeIndication;
import org.restcomm.protocols.ss7.tcapAnsi.api.tc.dialog.events.TCPAbortIndication;
import org.restcomm.protocols.ss7.tcapAnsi.api.tc.dialog.events.TCQueryIndication;
import org.restcomm.protocols.ss7.tcapAnsi.api.tc.dialog.events.TCResponseIndication;
import org.restcomm.protocols.ss7.tcapAnsi.api.tc.dialog.events.TCUniIndication;
import org.restcomm.protocols.ss7.tcapAnsi.api.tc.dialog.events.TCUserAbortIndication;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Test for call flow.
 *
 * @author baranowb
 *
 */
public class TCAPFunctionalTest extends SccpHarness {
    public static final long WAIT_TIME = 500;
    private static final int _WAIT_TIMEOUT = 90000;
    private static final int _WAIT_REMOVE = 30000;
    public static final long[] _ACN_ = new long[] { 0, 4, 0, 0, 1, 0, 19, 2 };
    private TCAPStackImpl tcapStack1;
    private TCAPStackImpl tcapStack2;
    private SccpAddress peer1Address;
    private SccpAddress peer2Address;
    private Client client;
    private Server server;
    private TCAPListenerWrapper tcapListenerWrapper;

    public TCAPFunctionalTest() {

    }

    @BeforeClass
    public void setUpClass() {
        this.sccpStack1Name = "TCAPFunctionalTestSccpStack1";
        this.sccpStack2Name = "TCAPFunctionalTestSccpStack2";
        System.out.println("setUpClass");
    }

    @AfterClass
    public void tearDownClass() throws Exception {
        System.out.println("tearDownClass");
    }

    /*
     * (non-Javadoc)
     *
     * @see junit.framework.TestCase#setUp()
     */
    @BeforeMethod
    public void setUp() throws Exception {
        System.out.println("setUp");
        super.setUp();

        peer1Address = super.parameterFactory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, null, 1, 8);
        peer2Address = super.parameterFactory.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, null, 2, 8);

        this.tcapStack1 = new TCAPStackImpl("TCAPFunctionalTest_1", this.sccpProvider1, 8);
        this.tcapStack2 = new TCAPStackImpl("TCAPFunctionalTest_2", this.sccpProvider2, 8);

        this.tcapListenerWrapper = new TCAPListenerWrapper();
        this.tcapStack1.getProvider().addTCListener(tcapListenerWrapper);

        this.tcapStack1.start();
        this.tcapStack2.start();

        this.tcapStack1.setInvokeTimeout(0);
        this.tcapStack2.setInvokeTimeout(0);
        // create test classes
        this.client = new Client(this.tcapStack1, super.parameterFactory, peer1Address, peer2Address);
        this.server = new Server(this.tcapStack2, super.parameterFactory, peer2Address, peer1Address);

    }

    /*
     * (non-Javadoc)
     *
     * @see junit.framework.TestCase#tearDown()
     */
    @AfterMethod
    public void tearDown() {
        this.tcapStack1.stop();
        this.tcapStack2.stop();
        super.tearDown();

    }

    @Test(groups = { "functional.flow" })
    public void simpleTCWithDialogTest() throws Exception {

        long stamp = System.currentTimeMillis();
        List<TestEvent> clientExpectedEvents = new ArrayList<TestEvent>();
        TestEvent te = TestEvent.createSentEvent(EventType.Begin, null, 0, stamp);
        clientExpectedEvents.add(te);
        te = TestEvent.createReceivedEvent(EventType.Continue, null, 1, stamp + WAIT_TIME);
        clientExpectedEvents.add(te);
        te = TestEvent.createSentEvent(EventType.End, null, 2, stamp + WAIT_TIME * 2);
        clientExpectedEvents.add(te);
        // te = TestEvent.createReceivedEvent(EventType.DialogRelease, null, 3,stamp+WAIT_TIME*2+_WAIT_REMOVE);
        te = TestEvent.createReceivedEvent(EventType.DialogRelease, null, 3, stamp + WAIT_TIME * 2);
        clientExpectedEvents.add(te);

        List<TestEvent> serverExpectedEvents = new ArrayList<TestEvent>();
        te = TestEvent.createReceivedEvent(EventType.Begin, null, 0, stamp);
        serverExpectedEvents.add(te);
        te = TestEvent.createSentEvent(EventType.Continue, null, 1, stamp + WAIT_TIME);
        serverExpectedEvents.add(te);
        te = TestEvent.createReceivedEvent(EventType.End, null, 2, stamp + WAIT_TIME * 2);
        serverExpectedEvents.add(te);
        // te = TestEvent.createReceivedEvent(EventType.DialogRelease, null, 3,stamp+WAIT_TIME*2+_WAIT_REMOVE);
        te = TestEvent.createReceivedEvent(EventType.DialogRelease, null, 3, stamp + WAIT_TIME * 2);
        serverExpectedEvents.add(te);

        // ..............................
//        this.saveTrafficInFile();
        // ..............................

        client.startClientDialog();
        assertNotNull(client.dialog.getLocalAddress());
        assertNull(client.dialog.getRemoteDialogId());

        client.sendBegin();
        client.waitFor(WAIT_TIME);

        server.sendContinue(false);
        assertNotNull(server.dialog.getLocalAddress());
        assertNotNull(server.dialog.getRemoteDialogId());

        client.waitFor(WAIT_TIME);
        client.dialog.sendComponent(client.createNewInvoke());
        client.sendEnd(false);
        assertNotNull(client.dialog.getLocalAddress());
        assertNotNull(client.dialog.getRemoteDialogId());

        client.waitFor(WAIT_TIME);
        // waitForEnd();

        client.compareEvents(clientExpectedEvents);
        server.compareEvents(serverExpectedEvents);

    }

    @Test(groups = { "functional.flow" })
    public void uniMsgTest() throws Exception {

        long stamp = System.currentTimeMillis();
        List<TestEvent> clientExpectedEvents = new ArrayList<TestEvent>();
        TestEvent te = TestEvent.createSentEvent(EventType.Uni, null, 0, stamp);
        clientExpectedEvents.add(te);
        te = TestEvent.createReceivedEvent(EventType.DialogRelease, null, 1, stamp);
        clientExpectedEvents.add(te);

        List<TestEvent> serverExpectedEvents = new ArrayList<TestEvent>();
        te = TestEvent.createReceivedEvent(EventType.Uni, null, 0, stamp);
        serverExpectedEvents.add(te);
        te = TestEvent.createReceivedEvent(EventType.DialogRelease, null, 1, stamp);
        serverExpectedEvents.add(te);

        client.startUniDialog();
        client.sendUni();
        client.waitFor(WAIT_TIME);

        client.compareEvents(clientExpectedEvents);
        server.compareEvents(serverExpectedEvents);

    }

    private void waitForEnd() {
        try {
            Thread.currentThread().sleep(_WAIT_TIMEOUT);
        } catch (InterruptedException e) {
            fail("Interrupted on wait!");
        }
    }

    private class TCAPListenerWrapper implements TCListener {

        @Override
        public void onTCUni(TCUniIndication ind) {
            // TODO Auto-generated method stub

        }

        @Override
        public void onTCQuery(TCQueryIndication ind) {
            // TODO Auto-generated method stub

        }

        @Override
        public void onTCConversation(TCConversationIndication ind) {
            assertEquals(ind.getComponents().length, 2);
            ReturnResultLast rrl = (ReturnResultLast) ind.getComponents()[0];
            Invoke inv = (Invoke) ind.getComponents()[1];

            // operationCode is not sent via ReturnResultLast because it does not contain a Parameter
            // so operationCode is taken from a sent Invoke
            assertEquals((long) rrl.getCorrelationId(), 0);
            assertEquals((long) rrl.getOperationCode().getPrivateOperationCode(), 12);

            // second Invoke has its own operationCode and it has linkedId to the second sent Invoke
            assertEquals((long) inv.getInvokeId(), 0);
            assertEquals((long) inv.getOperationCode().getPrivateOperationCode(), 14);
            assertEquals((long) inv.getCorrelationId(), 1);

            // we should see operationCode of the second sent Invoke
            Invoke linkedInv = inv.getCorrelationInvoke();
            assertEquals((long) linkedInv.getOperationCode().getPrivateOperationCode(), 13);
        }

        @Override
        public void onTCResponse(TCResponseIndication ind) {
            // TODO Auto-generated method stub

        }

        @Override
        public void onTCUserAbort(TCUserAbortIndication ind) {
            // TODO Auto-generated method stub

        }

        @Override
        public void onTCPAbort(TCPAbortIndication ind) {
            // TODO Auto-generated method stub

        }

        @Override
        public void onTCNotice(TCNoticeIndication ind) {
            // TODO Auto-generated method stub

        }

        @Override
        public void onDialogReleased(Dialog d) {
            // TODO Auto-generated method stub

        }

        @Override
        public void onInvokeTimeout(Invoke tcInvokeRequest) {
            // TODO Auto-generated method stub

        }

        @Override
        public void onDialogTimeout(Dialog d) {
            // TODO Auto-generated method stub

        }

    }
}
