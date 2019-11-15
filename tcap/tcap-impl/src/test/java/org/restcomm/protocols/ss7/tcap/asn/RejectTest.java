/*
 * JBoss, Home of Professional Open Source
 * Copyright 2011, Red Hat, Inc. and individual contributors
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

package org.restcomm.protocols.ss7.tcap.asn;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import java.io.IOException;
import java.util.Arrays;

import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.restcomm.protocols.ss7.tcap.asn.EncodeException;
import org.restcomm.protocols.ss7.tcap.asn.ParseException;
import org.restcomm.protocols.ss7.tcap.asn.TcapFactory;
import org.restcomm.protocols.ss7.tcap.asn.comp.Component;
import org.restcomm.protocols.ss7.tcap.asn.comp.ComponentType;
import org.restcomm.protocols.ss7.tcap.asn.comp.GeneralProblemType;
import org.restcomm.protocols.ss7.tcap.asn.comp.InvokeProblemType;
import org.restcomm.protocols.ss7.tcap.asn.comp.Problem;
import org.restcomm.protocols.ss7.tcap.asn.comp.ProblemType;
import org.restcomm.protocols.ss7.tcap.asn.comp.Reject;
import org.testng.annotations.Test;

/**
 *
 * @author sergey vetyutnev
 *
 */
@Test(groups = { "asn" })
public class RejectTest {

    private byte[] getData() {
        return new byte[] { (byte) 164, 6, 2, 1, 1, (byte) 129, 1, 2 };
    }

    private byte[] getDataNullInvokeId() {
        return new byte[] { -92, 5, 5, 0, -128, 1, 0 };
    }

    @Test(groups = { "functional.decode" })
    public void testDecode() throws IOException, ParseException {

        byte[] b = getData();
        AsnInputStream asnIs = new AsnInputStream(b);
        Component comp = TcapFactory.createComponent(asnIs);

        assertEquals(ComponentType.Reject, comp.getType(), "Wrong component Type");
        Reject rej = (Reject) comp;
        assertEquals(new Long(1), rej.getInvokeId(), "Wrong invoke ID");
        Problem prb = rej.getProblem();
        assertEquals(ProblemType.Invoke, prb.getType());
        assertEquals(InvokeProblemType.MistypedParameter, prb.getInvokeProblemType());

        b = getDataNullInvokeId();
        asnIs = new AsnInputStream(b);
        comp = TcapFactory.createComponent(asnIs);

        assertEquals(ComponentType.Reject, comp.getType(), "Wrong component Type");
        rej = (Reject) comp;
        assertNull(rej.getInvokeId());
        prb = rej.getProblem();
        assertEquals(ProblemType.General, prb.getType());
        assertEquals(GeneralProblemType.UnrecognizedComponent, prb.getGeneralProblemType());
    }

    @Test(groups = { "functional.encode" })
    public void testEncode() throws IOException, EncodeException {

        byte[] expected = this.getData();
        Reject rej = TcapFactory.createComponentReject();
        rej.setInvokeId(1L);
        Problem prb = TcapFactory.createProblem(ProblemType.Invoke);
        prb.setInvokeProblemType(InvokeProblemType.MistypedParameter);
        rej.setProblem(prb);

        AsnOutputStream asnos = new AsnOutputStream();
        rej.encode(asnos);
        byte[] encodedData = asnos.toByteArray();
        assertTrue(Arrays.equals(expected, encodedData));

        expected = this.getDataNullInvokeId();
        rej = TcapFactory.createComponentReject();
        prb = TcapFactory.createProblem(ProblemType.General);
        prb.setGeneralProblemType(GeneralProblemType.UnrecognizedComponent);
        rej.setProblem(prb);

        asnos = new AsnOutputStream();
        rej.encode(asnos);
        encodedData = asnos.toByteArray();
        assertTrue(Arrays.equals(expected, encodedData));
    }
}
