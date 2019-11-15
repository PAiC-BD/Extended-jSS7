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

package org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation;

import javax.xml.bind.DatatypeConverter;

import javolution.xml.XMLFormat;
import javolution.xml.stream.XMLStreamException;

import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.restcomm.protocols.ss7.map.api.MAPException;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.EUtranCgi;
import org.restcomm.protocols.ss7.map.primitives.OctetStringBase;
import org.restcomm.protocols.ss7.map.primitives.TbcdString;

import java.io.IOException;

/**
 * @author <a href="mailto:fernando.mendioroz@gmail.com"> Fernando Mendioroz </a>
 */
public class EUtranCgiImpl extends OctetStringBase implements EUtranCgi {

    private static final String MCC = "mcc";
    private static final String MNC = "mnc";
    private static final String ENB = "enb";
    private static final String CI = "cellId";

    private static final int DEFAULT_INT_VALUE = 0;
    private static final String DATA = "data";

    private static final String DEFAULT_VALUE = null;

    public EUtranCgiImpl() {
        super(7, 7, "EUtranCgi");
    }

    public EUtranCgiImpl(byte[] data) {
        super(7, 7, "EUtranCgi", data);
    }

    public byte[] getData() {
        return data;
    }

    public void setData(int mcc, int mnc, long eci) throws MAPException {
        if (mcc < 1 || mcc > 999)
            throw new MAPException("Bad MCC value");
        if (mnc < 0 || mnc > 999)
            throw new MAPException("Bad MNC value");

        this.data = new byte[7];

        StringBuilder sb = new StringBuilder();
        StringBuilder sb2 = new StringBuilder();
        if (mcc < 100)
            sb.append("0");
        if (mcc < 10)
            sb.append("0");
        sb.append(mcc);

        if (mnc < 100) {
            if (mnc < 10)
                sb2.append("0");
            sb2.append(mnc);
        } else {
            sb.append(mnc % 10);
            sb2.append(mnc / 10);
        }

        AsnOutputStream asnOs = new AsnOutputStream();
        TbcdString.encodeString(asnOs, sb.toString());
        System.arraycopy(asnOs.toByteArray(), 0, this.data, 0, 2);

        asnOs = new AsnOutputStream();
        TbcdString.encodeString(asnOs, sb2.toString());
        System.arraycopy(asnOs.toByteArray(), 0, this.data, 2, 1);

        data[3] = (byte) (eci / 65536);
        data[4] = (byte) (eci % 65536);
        data[5] = (byte) (eci / 256);
        data[6] = (byte) (eci % 256);
    }

    public int getMCC() throws Exception {

        if (data == null)
            throw new MAPException("Data must not be empty");
        if (data.length != 7)
            throw new MAPException("Data length must equal 7");

        AsnInputStream ansIS = new AsnInputStream(data);
        String res = null;
        try {
            res = TbcdString.decodeString(ansIS, 3);
        } catch (IOException e) {
            throw new IOException("IOException when decoding EUtranCgi: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new Exception("Parsing Component Exception when decoding EUtranCgi: " + e.getMessage(), e);
        }

        if (res.length() < 5 || res.length() > 6)
            throw new MAPException("Decoded TbcdString must equal 5 or 6");

        String sMcc = res.substring(0, 3);

        return Integer.parseInt(sMcc);
    }

    public int getMNC() throws Exception {

        if (data == null)
            throw new MAPException("Data must not be empty");
        if (data.length != 7)
            throw new MAPException("Data length must be equal 7");

        AsnInputStream ansIS = new AsnInputStream(data);
        String res = null;
        try {
            res = TbcdString.decodeString(ansIS, 3);
        } catch (IOException e) {
            throw new IOException("IOException when decoding EUtranCgi: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new Exception("Parsing Component Exception when decoding EUtranCgi: " + e.getMessage(), e);
        }

        if (res.length() < 5 || res.length() > 6)
            throw new MAPException("Decoded TbcdString must equal 5 or 6");

        String sMnc;
        if (res.length() == 5) {
            sMnc = res.substring(3);
        } else {
            sMnc = res.substring(4) + res.substring(3, 4);
        }

        return Integer.parseInt(sMnc);
    }

    public long getENodeBId() throws MAPException {

        if (data == null)
            throw new MAPException("Data must not be empty");
        if (data.length != 7)
            throw new MAPException("Data length must equal 7");

        long eNodeBId = (data[3] & 0xFF) * 65536 + (data[4] & 0xFF) * 256 + (data[5] & 0xFF);
        return eNodeBId;
    }

    public int getCi() throws MAPException {

        if (data == null)
            throw new MAPException("Data must not be empty");
        if (data.length != 7)
            throw new MAPException("Data length must equal 7");

        int ci = (data[6] & 0xFF);
        return ci;
    }

    @Override
    public String toString() {

        int mcc = 0;
        int mnc = 0;
        long enb = 0;
        int ci = 0;
        boolean correctData = false;

        try {
            try {
                mcc = this.getMCC();
                mnc = this.getMNC();
            } catch (Exception e) {
                e.printStackTrace();
            }
            enb = this.getENodeBId();
            ci = this.getCi();
            correctData = true;
        } catch (MAPException e) {
        }

        StringBuilder sb = new StringBuilder();
        sb.append(this._PrimitiveName);
        sb.append(" [");
        if (correctData) {
            sb.append(MCC+"=");
            sb.append(mcc);
            sb.append(", "+MNC+"=");
            sb.append(mnc);
            sb.append(", "+ENB+"=");
            sb.append(enb);
            sb.append(", "+CI+"=");
            sb.append(ci);
        } else {
            sb.append("Data=");
            sb.append(this.printDataArr());
        }
        sb.append("]");

        return sb.toString();
    }

    /**
     * XML Serialization/Deserialization
     */
    protected static final XMLFormat<EUtranCgiImpl> E_UTRAN_CGI_XML = new XMLFormat<EUtranCgiImpl>(EUtranCgiImpl.class) {

        @Override
        public void read(javolution.xml.XMLFormat.InputElement xml, EUtranCgiImpl eUtranCgi) throws XMLStreamException {
            String s = xml.getAttribute(DATA, DEFAULT_VALUE);
            if (s != null) {
                eUtranCgi.data = DatatypeConverter.parseHexBinary(s);
            }
        }

        @Override
        public void write(EUtranCgiImpl eUtranCgi, javolution.xml.XMLFormat.OutputElement xml) throws XMLStreamException {
            if (eUtranCgi.data != null) {
                xml.setAttribute(DATA, DatatypeConverter.printHexBinary(eUtranCgi.data));
            }
        }
    };
}

