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

package org.restcomm.protocols.ss7.cap.service.circuitSwitchedCall.primitive;

import java.io.IOException;

import javolution.xml.XMLFormat;
import javolution.xml.stream.XMLStreamException;

import org.mobicents.protocols.asn.AsnException;
import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.cap.api.CAPException;
import org.restcomm.protocols.ss7.cap.api.CAPParsingComponentException;
import org.restcomm.protocols.ss7.cap.api.CAPParsingComponentExceptionReason;
import org.restcomm.protocols.ss7.cap.api.isup.Digits;
import org.restcomm.protocols.ss7.cap.api.service.circuitSwitchedCall.primitive.VariablePart;
import org.restcomm.protocols.ss7.cap.api.service.circuitSwitchedCall.primitive.VariablePartDate;
import org.restcomm.protocols.ss7.cap.api.service.circuitSwitchedCall.primitive.VariablePartPrice;
import org.restcomm.protocols.ss7.cap.api.service.circuitSwitchedCall.primitive.VariablePartTime;
import org.restcomm.protocols.ss7.cap.isup.DigitsImpl;
import org.restcomm.protocols.ss7.cap.primitives.CAPAsnPrimitive;

/**
 *
 * @author sergey vetyutnev
 *
 */
public class VariablePartImpl implements VariablePart, CAPAsnPrimitive {

    public static final int _ID_integer = 0;
    public static final int _ID_number = 1;
    public static final int _ID_time = 2;
    public static final int _ID_date = 3;
    public static final int _ID_price = 4;

    public static final String _PrimitiveName = "VariablePart";

    private static final String INTEGER = "integer";
    private static final String NUMBER = "number";
    private static final String TIME = "time";
    private static final String DATE = "date";
    private static final String PRICE = "price";

    private Integer integer;
    private Digits number;
    private VariablePartTime time;
    private VariablePartDate date;
    private VariablePartPrice price;

    public VariablePartImpl() {
    }

    public VariablePartImpl(Integer integer) {
        this.integer = integer;
    }

    public VariablePartImpl(Digits number) {
        this.number = number;
    }

    public VariablePartImpl(VariablePartTime time) {
        this.time = time;
    }

    public VariablePartImpl(VariablePartDate date) {
        this.date = date;
    }

    public VariablePartImpl(VariablePartPrice price) {
        this.price = price;
    }

    @Override
    public Integer getInteger() {
        return integer;
    }

    @Override
    public Digits getNumber() {
        return number;
    }

    @Override
    public VariablePartTime getTime() {
        return time;
    }

    @Override
    public VariablePartDate getDate() {
        return date;
    }

    @Override
    public VariablePartPrice getPrice() {
        return price;
    }

    @Override
    public int getTag() throws CAPException {

        if (this.integer != null) {
            return _ID_integer;
        } else if (this.number != null) {
            return _ID_number;
        } else if (this.time != null) {
            return _ID_time;
        } else if (this.date != null) {
            return _ID_date;
        } else if (this.price != null) {
            return _ID_price;
        } else {
            throw new CAPException("Error while encoding " + _PrimitiveName + ": no of choices has been definite");
        }
    }

    @Override
    public int getTagClass() {
        return Tag.CLASS_CONTEXT_SPECIFIC;
    }

    @Override
    public boolean getIsPrimitive() {
        return true;
    }

    @Override
    public void decodeAll(AsnInputStream ansIS) throws CAPParsingComponentException {

        try {
            int length = ansIS.readLength();
            this._decode(ansIS, length);
        } catch (IOException e) {
            throw new CAPParsingComponentException("IOException when decoding " + _PrimitiveName + ": " + e.getMessage(), e,
                    CAPParsingComponentExceptionReason.MistypedParameter);
        } catch (AsnException e) {
            throw new CAPParsingComponentException("AsnException when decoding " + _PrimitiveName + ": " + e.getMessage(), e,
                    CAPParsingComponentExceptionReason.MistypedParameter);
        }
    }

    @Override
    public void decodeData(AsnInputStream ansIS, int length) throws CAPParsingComponentException {

        try {
            this._decode(ansIS, length);
        } catch (IOException e) {
            throw new CAPParsingComponentException("IOException when decoding " + _PrimitiveName + ": " + e.getMessage(), e,
                    CAPParsingComponentExceptionReason.MistypedParameter);
        } catch (AsnException e) {
            throw new CAPParsingComponentException("AsnException when decoding " + _PrimitiveName + ": " + e.getMessage(), e,
                    CAPParsingComponentExceptionReason.MistypedParameter);
        }
    }

    private void _decode(AsnInputStream ais, int length) throws CAPParsingComponentException, IOException, AsnException {

        this.integer = null;
        this.number = null;
        this.time = null;
        this.date = null;
        this.price = null;

        if (ais.getTagClass() != Tag.CLASS_CONTEXT_SPECIFIC || !ais.isTagPrimitive())
            throw new CAPParsingComponentException("Error while decoding " + _PrimitiveName
                    + ": bad tagClass or is not primitive", CAPParsingComponentExceptionReason.MistypedParameter);

        switch (ais.getTag()) {
            case _ID_integer:
                this.integer = (int) ais.readIntegerData(length);
                break;
            case _ID_number:
                this.number = new DigitsImpl();
                ((DigitsImpl) this.number).decodeData(ais, length);
                this.number.setIsGenericDigits();
                break;
            case _ID_time:
                this.time = new VariablePartTimeImpl();
                ((VariablePartTimeImpl) this.time).decodeData(ais, length);
                break;
            case _ID_date:
                this.date = new VariablePartDateImpl();
                ((VariablePartDateImpl) this.date).decodeData(ais, length);
                break;
            case _ID_price:
                this.price = new VariablePartPriceImpl();
                ((VariablePartPriceImpl) this.price).decodeData(ais, length);
                break;
            default:
                throw new CAPParsingComponentException("Error while decoding " + _PrimitiveName + ": bad tag: " + ais.getTag(),
                        CAPParsingComponentExceptionReason.MistypedParameter);
        }
    }

    @Override
    public void encodeAll(AsnOutputStream asnOs) throws CAPException {
        this.encodeAll(asnOs, this.getTagClass(), this.getTag());
    }

    @Override
    public void encodeAll(AsnOutputStream asnOs, int tagClass, int tag) throws CAPException {

        try {
            asnOs.writeTag(tagClass, this.getIsPrimitive(), tag);
            int pos = asnOs.StartContentDefiniteLength();
            this.encodeData(asnOs);
            asnOs.FinalizeContent(pos);
        } catch (AsnException e) {
            throw new CAPException("AsnException when encoding " + _PrimitiveName + ": " + e.getMessage(), e);
        }
    }

    @Override
    public void encodeData(AsnOutputStream asnOs) throws CAPException {

        int choiceCnt = 0;
        if (this.integer != null)
            choiceCnt++;
        if (this.number != null)
            choiceCnt++;
        if (this.time != null)
            choiceCnt++;
        if (this.date != null)
            choiceCnt++;
        if (this.price != null)
            choiceCnt++;

        if (choiceCnt != 1)
            throw new CAPException("Error while encoding " + _PrimitiveName + ": only one choice must be definite, found: "
                    + choiceCnt);

        try {
            if (this.integer != null)
                asnOs.writeIntegerData(this.integer);
            if (this.number != null)
                ((DigitsImpl) this.number).encodeData(asnOs);
            if (this.time != null)
                ((VariablePartTimeImpl) this.time).encodeData(asnOs);
            if (this.date != null)
                ((VariablePartDateImpl) this.date).encodeData(asnOs);
            if (this.price != null)
                ((VariablePartPriceImpl) this.price).encodeData(asnOs);
        } catch (IOException e) {
            throw new CAPException("IOException when encoding " + _PrimitiveName + ": " + e.getMessage(), e);
        }
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();
        sb.append(_PrimitiveName);
        sb.append(" [");

        if (this.integer != null) {
            sb.append("integer=");
            sb.append(integer);
        }
        if (this.number != null) {
            sb.append(" number=");
            sb.append(number.toString());
        }
        if (this.time != null) {
            sb.append(" time=");
            sb.append(time.toString());
        }
        if (this.date != null) {
            sb.append(" date=");
            sb.append(date.toString());
        }
        if (this.price != null) {
            sb.append(" price=");
            sb.append(price.toString());
        }

        sb.append("]");

        return sb.toString();
    }

    /**
     * XML Serialization/Deserialization
     */
    protected static final XMLFormat<VariablePartImpl> VARIABLE_PART_XML = new XMLFormat<VariablePartImpl>(
            VariablePartImpl.class) {

        @Override
        public void read(javolution.xml.XMLFormat.InputElement xml, VariablePartImpl variablePart)
                throws XMLStreamException {
            variablePart.integer = xml.get(INTEGER, Integer.class);
            variablePart.number = xml.get(NUMBER, DigitsImpl.class);
            variablePart.time = xml.get(TIME, VariablePartTimeImpl.class);
            variablePart.date = xml.get(DATE, VariablePartDateImpl.class);
            variablePart.price = xml.get(PRICE, VariablePartPriceImpl.class);

            int choiceCount = 0;
            if (variablePart.integer != null)
                choiceCount++;
            if (variablePart.number != null)
                choiceCount++;
            if (variablePart.time != null)
                choiceCount++;
            if (variablePart.date != null)
                choiceCount++;
            if (variablePart.price != null)
                choiceCount++;

            if (choiceCount != 1)
                throw new XMLStreamException("VariablePart decoding error: there must be one choice selected, found: "
                        + choiceCount);
        }

        @Override
        public void write(VariablePartImpl variablePart, javolution.xml.XMLFormat.OutputElement xml)
                throws XMLStreamException {
            if (variablePart.integer != null)
                xml.add(variablePart.integer, INTEGER, Integer.class);
            if (variablePart.number != null)
                xml.add((DigitsImpl) variablePart.number, NUMBER, DigitsImpl.class);
            if (variablePart.time != null)
                xml.add((VariablePartTimeImpl) variablePart.time, TIME, VariablePartTimeImpl.class);
            if (variablePart.date != null)
                xml.add((VariablePartDateImpl) variablePart.date, DATE, VariablePartDateImpl.class);
            if (variablePart.price != null)
                xml.add((VariablePartPriceImpl) variablePart.price, PRICE, VariablePartPriceImpl.class);
        }
    };
}
