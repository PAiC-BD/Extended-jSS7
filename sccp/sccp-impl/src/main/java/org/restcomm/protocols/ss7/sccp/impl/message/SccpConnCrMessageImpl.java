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

package org.restcomm.protocols.ss7.sccp.impl.message;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.restcomm.protocols.ss7.sccp.LongMessageRuleType;
import org.restcomm.protocols.ss7.sccp.SccpProtocolVersion;
import org.restcomm.protocols.ss7.sccp.impl.SccpStackImpl;
import org.restcomm.protocols.ss7.sccp.impl.parameter.CreditImpl;
import org.restcomm.protocols.ss7.sccp.impl.parameter.HopCounterImpl;
import org.restcomm.protocols.ss7.sccp.impl.parameter.ImportanceImpl;
import org.restcomm.protocols.ss7.sccp.impl.parameter.LocalReferenceImpl;
import org.restcomm.protocols.ss7.sccp.impl.parameter.ProtocolClassImpl;
import org.restcomm.protocols.ss7.sccp.impl.parameter.SccpAddressImpl;
import org.restcomm.protocols.ss7.sccp.message.ParseException;
import org.restcomm.protocols.ss7.sccp.message.SccpConnCrMessage;
import org.restcomm.protocols.ss7.sccp.parameter.Credit;
import org.restcomm.protocols.ss7.sccp.parameter.HopCounter;
import org.restcomm.protocols.ss7.sccp.parameter.Importance;
import org.restcomm.protocols.ss7.sccp.parameter.LocalReference;
import org.restcomm.protocols.ss7.sccp.parameter.Parameter;
import org.restcomm.protocols.ss7.sccp.parameter.ParameterFactory;
import org.restcomm.protocols.ss7.sccp.parameter.ProtocolClass;
import org.restcomm.protocols.ss7.sccp.parameter.SccpAddress;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class SccpConnCrMessageImpl extends SccpAddressedMessageImpl implements SccpConnCrMessage {
    protected LocalReference sourceLocalReferenceNumber;
    protected ProtocolClass protocolClass;
    protected Credit credit;
    protected byte[] userData;
    protected Importance importance;

    public SccpConnCrMessageImpl(int sls, int localSsn, SccpAddress calledParty, SccpAddress callingParty, HopCounter hopCounter) {
        super(130, MESSAGE_TYPE_CR, sls, localSsn, calledParty, callingParty, hopCounter);
    }

    public SccpConnCrMessageImpl(int incomingOpc, int incomingDpc, int incomingSls, int networkId) {
        super(130, MESSAGE_TYPE_CR, incomingOpc, incomingDpc, incomingSls, networkId);
    }

    @Override
    public LocalReference getSourceLocalReferenceNumber() {
        return sourceLocalReferenceNumber;
    }

    @Override
    public void setSourceLocalReferenceNumber(LocalReference sourceLocalReferenceNumber) {
        this.sourceLocalReferenceNumber = sourceLocalReferenceNumber;
    }

    @Override
    public ProtocolClass getProtocolClass() {
        return protocolClass;
    }

    @Override
    public void setProtocolClass(ProtocolClass protocolClass) {
        this.protocolClass = protocolClass;
    }

    @Override
    public Credit getCredit() {
        return credit;
    }

    @Override
    public void setCredit(Credit credit) {
        this.credit = credit;
    }

    @Override
    public byte[] getUserData() {
        return userData;
    }

    @Override
    public void setUserData(byte[] userData) {
        this.userData = userData;
    }

    @Override
    public Importance getImportance() {
        return importance;
    }

    @Override
    public void setImportance(Importance importance) {
        this.importance = importance;
    }

    @Override
    public void decode(InputStream in, ParameterFactory factory, SccpProtocolVersion sccpProtocolVersion) throws ParseException {
        try {
            byte[] buffer = new byte[3];
            in.read(buffer);
            LocalReferenceImpl ref = new LocalReferenceImpl();
            ref.decode(buffer, factory, sccpProtocolVersion);
            sourceLocalReferenceNumber = ref;

            buffer = new byte[1];
            in.read(buffer);
            ProtocolClassImpl protocol = new ProtocolClassImpl();
            protocol.decode(buffer, factory, sccpProtocolVersion);
            protocolClass = protocol;

            int cpaPointer = in.read() & 0xFF;
            in.mark(in.available());

            in.skip(cpaPointer - 1);
            int len = in.read() & 0xff;

            buffer = new byte[len];
            in.read(buffer);

            calledParty = createAddress(buffer, factory, sccpProtocolVersion);

            in.reset();

            int pointer = in.read() & 0xff;
            in.mark(in.available());

            if (pointer == 0) {
                // we are done
                return;
            }
            if (pointer - 1 != in.skip(pointer - 1)) {
                throw new IOException("Not enough data in buffer");
            }

            int paramCode = 0;
            // EOP
            while ((paramCode = in.read() & 0xFF) != 0) {
                if (paramCode != Credit.PARAMETER_CODE
                        && paramCode != SccpAddress.CGA_PARAMETER_CODE
                        && paramCode != Parameter.DATA_PARAMETER_CODE
                        && paramCode != HopCounter.PARAMETER_CODE
                        && paramCode != Importance.PARAMETER_CODE) {
                    throw new ParseException(String.format("Code %d is not supported for CR message", paramCode));
                }
                len = in.read() & 0xff;
                buffer = new byte[len];
                in.read(buffer);
                decodeOptional(paramCode, buffer, sccpProtocolVersion, factory);
            }
        } catch (IOException e) {
            throw new ParseException(e);
        }
    }

    @Override
    public EncodingResultData encode(SccpStackImpl sccpStackImpl, LongMessageRuleType longMessageRuleType, int maxMtp3UserDataLength, Logger logger, boolean removeSPC, SccpProtocolVersion sccpProtocolVersion) throws ParseException {
        try {
            if (type == 0) {
                return new EncodingResultData(EncodingResult.MessageTypeMissing, null, null, null);
            }
            if (sourceLocalReferenceNumber == null) {
                return new EncodingResultData(EncodingResult.SourceLocalReferenceNumberMissing, null, null, null);
            }
            if (protocolClass == null) {
                return new EncodingResultData(EncodingResult.ProtocolClassMissing, null, null, null);
            }
            if (calledParty == null) {
                return new EncodingResultData(EncodingResult.CalledPartyAddressMissing, null, null, null);
            }

            byte[] cdp = ((SccpAddressImpl) calledParty).encode(sccpStackImpl.isRemoveSpc(), sccpStackImpl.getSccpProtocolVersion());
            byte[] cnp = new byte[0];
            if (callingParty != null) {
                cnp = ((SccpAddressImpl) callingParty).encode(sccpStackImpl.isRemoveSpc(), sccpStackImpl.getSccpProtocolVersion());
            }

            byte[] slr = ((LocalReferenceImpl) sourceLocalReferenceNumber).encode(sccpStackImpl.isRemoveSpc(), sccpStackImpl.getSccpProtocolVersion());
            byte[] protocol = ((ProtocolClassImpl) protocolClass).encode(sccpStackImpl.isRemoveSpc(), sccpStackImpl.getSccpProtocolVersion());
            byte[] bf = new byte[0];
            if (userData != null) {
                bf = userData;
            }

            int fieldsLen = MessageUtil.calculateCrFieldsLengthWithoutData(cdp.length, credit != null, cnp.length,
                    hopCounter != null, importance != null);
            int availLen = maxMtp3UserDataLength - fieldsLen;

            if (availLen > 130)
                availLen = 130;

            if (bf.length > availLen) {
                if (logger.isEnabledFor(Level.WARN)) {
                    logger.warn(String.format(
                            "Failure when sending a CR message: message is too long. SccpMessageSegment=%s", this));
                }
                return new EncodingResultData(EncodingResult.SegmentationNotSupported, null, null, null);
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream(fieldsLen + bf.length);

            out.write(type);
            out.write(slr);
            out.write(protocol);

            // we have 2 pointers (cdp, optionals), cdp starts after 2 octets then
            int len = 2;
            out.write(len); //cdp pointer

            boolean optionalPresent = false;
            if (credit != null || callingParty != null || userData != null || hopCounter != null || importance != null) {
                len += cdp.length;
                out.write(len); // optionals pointer

                optionalPresent = true;
            } else {
                // in case there is no optional
                out.write(0);
            }

            out.write(cdp.length);
            out.write(cdp);

            if (credit != null) {
                out.write(Credit.PARAMETER_CODE);
                byte[] b = ((CreditImpl)credit).encode(removeSPC, sccpProtocolVersion);
                out.write(b.length);
                out.write(b);
            }
            if (callingParty != null) {
                out.write(SccpAddress.CGA_PARAMETER_CODE);
                byte[] b = ((SccpAddressImpl)callingParty).encode(removeSPC, sccpProtocolVersion);
                out.write(b.length);
                out.write(b);
            }
            if (userData != null) {
                out.write(Parameter.DATA_PARAMETER_CODE);
                out.write(userData.length);
                out.write(userData);
            }
            if (hopCounter != null) {
                out.write(HopCounter.PARAMETER_CODE);
                byte[] b = ((HopCounterImpl)hopCounter).encode(removeSPC, sccpProtocolVersion);
                out.write(b.length);
                out.write(b);
            }
            if (importance != null) {
                out.write(Importance.PARAMETER_CODE);
                byte[] b = ((ImportanceImpl)importance).encode(removeSPC, sccpProtocolVersion);
                out.write(b.length);
                out.write(b);
            }

            if (optionalPresent) {
                out.write(0x00);
            }

            return new EncodingResultData(EncodingResult.Success, out.toByteArray(), null, null);
        } catch (IOException e) {
            throw new ParseException(e);
        }
    }

    protected void decodeOptional(int code, byte[] buffer, final SccpProtocolVersion sccpProtocolVersion, ParameterFactory factory) throws ParseException {
        switch (code) {
            case Credit.PARAMETER_CODE:
                CreditImpl cred = new CreditImpl();
                cred.decode(buffer, factory, sccpProtocolVersion);
                credit = cred;
                break;

            case SccpAddress.CGA_PARAMETER_CODE:
                SccpAddressImpl address = new SccpAddressImpl();
                address.decode(buffer, factory, sccpProtocolVersion);
                callingParty = address;
                break;

            case SccpAddress.CDA_PARAMETER_CODE:
                SccpAddressImpl address2 = new SccpAddressImpl();
                address2.decode(buffer, factory, sccpProtocolVersion);
                calledParty = address2;
                break;

            case Parameter.DATA_PARAMETER_CODE:
                userData = buffer;
                break;

            case HopCounter.PARAMETER_CODE:
                HopCounterImpl counter = new HopCounterImpl(buffer[0]);
                hopCounter = counter;
                break;

            case Importance.PARAMETER_CODE:
                ImportanceImpl imp = new ImportanceImpl();
                imp.decode(buffer, null, sccpProtocolVersion);
                importance = imp;
                break;

            default:
                throw new ParseException("Unknown optional parameter code: " + code);
        }
    }

    protected SccpAddress createAddress(byte[] buffer, ParameterFactory factory, SccpProtocolVersion sccpProtocolVersion) throws ParseException {
        SccpAddressImpl addressImpl = new SccpAddressImpl();
        addressImpl.decode(buffer, factory, sccpProtocolVersion);
        return addressImpl;
    }

    public boolean reduceHopCounter() {
        if (this.hopCounter != null) {
            int val = this.hopCounter.getValue();
            if (--val <= 0) {
                val = 0;
            }
            ((HopCounterImpl)this.hopCounter).setValue(val);
            if (val == 0)
                return false;
        }
        return true;
    }

    public boolean getSccpCreatesSls() {
        return false;
    }

    @Override
    public boolean getReturnMessageOnError() {
        throw new IllegalStateException();
    }

    @Override
    public void clearReturnMessageOnError() {
        throw new IllegalStateException();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();

        sb.append("Sccp Msg [Type=CR");
        sb.append(" networkId=");
        sb.append(this.networkId);
        sb.append(" sls=");
        sb.append(this.sls);
        sb.append(" incomingOpc=");
        sb.append(this.incomingOpc);
        sb.append(" incomingDpc=");
        sb.append(this.incomingDpc);
        sb.append(" outgoingDpc=");
        sb.append(this.outgoingDpc);
        sb.append(" CallingAddress(");
        sb.append(this.callingParty);
        sb.append(") CalledParty(");
        sb.append(this.calledParty);
        sb.append(")");
        sb.append(" DataLen=");
        if (this.userData != null)
            sb.append(this.userData.length);

        sb.append(" sourceLR=");
        if (this.sourceLocalReferenceNumber != null)
            sb.append(this.sourceLocalReferenceNumber.getValue());
        sb.append(" protocolClass=");
        if (this.protocolClass != null)
            sb.append(this.protocolClass.getProtocolClass());
        sb.append(" credit=");
        if (this.credit != null)
            sb.append(this.credit.getValue());
        sb.append(" importance=");
        if (this.importance != null)
            sb.append(this.importance.getValue());
        sb.append(" hopCounter=");
        if (this.hopCounter != null)
            sb.append(this.hopCounter.getValue());
        sb.append(" isMtpOriginated=");
        sb.append(this.isMtpOriginated);

        sb.append("]");

        return sb.toString();
    }
}
