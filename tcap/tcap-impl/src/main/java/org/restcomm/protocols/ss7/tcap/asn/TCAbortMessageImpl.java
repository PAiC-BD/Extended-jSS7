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

package org.restcomm.protocols.ss7.tcap.asn;

import java.io.IOException;

import org.mobicents.protocols.asn.AsnException;
import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.restcomm.protocols.ss7.tcap.asn.comp.PAbortCauseType;
import org.restcomm.protocols.ss7.tcap.asn.comp.TCAbortMessage;

/**
 * @author amit bhayani
 * @author baranowb
 * @author sergey vetyutnev
 *
 */
public class TCAbortMessageImpl implements TCAbortMessage {

    private static final String _OCTET_STRING_ENCODE = "US-ASCII";

    private byte[] destTxId;
    private PAbortCauseType type;
    private DialogPortion dp;

    /*
     * (non-Javadoc)
     *
     * @seeorg.restcomm.protocols.ss7.tcap.asn.comp.TCAbortMessage# getDestinationTransactionId()
     */
    public byte[] getDestinationTransactionId() {

        return destTxId;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.tcap.asn.comp.TCAbortMessage#getDialogPortion ()
     */
    public DialogPortion getDialogPortion() {

        return dp;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.tcap.asn.comp.TCAbortMessage#getPAbortCause()
     */
    public PAbortCauseType getPAbortCause() {

        return type;
    }

    /*
     * (non-Javadoc)
     *
     * @seeorg.restcomm.protocols.ss7.tcap.asn.comp.TCAbortMessage# setDestinationTransactionId()
     */
    public void setDestinationTransactionId(byte[] t) {
        this.destTxId = t;

    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.tcap.asn.comp.TCAbortMessage#setDialogPortion
     * (org.restcomm.protocols.ss7.tcap.asn.DialogPortion)
     */
    public void setDialogPortion(DialogPortion dp) {
        this.dp = dp;
        this.type = null;

    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.tcap.asn.comp.TCAbortMessage#setPAbortCause
     * (org.restcomm.protocols.ss7.tcap.asn.comp.PAbortCauseType)
     */
    public void setPAbortCause(PAbortCauseType t) {
        this.type = t;
        this.dp = null;

    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.tcap.asn.Encodable#decode(org.mobicents.protocols .asn.AsnInputStream)
     */
    public void decode(AsnInputStream ais) throws ParseException {
        try {
            AsnInputStream localAis = ais.readSequenceStream();

            int tag = localAis.readTag();
            if (tag != _TAG_DTX || localAis.getTagClass() != Tag.CLASS_APPLICATION)
                throw new ParseException(PAbortCauseType.IncorrectTxPortion, null,
                        "Error decoding TC-Abort: Expected DestinationTransactionId, found tag: " + tag);
            this.destTxId = localAis.readOctetString();

            if (localAis.available() == 0)
                return;
            tag = localAis.readTag();
            if (localAis.getTagClass() != Tag.CLASS_APPLICATION)
                throw new ParseException(PAbortCauseType.IncorrectTxPortion, null,
                        "Error decoding TC-Abort: DialogPortion and P-AbortCause portion must has tag class CLASS_APPLICATION");

            switch (tag) {
                case DialogPortion._TAG:
                    if (localAis.isTagPrimitive())
                        throw new ParseException(PAbortCauseType.IncorrectTxPortion, null,
                                "Error decoding TC-End: DialogPortion must be constructive");
                    this.dp = TcapFactory.createDialogPortion(localAis);
                    break;

                case _TAG_P:
                    // primitive?
                    this.type = PAbortCauseType.getFromInt((int) localAis.readInteger());
                    break;

                default:
                    throw new ParseException(PAbortCauseType.IncorrectTxPortion, null,
                            "Error decoding TC-Abort: bad tag while parsing DialogPortion and P-AbortCause portion: " + tag);
            }

            if (localAis.available() > 0)
                throw new ParseException(PAbortCauseType.IncorrectTxPortion, null, "Error decoding TC-Abort: too mych data");

        } catch (IOException e) {
            throw new ParseException(PAbortCauseType.BadlyFormattedTxPortion, null, "IOException while decoding TC-Abort: "
                    + e.getMessage(), e);
        } catch (AsnException e) {
            throw new ParseException(PAbortCauseType.BadlyFormattedTxPortion, null, "AsnException while decoding TC-Abort: "
                    + e.getMessage(), e);
        }

    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.tcap.asn.Encodable#encode(org.mobicents.protocols .asn.AsnOutputStream)
     */
    public void encode(AsnOutputStream aos) throws EncodeException {

        try {
            aos.writeTag(Tag.CLASS_APPLICATION, false, _TAG);
            int pos = aos.StartContentDefiniteLength();

            aos.writeOctetString(Tag.CLASS_APPLICATION, _TAG_DTX, this.destTxId);

            if (this.type != null)
                aos.writeInteger(Tag.CLASS_APPLICATION, _TAG_P, this.type.getType());
            else if (this.dp != null)
                this.dp.encode(aos);

            aos.FinalizeContent(pos);

        } catch (IOException e) {
            throw new EncodeException("IOException while encoding TC-Abort: " + e.getMessage(), e);
        } catch (AsnException e) {
            throw new EncodeException("AsnException while encoding TC-Abort: " + e.getMessage(), e);
        }

    }

}
