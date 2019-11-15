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

package org.restcomm.protocols.ss7.cap.service.circuitSwitchedCall.primitive;

import javolution.xml.XMLFormat;
import javolution.xml.stream.XMLStreamException;

import org.restcomm.protocols.ss7.cap.api.service.circuitSwitchedCall.primitive.FreeFormatData;
import org.restcomm.protocols.ss7.cap.primitives.OctetStringBase;
import org.restcomm.protocols.ss7.isup.impl.message.parameter.ByteArrayContainer;

/**
*
* @author Lasith Waruna Perera
* @author sergey vetyutnev
*
*/
public class FreeFormatDataImpl extends OctetStringBase implements FreeFormatData {

    private static final String DATA = "data";

    public FreeFormatDataImpl() {
        super(1, 160, "FreeFormatData");
    }

    public FreeFormatDataImpl(byte[] data) {
        super(1, 160, "FreeFormatData", data);
    }

    @Override
    public byte[] getData() {
        return data;
    }

    /**
     * XML Serialization/Deserialization
     */
    protected static final XMLFormat<FreeFormatDataImpl> FREE_FORMAT_DATA_XML = new XMLFormat<FreeFormatDataImpl>(
            FreeFormatDataImpl.class) {

        @Override
        public void read(javolution.xml.XMLFormat.InputElement xml, FreeFormatDataImpl freeFormatData)
                throws XMLStreamException {
            ByteArrayContainer bc = xml.get(DATA, ByteArrayContainer.class);
            if (bc != null) {
                freeFormatData.data = bc.getData();
            }
        }

        @Override
        public void write(FreeFormatDataImpl freeFormatData, javolution.xml.XMLFormat.OutputElement xml)
                throws XMLStreamException {
            if (freeFormatData.data != null) {
                ByteArrayContainer bac = new ByteArrayContainer(freeFormatData.data);
                xml.add(bac, DATA, ByteArrayContainer.class);
            }
        }
    };

}
