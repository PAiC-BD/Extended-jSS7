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

/**
 * Start time:13:39:50 2009-03-30<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com"> Bartosz Baranowski
 *         </a>
 *
 */
package org.restcomm.protocols.ss7.isup.impl.message.parameter.accessTransport;

import java.io.ByteArrayOutputStream;

import org.restcomm.protocols.ss7.isup.ParameterException;
import org.restcomm.protocols.ss7.isup.impl.message.parameter.AbstractISUPParameter;
import org.restcomm.protocols.ss7.isup.message.parameter.accessTransport.AccessTransport;

/**
 * Start time:13:39:50 2009-03-30<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com"> Bartosz Baranowski </a>
 */
public class AccessTransportImpl extends AbstractISUPParameter implements AccessTransport {

    // FIXME: Q763 3.3

    public AccessTransportImpl() {
        super();

    }

    public AccessTransportImpl(byte[] b) throws ParameterException {
        super();
        decode(b);
    }

    public int decode(byte[] b) throws ParameterException {
        // TODO Auto-generated method stub
        return 0;
    }

    public byte[] encode() throws ParameterException {
        // TODO Auto-generated method stub
        return null;
    }

    public int encode(ByteArrayOutputStream bos) throws ParameterException {
        // TODO Auto-generated method stub
        return 0;
    }

    public int getCode() {
        return _PARAMETER_CODE;
    }

}
