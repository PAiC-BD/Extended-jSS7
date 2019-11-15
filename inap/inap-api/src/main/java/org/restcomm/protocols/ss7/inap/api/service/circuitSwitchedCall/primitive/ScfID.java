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

package org.restcomm.protocols.ss7.inap.api.service.circuitSwitchedCall.primitive;

import java.io.Serializable;

/**
*

<code>
ScfID {PARAMETERS-BOUND : bound} ::= OCTET STRING (SIZE(bound.&minScfIDLength..bound.&maxScfIDLength))
-- defined by network operator.
-- Indicates the SCF identity.
-- Used to derive the INAP address of the SCF to establish a connection between a requesting FE
-- and the specified SCF.
-- When ScfID is used in an operation which may cross an internetwork boundary, its encoding must
-- be understood in both networks; this requires bilateral agreement on the encoding.
-- Refer to 3.5/ETS 300 009-1 "calling party address" parameter for encoding. It indicates the SCCP
address of the SCF.
-- Other encoding schemes are also possible as an operator specific option.
</code>

*
* @author sergey vetyutnev
*
*/
public interface ScfID extends Serializable {

    byte[] getData();

    // TODO: add "calling party address" parameter for encoding

}
