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

package org.restcomm.protocols.ss7.inap.api.isup;

import java.io.Serializable;

import org.restcomm.protocols.ss7.isup.message.parameter.BackwardGVNS;

/**
*

<code>
BackwardGVNS {PARAMETERS-BOUND : bound} ::= OCTET STRING (SIZE(
bound.&minBackwardGVNSLength..bound.&maxBackwardGVNSLength))
-- Indicats the GVNS Backward information. Refer to Q.735, 6 for encoding.
</code>

*
* @author sergey vetyutnev
*
*/
public interface BackwardGVNSInap extends Serializable {

    byte[] getData();

    BackwardGVNS getBackwardGVNS();

    // TODO: Spec refers to "Q.735, 6", we refer to ISUP, what is correct ?

}
