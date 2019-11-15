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

package org.restcomm.protocols.ss7.tcap.asn.comp;

import org.mobicents.protocols.asn.Tag;

/**
 * @author baranowb
 * @author sergey vetyutnev
 *
 */
public interface Reject extends Component {

    int _TAG = 0x04;
    boolean _TAG_PC_PRIMITIVE = false;
    int _TAG_CLASS = Tag.CLASS_CONTEXT_SPECIFIC;

    int _TAG_IID = 0x02;
    boolean _TAG_IID_PC_PRIMITIVE = true;
    int _TAG_IID_CLASS = Tag.CLASS_UNIVERSAL;

    Problem getProblem();

    void setProblem(Problem p);

    /**
     * @return true: local originated Reject (rejecting a bad incoming primitive by a local side) false: remote originated
     *         Reject (rejecting a bad outgoing primitive by a peer)
     */
    boolean isLocalOriginated();

    void setLocalOriginated(boolean p);

}
