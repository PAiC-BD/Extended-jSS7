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
 * Start time:14:23:10 2009-07-23<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
package org.restcomm.protocols.ss7.isup.message.parameter;

/**
 * Start time:14:23:10 2009-07-23<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
public interface UserToUserIndicators extends ISUPParameter {
    int _PARAMETER_CODE = 0x2A;

    // FIXME: Add C defs

    /**
     * Service 1,2,3 request : no info
     */
    int _REQ_Sx_NO_INFO = 0;
    /**
     * Service 1,2,3 request : not essential
     */
    int _REQ_Sx_RNE = 2;
    /**
     * Service 1,2,3 request : essential
     */
    int _REQ_Sx_RE = 3;

    /**
     * Service 1,2,3 request : no info
     */
    int _RESP_Sx_NO_INFO = 0;
    /**
     * Service 1,2,3 request : not provided
     */
    int _RESP_Sx_NOT_PROVIDED = 1;

    /**
     * Service 1,2,3 request : provided
     */
    int _RESP_Sx_PROVIDED = 2;

    /**
     * See Q.763 3.60 Network discard indicator : no information
     */
    boolean _NDI_NO_INFO = false;

    /**
     * See Q.763 3.60 Network discard indicator : user-to-user information discarded by the network
     */
    boolean _NDI_UTUIDBTN = true;

    boolean isResponse();

    void setResponse(boolean response);

    int getServiceOne();

    void setServiceOne(int serviceOne);

    int getServiceTwo();

    void setServiceTwo(int serviceTwo);

    int getServiceThree();

    void setServiceThree(int serviceThree);

    boolean isNetworkDiscardIndicator();

    void setNetworkDiscardIndicator(boolean networkDiscardIndicator);

}
