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

package org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement;

/**
 *
 GPRS-TriggerDetectionPoint ::= ENUMERATED { attach (1), attachChangeOfPosition (2), pdp-ContextEstablishment (11),
 * pdp-ContextEstablishmentAcknowledgement (12), pdp-ContextChangeOfPosition (14), ... } -- exception handling: -- For
 * GPRS-CamelTDPData sequences containing this parameter with any -- other value than the ones listed the receiver shall ignore
 * the whole -- GPRS-CamelTDPDatasequence.
 *
 *
 *
 * @author sergey vetyutnev
 *
 */
public enum GPRSTriggerDetectionPoint {
    attach(1), attachChangeOfPosition(2), pdpContextEstablishment(11), pdpContextEstablishmentAcknowledgement(12), pdpContextChangeOfPosition(
            14);

    private int code;

    private GPRSTriggerDetectionPoint(int code) {
        this.code = code;
    }

    public int getCode() {
        return this.code;
    }

    public static GPRSTriggerDetectionPoint getInstance(int code) {
        switch (code) {
            case 1:
                return GPRSTriggerDetectionPoint.attach;
            case 2:
                return GPRSTriggerDetectionPoint.attachChangeOfPosition;
            case 11:
                return GPRSTriggerDetectionPoint.pdpContextEstablishment;
            case 12:
                return GPRSTriggerDetectionPoint.pdpContextEstablishmentAcknowledgement;
            case 14:
                return GPRSTriggerDetectionPoint.pdpContextChangeOfPosition;
            default:
                return null;
        }
    }
}
