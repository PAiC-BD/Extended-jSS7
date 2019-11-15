/*
 * JBoss, Home of Professional Open Source
 * Copyright 2011, Red Hat, Inc. and individual contributors
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

package org.restcomm.protocols.ss7.map.api.errors;

/**
 * MAP Error codes Carried by ReturnError primitive
 *
 * @author sergey vetyutnev
 *
 */
public interface MAPErrorCode {

    // -- values band
    int minimalCodeValue = 1;
    int maximumCodeValue = 72;

    // -- generic error codes
    int systemFailure = 34;
    int dataMissing = 35;
    int unexpectedDataValue = 36;
    int facilityNotSupported = 21;
    int incompatibleTerminal = 28;
    int resourceLimitation = 51;

    // -- call handling error codes
    int noRoamingNumberAvailable = 39;
    int absentSubscriber = 27;
    int busySubscriber = 45;
    int noSubscriberReply = 46;
    int callBarred = 13;
    int forwardingFailed = 47;
    int orNotAllowed = 48;
    int forwardingViolation = 14;
    int cugReject = 15;

    // -- identification and numbering errors
    int unknownSubscriber = 1;
    int numberChanged = 44;
    int unknownMSC = 3;
    int unidentifiedSubscriber = 5;
    int unknownEquipment = 7;

    // -- subscription error codes
    int roamingNotAllowed = 8;
    int illegalSubscriber = 9;
    int illegalEquipment = 12;
    int bearerServiceNotProvisioned = 10;
    int teleserviceNotProvisioned = 11;

    // -- short message service errors
    int subscriberBusyForMTSMS = 31;
    int smDeliveryFailure = 32;
    int messageWaitingListFull = 33;
    int absentSubscriberSM = 6;

    // -- location service errors
    int unauthorizedRequestingNetwork = 52;
    int unauthorizedLCSClient = 53;
    int positionMethodFailure = 54;
    int unknownOrUnreachableLCSClient = 58;
    int mmEventNotSupported = 59;

    // -- supplementary service errors
    int illegalSSOperation = 16;
    int ssErrorStatus = 17;
    int ssNotAvailable = 18;
    int ssSubscriptionViolation = 19;
    int ssIncompatibility = 20;
    int unknownAlphabet = 71;
    int ussdBusy = 72;
    int pwRegistrationFailure = 37;
    int negativePWCheck = 38;
    int numberOfPWAttemptsViolation = 43;
    int shortTermDenial = 29;
    int longTermDenial = 30;

    /**
     * systemFailure | unexpectedDataValue | facilityNotSupported | sm-DeliveryFailure} dataMissing | unidentifiedSubscriber |
     * illegalSubscriber | illegalEquipment | subscriberBusyForMT-SMS | absentSubscriberSM unknownSubscriber |
     * teleserviceNotProvisioned | callBarred | messageWaitingListFull absentSubscriber unauthorizedRequestingNetwork
     * unauthorizedLCSClient positionMethodFailure resourceLimitation unknownOrUnreachableLCSClient
     *
     */

}
