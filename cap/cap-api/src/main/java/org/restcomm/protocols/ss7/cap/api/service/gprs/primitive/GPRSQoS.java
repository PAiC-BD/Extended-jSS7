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

package org.restcomm.protocols.ss7.cap.api.service.gprs.primitive;

import java.io.Serializable;

import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtQoSSubscribed;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.QoSSubscribed;

/**
 *
 GPRS-QoS ::= CHOICE { short-QoS-format [0] QoS-Subscribed, long-QoS-format [1] Ext-QoS-Subscribed } -- Short-QoS-format shall
 * be sent for QoS in pre GSM release 99 format. -- Long-QoS-format shall be sent for QoS in GSM release 99 (and beyond) format.
 * -- Which of the two QoS formats shall be sent is determined by which QoS -- format is available in the SGSN at the time of
 * sending. -- Refer to 3GPP TS 29.002 [11] for encoding details of QoS-Subscribed and -- Ext-QoS-Subscribed.
 *
 *
 * @author sergey vetyutnev
 *
 */
public interface GPRSQoS extends Serializable {

    QoSSubscribed getShortQoSFormat();

    ExtQoSSubscribed getLongQoSFormat();

}