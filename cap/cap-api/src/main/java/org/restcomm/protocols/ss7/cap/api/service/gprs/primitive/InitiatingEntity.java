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

/**
 *
 InitiatingEntity ::= ENUMERATED { mobileStation (0), sgsn (1), hlr (2), ggsn (3) }
 *
 *
 * @author sergey vetyutnev
 *
 */
public enum InitiatingEntity {
    mobileStation(0), sgsn(1), hlr(2), ggsn(3);

    private int code;

    private InitiatingEntity(int code) {
        this.code = code;
    }

    public int getCode() {
        return this.code;
    }

    public static InitiatingEntity getInstance(int code) {
        switch (code) {
            case 0:
                return InitiatingEntity.mobileStation;
            case 1:
                return InitiatingEntity.sgsn;
            case 2:
                return InitiatingEntity.hlr;
            case 3:
                return InitiatingEntity.ggsn;
            default:
                return null;
        }
    }
}
