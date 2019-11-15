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

package org.restcomm.protocols.ss7.map.api.service.lsm;

/**
 * PrivacyCheckRelatedAction ::= ENUMERATED { allowedWithoutNotification (0), allowedWithNotification (1), allowedIfNoResponse
 * (2), restrictedIfNoResponse (3), notAllowed (4), ...} -- exception handling: -- a ProvideSubscriberLocation-Arg containing an
 * unrecognized PrivacyCheckRelatedAction -- shall be rejected by the receiver with a return error cause of unexpected data
 * value
 *
 * @author amit bhayani
 *
 */
public enum PrivacyCheckRelatedAction {

    allowedWithoutNotification(0), allowedWithNotification(1), allowedIfNoResponse(2), restrictedIfNoResponse(3), notAllowed(4);

    private final int action;

    private PrivacyCheckRelatedAction(int action) {
        this.action = action;
    }

    public int getAction() {
        return this.action;
    }

    public static PrivacyCheckRelatedAction getPrivacyCheckRelatedAction(int action) {
        switch (action) {
            case 0:
                return allowedWithoutNotification;
            case 1:
                return allowedWithNotification;
            case 2:
                return allowedIfNoResponse;
            case 3:
                return restrictedIfNoResponse;
            case 4:
                return notAllowed;
            default:
                return null;
        }
    }
}
