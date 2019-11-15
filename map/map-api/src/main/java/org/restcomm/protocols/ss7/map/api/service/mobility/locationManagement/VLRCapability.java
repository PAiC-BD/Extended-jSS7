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

package org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement;

import java.io.Serializable;

import org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.OfferedCamel4CSIs;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.SupportedCamelPhases;

/**
 *
 <code>
VLR-Capability ::= SEQUENCE{
  supportedCamelPhases          [0] SupportedCamelPhases OPTIONAL,
  extensionContainer            ExtensionContainer OPTIONAL,
  ... ,
  solsaSupportIndicator         [2] NULL OPTIONAL,
  istSupportIndicator           [1] IST-SupportIndicator OPTIONAL,
  superChargerSupportedInServingNetworkEntity [3] SuperChargerInfo OPTIONAL,
  longFTN-Supported             [4] NULL OPTIONAL,
  supportedLCS-CapabilitySets   [5] SupportedLCS-CapabilitySets OPTIONAL,
  offeredCamel4CSIs             [6] OfferedCamel4CSIs OPTIONAL,
  supportedRAT-TypesIndicator   [7] SupportedRAT-Types OPTIONAL,
  longGroupID-Supported         [8] NULL OPTIONAL,
  mtRoamingForwardingSupported  [9] NULL OPTIONAL
}
</code>
 *
 *
 * @author sergey vetyutnev
 *
 */
public interface VLRCapability extends Serializable {

    SupportedCamelPhases getSupportedCamelPhases();

    MAPExtensionContainer getExtensionContainer();

    boolean getSolsaSupportIndicator();

    ISTSupportIndicator getIstSupportIndicator();

    SuperChargerInfo getSuperChargerSupportedInServingNetworkEntity();

    boolean getLongFtnSupported();

    SupportedLCSCapabilitySets getSupportedLCSCapabilitySets();

    OfferedCamel4CSIs getOfferedCamel4CSIs();

    SupportedRATTypes getSupportedRATTypesIndicator();

    boolean getLongGroupIDSupported();

    boolean getMtRoamingForwardingSupported();

}
