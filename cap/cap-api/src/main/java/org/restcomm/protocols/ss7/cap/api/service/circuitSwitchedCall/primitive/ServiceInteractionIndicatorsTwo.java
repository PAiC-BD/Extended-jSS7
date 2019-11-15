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

package org.restcomm.protocols.ss7.cap.api.service.circuitSwitchedCall.primitive;

import java.io.Serializable;

import org.restcomm.protocols.ss7.inap.api.primitives.BothwayThroughConnectionInd;

/**
 *
<code>
ServiceInteractionIndicatorsTwo ::= SEQUENCE {
  forwardServiceInteractionInd      [0] ForwardServiceInteractionInd OPTIONAL,
  -- applicable to operations InitialDP, Connect and ContinueWithArgument.
  backwardServiceInteractionInd     [1] BackwardServiceInteractionInd OPTIONAL,
  -- applicable to operations Connect and ContinueWithArgument.
  bothwayThroughConnectionInd       [2] BothwayThroughConnectionInd OPTIONAL,
  -- applicable to ConnectToResource and EstablishTemporaryConnection
  connectedNumberTreatmentInd       [4] ConnectedNumberTreatmentInd OPTIONAL,
  -- applicable to Connect and ContinueWithArgument

  nonCUGCall                        [13] NULL OPTIONAL,
  -- applicable to Connect and ContinueWithArgument
  -- indicates that no parameters for CUG shall be used for the call (i.e. the call shall
  -- be a non-CUG call).
  -- If not present, it indicates one of three things:
  -- a) continue with modified CUG information (when one or more of either CUG Interlock Code
  -- and Outgoing Access Indicator are present), or
  -- b) continue with original CUG information (when neither CUG Interlock Code or Outgoing
  -- Access Indicator are present), i.e. no IN impact.
  -- c) continue with the original non-CUG call.

  holdTreatmentIndicator            [50] OCTET STRING (SIZE(1)) OPTIONAL,
  -- applicable to InitialDP, Connect and ContinueWithArgument
  -- acceptHoldRequest 'xxxx xx01'B
  -- rejectHoldRequest 'xxxx xx10'B
  -- if absent from Connect or ContinueWithArgument,
  -- then CAMEL service does not affect call hold treatment

  cwTreatmentIndicator              [51] OCTET STRING (SIZE(1)) OPTIONAL,
  -- applicable to InitialDP, Connect and ContinueWithArgument
  -- acceptCw 'xxxx xx01'B
  -- rejectCw 'xxxx xx10'B
  -- if absent from Connect or ContinueWithArgument,
  -- then CAMEL service does not affect call waiting treatment

  ectTreatmentIndicator             [52] OCTET STRING (SIZE(1)) OPTIONAL,
  -- applicable to InitialDP, Connect and ContinueWithArgument
  -- acceptEctRequest 'xxxx xx01'B
  -- rejectEctRequest 'xxxx xx10'B
  -- if absent from Connect or ContinueWithArgument,
  -- then CAMEL service does not affect explicit call transfer treatment
  ...
}
</code>
 *
 * @author sergey vetyutnev
 *
 */
public interface ServiceInteractionIndicatorsTwo extends Serializable {

    ForwardServiceInteractionInd getForwardServiceInteractionInd();

    BackwardServiceInteractionInd getBackwardServiceInteractionInd();

    BothwayThroughConnectionInd getBothwayThroughConnectionInd();

    ConnectedNumberTreatmentInd getConnectedNumberTreatmentInd();

    boolean getNonCUGCall();

    HoldTreatmentIndicator getHoldTreatmentIndicator();

    CwTreatmentIndicator getCwTreatmentIndicator();

    EctTreatmentIndicator getEctTreatmentIndicator();

}
