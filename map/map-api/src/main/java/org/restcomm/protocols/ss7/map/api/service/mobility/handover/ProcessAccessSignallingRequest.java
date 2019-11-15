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

package org.restcomm.protocols.ss7.map.api.service.mobility.handover;

import org.restcomm.protocols.ss7.map.api.primitives.AccessNetworkSignalInfo;
import org.restcomm.protocols.ss7.map.api.primitives.ExternalSignalInfo;
import org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.restcomm.protocols.ss7.map.api.service.mobility.MobilityMessage;

/**
 *
 MAP V1-2-3:
 *
 * MAP V3: processAccessSignalling OPERATION ::= { --Timer s ARGUMENT ProcessAccessSignalling-Arg CODE local:33 }
 *
 * MAP V2: ProcessAccessSignalling ::= OPERATION--Timer s ARGUMENT bss-APDU ExternalSignalInfo
 *
 *
 * MAP V3: ProcessAccessSignalling-Arg ::= [3] SEQUENCE { an-APDU AccessNetworkSignalInfo, selectedUMTS-Algorithms [1]
 * SelectedUMTS-Algorithms OPTIONAL, selectedGSM-Algorithm [2] SelectedGSM-Algorithm OPTIONAL, chosenRadioResourceInformation
 * [3] ChosenRadioResourceInformation OPTIONAL, selectedRab-Id [4] RAB-Id OPTIONAL, extensionContainer [0] ExtensionContainer
 * OPTIONAL, ..., iUSelectedCodec [5] Codec OPTIONAL, iuAvailableCodecsList [6] CodecList OPTIONAL, aoipSelectedCodecTarget [7]
 * AoIPCodec OPTIONAL, aoipAvailableCodecsListMap [8] AoIPCodecsList OPTIONAL }
 *
 * RAB-Id ::= INTEGER (1..255)
 *
 *
 * @author sergey vetyutnev
 *
 */
public interface ProcessAccessSignallingRequest extends MobilityMessage {

    AccessNetworkSignalInfo getAnApdu();

    SelectedUMTSAlgorithms getSelectedUMTSAlgorithms();

    SelectedGSMAlgorithm getSelectedGSMAlgorithm();

    ChosenRadioResourceInformation getChosenRadioResourceInformation();

    Integer getSelectedRabId();

    MAPExtensionContainer getExtensionContainer();

    Codec getIUSelectedCodec();

    CodecList getIuAvailableCodecsList();

    AoIPCodec getAoipSelectedCodecTarget();

    AoIPCodecsList getAoipAvailableCodecsListMap();

    // for MAP V1-2 only
    ExternalSignalInfo getBssAPDU();

}
