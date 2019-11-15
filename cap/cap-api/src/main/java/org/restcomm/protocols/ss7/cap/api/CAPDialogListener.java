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

package org.restcomm.protocols.ss7.cap.api;

import org.restcomm.protocols.ss7.cap.api.dialog.CAPGeneralAbortReason;
import org.restcomm.protocols.ss7.cap.api.dialog.CAPGprsReferenceNumber;
import org.restcomm.protocols.ss7.cap.api.dialog.CAPNoticeProblemDiagnostic;
import org.restcomm.protocols.ss7.cap.api.dialog.CAPUserAbortReason;
import org.restcomm.protocols.ss7.tcap.asn.comp.PAbortCauseType;

/**
 *
 * @author sergey vetyutnev
 *
 */
public interface CAPDialogListener {
    /**
     * Called after all components has been processed.
     */
     void onDialogDelimiter(CAPDialog capDialog);

    /**
     * When TC-BEGIN received. If CAP user rejects this dialog it should call CAPDialog.abort()
     */
     void onDialogRequest(CAPDialog capDialog, CAPGprsReferenceNumber capGprsReferenceNumber);

    /**
     * When TC-CONTINUE or TC-END received with dialogueResponse DialoguePDU (AARE-apdu) (dialog accepted) this is called before
     * ComponentPortion is called
     */
     void onDialogAccept(CAPDialog capDialog, CAPGprsReferenceNumber capGprsReferenceNumber);

    /**
     * When TC-ABORT received with user abort userReason is defined only if generalReason=UserSpecific
     */
     void onDialogUserAbort(CAPDialog capDialog, CAPGeneralAbortReason generalReason, CAPUserAbortReason userReason);

    /**
     * When TC-ABORT received with provider abort
     *
     */
     void onDialogProviderAbort(CAPDialog capDialog, PAbortCauseType abortCause);

    /**
     * When TC-END received
     */
     void onDialogClose(CAPDialog capDialog);

    /**
     * Called when the CADDialog has been released
     *
     * @param capDialog
     */
     void onDialogRelease(CAPDialog capDialog);

    /**
     * Called when the CADDialog is about to aborted because of TimeOut
     *
     * @param capDialog
     */
     void onDialogTimeout(CAPDialog capDialog);

    /**
     * Called to notice of abnormal cases
     *
     */
     void onDialogNotice(CAPDialog capDialog, CAPNoticeProblemDiagnostic noticeProblemDiagnostic);

}
