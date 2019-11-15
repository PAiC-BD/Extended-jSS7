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

package org.restcomm.protocols.ss7.tools.traceparser;

import java.util.ArrayList;

import org.apache.log4j.Logger;

/**
 *
 * @author sergey vetyutnev
 *
 */
public abstract class TraceReaderDriverBase implements TraceReaderDriver {

    protected Logger loger = Logger.getLogger(TraceReaderDriverBase.class);

    protected ArrayList<TraceReaderListener> listeners = new ArrayList<TraceReaderListener>();
    protected boolean isStarted = false;

    protected ProcessControl processControl;
    protected String fileName;

    public TraceReaderDriverBase(ProcessControl processControl, String fileName) {
        this.processControl = processControl;
        this.fileName = fileName;
    }

    public void addTraceListener(TraceReaderListener listener) {
        this.listeners.add(listener);
    }

    public void removeTraceListener(TraceReaderListener listener) {
        this.listeners.remove(listener);
    }

    public void stop() {
        this.isStarted = false;
    }

}
