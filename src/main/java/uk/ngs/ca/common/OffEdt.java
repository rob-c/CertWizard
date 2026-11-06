/*
 * CertWizard - UK eScience CA Certificate Management Client
 * Copyright (C) 2021 UKRI-STFC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package uk.ngs.ca.common;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dialog;
import java.awt.FlowLayout;
import java.awt.GraphicsEnvironment;
import java.awt.Window;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Runs blocking network work off the Swing event dispatch thread while
 * keeping the calling code sequential.
 * <p>
 * Called on the EDT, {@link #call} runs the task on a background thread and
 * waits for it inside a modal "please wait" dialog (shown only if the task
 * takes longer than a moment), so the UI keeps painting and other windows
 * cannot be used meanwhile. The dialog's Cancel button interrupts the work:
 * requests through {@link CaHttpClient} then stop promptly (and are not
 * retried), so the user is never stuck behind a slow server. Called on any
 * other thread, it simply runs the task. Exceptions thrown by the task are
 * rethrown unchanged.
 */
public final class OffEdt {

    /** Delay before the wait dialog appears, to avoid flashing it for quick calls. */
    private static final long DIALOG_DELAY_MILLIS = 300;

    private OffEdt() {
    }

    /** Work that may throw a checked exception of type E. */
    @FunctionalInterface
    public interface Task<T, E extends Exception> {

        T run() throws E;
    }

    /**
     * Run the task, off the EDT if called on it.
     *
     * @param parent  component to centre the wait dialog on (may be null)
     * @param message what is being waited for, e.g. "Contacting the CA server..."
     * @param task    the blocking work
     * @return the task's result
     * @throws E whatever the task throws
     */
    public static <T, E extends Exception> T call(Component parent, String message, Task<T, E> task) throws E {
        if (!SwingUtilities.isEventDispatchThread()) {
            return task.run();
        }
        FutureTask<T> future = new FutureTask<>(task::run);
        AtomicReference<Thread> workerRef = new AtomicReference<>();
        JDialog dialog = GraphicsEnvironment.isHeadless() ? null
                : createDialog(parent, message, () -> workerRef.get().interrupt());
        Thread worker = new Thread(() -> {
            try {
                future.run();
            } finally {
                if (dialog != null) {
                    SwingUtilities.invokeLater(dialog::dispose);
                }
            }
        }, "certwizard-network-call");
        worker.setDaemon(true);
        workerRef.set(worker);
        worker.start();

        if (dialog != null) {
            try {
                future.get(DIALOG_DELAY_MILLIS, TimeUnit.MILLISECONDS);
            } catch (TimeoutException slow) {
                // Blocks in a nested event loop until the worker disposes it.
                dialog.setVisible(true);
            } catch (InterruptedException | ExecutionException ignored) {
                // handled below
            }
        }
        return result(future);
    }

    @SuppressWarnings("unchecked")
    private static <T, E extends Exception> T result(FutureTask<T> future) throws E {
        boolean interrupted = false;
        try {
            while (true) {
                try {
                    return future.get();
                } catch (InterruptedException e) {
                    interrupted = true; // keep waiting: the task must finish first
                } catch (ExecutionException e) {
                    Throwable cause = e.getCause();
                    if (cause instanceof RuntimeException) {
                        throw (RuntimeException) cause;
                    }
                    if (cause instanceof Error) {
                        throw (Error) cause;
                    }
                    // Task.run() only declares E, so any checked cause is an E.
                    throw (E) cause;
                }
            }
        } finally {
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static JDialog createDialog(Component parent, String message, Runnable cancel) {
        Window owner = parent == null ? null : (parent instanceof Window ? (Window) parent : SwingUtilities.getWindowAncestor(parent));
        JDialog dialog = new JDialog(owner, "Please wait", Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        JPanel panel = new JPanel(new BorderLayout(0, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(15, 20, 15, 20));
        JLabel label = new JLabel(message);
        panel.add(label, BorderLayout.NORTH);
        JProgressBar bar = new JProgressBar();
        bar.setIndeterminate(true);
        panel.add(bar, BorderLayout.CENTER);
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> {
            cancelButton.setEnabled(false);
            label.setText("Cancelling...");
            cancel.run();
        });
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        buttons.add(cancelButton);
        panel.add(buttons, BorderLayout.SOUTH);
        dialog.setContentPane(panel);
        dialog.pack();
        dialog.setResizable(false);
        dialog.setLocationRelativeTo(parent);
        return dialog;
    }
}
