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
package uk.ngs.ca.wire;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Minimal HTTP/1.1 server on the loopback interface that records every
 * request byte-for-byte (request line, header lines with their original name
 * case and order, de-chunked body) and answers with scripted responses.
 * <p>
 * A raw socket is used deliberately instead of
 * {@code com.sun.net.httpserver.HttpServer}: the JDK server canonicalises
 * header names (e.g. {@code LocalHost} becomes {@code Localhost},
 * {@code PPPK} becomes {@code Pppk}), which would hide exactly the kind of
 * difference the wire compatibility tests need to detect.
 */
public final class RawHttpCaptureServer implements AutoCloseable {

    /** A scripted response. */
    public static final class Reply {

        final int status;
        final String reason;
        final Map<String, String> headers = new LinkedHashMap<>();
        byte[] body = new byte[0];
        boolean drop;

        public Reply(int status, String reason) {
            this.status = status;
            this.reason = reason;
        }

        /** Read the request, then close the connection without answering. */
        public static Reply dropConnection() {
            Reply r = new Reply(0, null);
            r.drop = true;
            return r;
        }

        public Reply header(String name, String value) {
            headers.put(name, value);
            return this;
        }

        public Reply body(String contentType, String text) {
            headers.put("Content-Type", contentType);
            this.body = text.getBytes(StandardCharsets.UTF_8);
            return this;
        }

        public Reply xml(String xml) {
            return body("application/xml; charset=UTF-8", xml);
        }
    }

    private final ServerSocket serverSocket;
    private final Thread acceptThread;
    private final List<CapturedRequest> captured = new CopyOnWriteArrayList<>();
    private final ConcurrentLinkedQueue<Reply> script = new ConcurrentLinkedQueue<>();
    private final List<Socket> openSockets = Collections.synchronizedList(new ArrayList<>());
    private volatile boolean running = true;

    public RawHttpCaptureServer() throws IOException {
        serverSocket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        acceptThread = new Thread(this::acceptLoop, "raw-capture-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    public int getPort() {
        return serverSocket.getLocalPort();
    }

    public String baseUrl() {
        return "http://127.0.0.1:" + getPort();
    }

    /** Clear captured requests and the response script. */
    public void reset() {
        captured.clear();
        script.clear();
    }

    /** Queue responses; each request consumes one. Unscripted requests get 404. */
    public void enqueue(Reply... replies) {
        Collections.addAll(script, replies);
    }

    public List<CapturedRequest> getCaptured() {
        return new ArrayList<>(captured);
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket s = serverSocket.accept();
                openSockets.add(s);
                Thread t = new Thread(() -> serve(s), "raw-capture-conn");
                t.setDaemon(true);
                t.start();
            } catch (IOException e) {
                if (running) {
                    e.printStackTrace();
                }
            }
        }
    }

    private void serve(Socket socket) {
        try (Socket s = socket) {
            s.setSoTimeout(30_000);
            InputStream in = new BufferedInputStream(s.getInputStream());
            OutputStream out = s.getOutputStream();
            while (running) {
                String requestLine = readLine(in);
                if (requestLine == null) {
                    return; // client closed the connection
                }
                if (requestLine.isEmpty()) {
                    continue;
                }
                String[] parts = requestLine.split(" ", 3);
                List<String[]> headers = new ArrayList<>();
                String line;
                while ((line = readLine(in)) != null && !line.isEmpty()) {
                    int colon = line.indexOf(':');
                    headers.add(new String[]{line.substring(0, colon), line.substring(colon + 1).trim()});
                }
                if ("100-continue".equalsIgnoreCase(find(headers, "Expect"))) {
                    out.write("HTTP/1.1 100 Continue\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
                    out.flush();
                }
                byte[] body = readBody(in, headers);
                captured.add(new CapturedRequest(parts[0], parts[1], parts.length > 2 ? parts[2] : "", headers, body));

                Reply reply = script.poll();
                if (reply == null) {
                    reply = new Reply(404, "Not Found");
                }
                if (reply.drop) {
                    return;
                }
                boolean close = "close".equalsIgnoreCase(find(headers, "Connection"));
                writeReply(out, reply, close);
                if (close) {
                    return;
                }
            }
        } catch (SocketException ignored) {
            // connection reset/closed by client
        } catch (IOException e) {
            if (running) {
                e.printStackTrace();
            }
        } finally {
            openSockets.remove(socket);
        }
    }

    private static void writeReply(OutputStream out, Reply reply, boolean close) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("HTTP/1.1 ").append(reply.status).append(' ').append(reply.reason).append("\r\n");
        for (Map.Entry<String, String> h : reply.headers.entrySet()) {
            sb.append(h.getKey()).append(": ").append(h.getValue()).append("\r\n");
        }
        sb.append("Content-Length: ").append(reply.body.length).append("\r\n");
        if (close) {
            sb.append("Connection: close\r\n");
        }
        sb.append("\r\n");
        out.write(sb.toString().getBytes(StandardCharsets.ISO_8859_1));
        out.write(reply.body);
        out.flush();
    }

    private static String find(List<String[]> headers, String name) {
        for (String[] h : headers) {
            if (h[0].equalsIgnoreCase(name)) {
                return h[1];
            }
        }
        return null;
    }

    private static byte[] readBody(InputStream in, List<String[]> headers) throws IOException {
        String te = find(headers, "Transfer-Encoding");
        if (te != null && te.toLowerCase().contains("chunked")) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            while (true) {
                String sizeLine = readLine(in);
                int semi = sizeLine.indexOf(';');
                int size = Integer.parseInt((semi < 0 ? sizeLine : sizeLine.substring(0, semi)).trim(), 16);
                if (size == 0) {
                    String trailer;
                    while ((trailer = readLine(in)) != null && !trailer.isEmpty()) {
                        // discard trailers
                    }
                    return bos.toByteArray();
                }
                bos.write(in.readNBytes(size));
                readLine(in); // CRLF after the chunk
            }
        }
        String cl = find(headers, "Content-Length");
        if (cl != null) {
            return in.readNBytes(Integer.parseInt(cl.trim()));
        }
        return new byte[0];
    }

    /** Read a CRLF (or LF) terminated ISO-8859-1 line; null on EOF. */
    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) != -1) {
            if (c == '\n') {
                byte[] b = bos.toByteArray();
                int len = b.length > 0 && b[b.length - 1] == '\r' ? b.length - 1 : b.length;
                return new String(b, 0, len, StandardCharsets.ISO_8859_1);
            }
            bos.write(c);
        }
        return bos.size() == 0 ? null : bos.toString(StandardCharsets.ISO_8859_1);
    }

    @Override
    public void close() throws IOException {
        running = false;
        serverSocket.close();
        synchronized (openSockets) {
            for (Socket s : openSockets) {
                try {
                    s.close();
                } catch (IOException ignored) {
                }
            }
        }
    }
}
