package uk.ngs.ca.certificate;

import org.junit.Test;
import uk.ngs.ca.common.CaOfflineException;

import java.io.IOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpTimeoutException;

import static org.junit.Assert.assertEquals;

/**
 * A failure while sending the SIGNED renewal request decides whether
 * auto-renew may try again: only failures that provably happened before
 * anything left this machine are NOT_SENT.
 */
public class RenewalFailureClassificationTest {

    private static OnlineCertRenewRequest.Status classify(IOException e) {
        return OnlineCertRenewRequest.classifySubmissionFailure(e);
    }

    @Test
    public void failuresBeforeSendingAreNotSent() {
        assertEquals(OnlineCertRenewRequest.Status.NOT_SENT, classify(new CaOfflineException("CA known to be unreachable")));
        assertEquals(OnlineCertRenewRequest.Status.NOT_SENT, classify(new ConnectException("refused")));
        assertEquals(OnlineCertRenewRequest.Status.NOT_SENT, classify(new HttpConnectTimeoutException("connect timed out")));
        assertEquals(OnlineCertRenewRequest.Status.NOT_SENT, classify(new UnknownHostException("cwiz-live.ca.ngs.ac.uk")));
        assertEquals(OnlineCertRenewRequest.Status.NOT_SENT, classify(new NoRouteToHostException("no route")));
    }

    @Test
    public void failuresAfterTheRequestMayHaveLeftAreMaybeSent() {
        assertEquals(OnlineCertRenewRequest.Status.MAYBE_SENT, classify(new HttpTimeoutException("request timed out")));
        assertEquals(OnlineCertRenewRequest.Status.MAYBE_SENT, classify(new SocketTimeoutException("read timed out")));
        assertEquals(OnlineCertRenewRequest.Status.MAYBE_SENT, classify(new IOException("connection reset")));
    }
}
