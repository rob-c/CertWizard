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
package uk.ngs.ca.certificate.management;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import uk.ngs.ca.certificate.chain.CertChainBuilder;
import uk.ngs.ca.certificate.chain.KeyStoreChains;
import uk.ngs.ca.certificate.client.CertificateDownload;
import uk.ngs.ca.certificate.client.ResourcesPublicKey;
import uk.ngs.ca.tools.property.SysProperty;

import javax.xml.xpath.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Shared singleton that wraps the {@link ClientKeyStore} class and hosts a map
 * of {@link KeyStoreEntryWrapper} objects which both constitute the
 * application's shared data model.
 * <p>
 * Provides functionality for updating a keyStore entry by querying the CA
 * server for the <b>latest/current</b> state of a particular entry. The public
 * key of the keyStore entry is used as the query parameter to query for the
 * latest certificate/CSR state.
 * <p>
 * Importantly, the keyStore is <b>NEVER reStored to disk</b> by any of the
 * methods. ReStoring to disk has to be called manually by the client via
 * {@link ClientKeyStore}.
 *
 * @author Xiao Wang
 * @author David Meredith (many modifications - more still needed)
 */
public class ClientKeyStoreCaServiceWrapper {

    // important member vars
    /**
     * The password of the managed keyStore file
     */
    private char[] mKeystorePASSPHRASE = null;
    /**
     * Wrapper object that holds the reference to the managed keyStore
     */
    private final ClientKeyStore clientKeyStore;
    /**
     * Map.key is keyStore alias and Map.value is a KeyStoreEntryWrapper
     */
    private final Map<String, KeyStoreEntryWrapper> keyStoreEntryMap = new ConcurrentHashMap<>(0);

    private final XPathExpression extractCertificateExpr;
    private final XPathExpression exptractCSR_Expr;
    /**
     * Class is a singleton, so hold internal reference
     */
    private static ClientKeyStoreCaServiceWrapper instance = null;

    /**
     * Get a shared singleton <code>KeyStoreWrapper</code> instance for the
     * <tt>'$HOME/.ca/cakeystore.pkcs12'</tt> keyStore file.
     *
     * @param passphrase used to protect the keyStore file.
     * @return
     * @throws KeyStoreException     if keyStore file cannot be created or read
     * @throws IllegalStateException if class cannot load for some other reason
     */
    public static synchronized ClientKeyStoreCaServiceWrapper getInstance(char[] passphrase) throws KeyStoreException, IOException, CertificateException {
        if (instance == null) {
            instance = new ClientKeyStoreCaServiceWrapper(passphrase);
        }
        return instance;
    }

    /**
     * Forget the shared instances. For tests only: lets each test load its
     * own keystore from its own temporary data directory.
     */
    public static synchronized void resetForTesting() {
        instance = null;
        ClientKeyStore.resetForTesting();
    }

    private ClientKeyStoreCaServiceWrapper(char[] passphrase) throws KeyStoreException, IOException, CertificateException {
        this.mKeystorePASSPHRASE = passphrase;
        try {
            // some internals
            XPath certXpath = XPathFactory.newInstance().newXPath();
            extractCertificateExpr = certXpath.compile("/resources/resource/certificates/certificate");
            XPath csrXpath = XPathFactory.newInstance().newXPath();
            exptractCSR_Expr = csrXpath.compile("/resources/resource/CSRs/CSR");
        } catch (XPathExpressionException ex) {
            Logger.getLogger(ClientKeyStoreCaServiceWrapper.class.getName()).log(Level.SEVERE, null, ex);
            throw new IllegalStateException(ex);
        }
        this.clientKeyStore = ClientKeyStore.getClientkeyStore(this.mKeystorePASSPHRASE);
        this.loadMap();
    }

    /**
     * Build the chain to store for a certificate downloaded from the CA: the
     * certificate itself followed by every issuer up to and including the
     * root. Issuers come from the chain already stored for the entry, the
     * bundled UK e-Science CA certificates and, failing those, AIA download.
     * If the root cannot be reached the partial chain is returned (never less
     * than the downloaded certificate) and the gap is logged.
     *
     * @param downloaded   certificate just downloaded from the CA
     * @param storedChain  chain currently stored for the entry (may be null)
     * @return leaf-first chain
     */
    private static X509Certificate[] fullChainFor(X509Certificate downloaded, Certificate[] storedChain) {
        CertChainBuilder.Result result = CertChainBuilder.standard().build(downloaded, storedChain);
        if (!result.isComplete()) {
            Logger.getLogger(ClientKeyStoreCaServiceWrapper.class.getName()).log(Level.WARNING,
                    "Incomplete certificate chain for [{0}]: {1}",
                    new Object[]{downloaded.getSubjectX500Principal().getName(), result.getProblems()});
        }
        return result.toArray();
    }

    /**
     * Earlier CertWizard versions stored downloaded certificates without their
     * issuer chain (leaf only). Fill in the missing intermediate and root
     * certificates for every key entry whose stored chain is not already
     * complete and ordered, using only the certificates already in the
     * keyStore plus the bundled UK e-Science CA certificates (no network).
     * <p>
     * Only the in-memory keyStore is changed. As with every other method of
     * this class, persisting it is left to the caller via
     * {@link ClientKeyStore#reStore()}. Failures are logged and never thrown.
     *
     * @return the number of entries whose chain was completed.
     */
    public int completeStoredCertificateChains() {
        return completeStoredCertificateChains(CertChainBuilder.offline());
    }

    /**
     * As {@link #completeStoredCertificateChains()} but with an explicit
     * builder (tests use one backed by a throwaway CA).
     *
     * @param builder chain builder
     * @return the number of entries whose chain was completed.
     */
    int completeStoredCertificateChains(CertChainBuilder builder) {
        int repaired = 0;
        try {
            synchronized (this.clientKeyStore) {
                for (String alias : Collections.list(this.clientKeyStore.aliases())) {
                    if (!this.clientKeyStore.isKeyEntry(alias)) {
                        continue;
                    }
                    Certificate[] stored = this.clientKeyStore.getCertificateChain(alias);
                    CertChainBuilder.Result built = KeyStoreChains.complete(stored, builder);
                    if (!KeyStoreChains.shouldReplace(stored, built)) {
                        continue;
                    }
                    Key key = this.clientKeyStore.getKey(alias, this.mKeystorePASSPHRASE);
                    if (!(key instanceof PrivateKey)) {
                        continue;
                    }
                    this.clientKeyStore.setKeyEntry(alias, key, this.mKeystorePASSPHRASE, built.toArray());
                    repaired++;
                    Logger.getLogger(ClientKeyStoreCaServiceWrapper.class.getName()).log(Level.INFO,
                            "Completed certificate chain for [{0}]: {1} -> {2} certificates",
                            new Object[]{alias, stored.length, built.getChain().size()});
                }
            }
            // No need to rebuild keyStoreEntryMap: the leaf certificate (from
            // which every KeyStoreEntryWrapper field is derived) is unchanged.
        } catch (Exception ex) {
            Logger.getLogger(ClientKeyStoreCaServiceWrapper.class.getName()).log(Level.WARNING,
                    "Could not complete stored certificate chains", ex);
        }
        return repaired;
    }

    /**
     * @return The current password for the CA keyStore file.
     */
    public char[] getPassword() {
        return this.mKeystorePASSPHRASE;
    }

    /**
     * Clear and populate <code>this.mKeyStoreEntries</code> with
     * <code>KeyStoreEntryWrapper</code> objects. Involves no online
     * interactions.
     *
     * @throws KeyStoreException
     */
    private void loadMap() throws KeyStoreException {
        this.keyStoreEntryMap.clear();
        Enumeration<String> keystoreAliases = this.clientKeyStore.aliases();
        while (keystoreAliases.hasMoreElements()) {
            String sAlias = keystoreAliases.nextElement();
            this.keyStoreEntryMap.put(sAlias, this.createKSEntryWrapperInstanceFromEntry(sAlias));
        }
    }

    /**
     * Using the given keyStore alias, create a new
     * <tt>KeyStoreEntryWrapper</tt>
     * from the corresponding entry stored in the managed keyStore. Note, this
     * does not put the KeyStoreEntryWrapper into the keyStore, it simply
     * creates a new instance.
     *
     * @param sAlias
     * @return
     * @throws KeyStoreException
     */
    public KeyStoreEntryWrapper createKSEntryWrapperInstanceFromEntry(String sAlias) throws KeyStoreException {
        String x500PrincipalName = "Unknown"; // provide a default incase
        String issuerName = "Unknown";
        Date notBefore = null, notAfter = null;

        // Lets correspond to the java keytool entry types, see:
        // http://download.oracle.com/javase/1.4.2/docs/tooldocs/windows/keytool.html
        KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE type;
        //boolean isCSR = false; 
        if (this.clientKeyStore.isCertificateEntry(sAlias)) {
            // A single public key certificate belonging and signed by another party
            type = KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.TRUST_CERT_ENTRY;
            X509Certificate trustedCert = (X509Certificate) this.clientKeyStore.getCertificate(sAlias);
            x500PrincipalName = trustedCert.getSubjectX500Principal().toString();
            issuerName = trustedCert.getIssuerX500Principal().toString();
            notAfter = trustedCert.getNotAfter();
            notBefore = trustedCert.getNotBefore();

        } else if (this.clientKeyStore.isKeyEntry(sAlias) && this.clientKeyStore.getCertificateChain(sAlias) != null
                && this.clientKeyStore.getCertificateChain(sAlias).length != 0) {
            // A private key accompanied by the certificate "chain" for the corresponding public key
            type = KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY;
            // get the first in the chain - we know it has a value.
            X509Certificate cert = (X509Certificate) this.clientKeyStore.getCertificateChain(sAlias)[0];
            x500PrincipalName = cert.getSubjectX500Principal().toString();
            issuerName = cert.getIssuerX500Principal().toString();
            // is this cert a self signed CSR cert ? 
            notAfter = cert.getNotAfter();
            notBefore = cert.getNotBefore();

        } else {
            // Still a keyEntry but with no corresponding cert chain.
            type = KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_ENTRY;
        }
        // create and add the KeyStoreEntryWrapper.
        KeyStoreEntryWrapper keyStoreEntry = new KeyStoreEntryWrapper(sAlias, type, this.clientKeyStore.getCreationDate(sAlias));
        keyStoreEntry.setNotAfter(notAfter);
        keyStoreEntry.setNotBefore(notBefore);
        keyStoreEntry.setX500PrincipalName(x500PrincipalName);
        keyStoreEntry.setIssuerName(issuerName);
        return keyStoreEntry;
    }

    /**
     * Requests an online update of the given keyStore entry object and updates
     * the state of the given keyStoreEntryWrapper and the keyStore model
     * accordingly. Important: the keyStore is <b>NOT reStored to disk</b>. This
     * method is long running and could be run in a background thread. The data
     * model it modifies is itself thread safe (delegation of thread safety to
     * model).
     * <p>
     * The method will only return true if the <b>keyStore</b> is updated. This
     * only occurs if the certificate stored in the keyStore identified by the
     * keyStoreEntryWrapper was updated. The state of the keyStoreEntryWrapper's
     * {@link CertificateCSRInfo} object may be updated and the method will
     * still return false if the keyStore was not updated.
     *
     * @param keyStoreEntryWrapper
     * @return true if the keyStore (not the keyStoreEntryWrapper) was updated,
     * otherwise false.
     * @throws KeyStoreException
     */
    public boolean onlineUpdateKeyStoreEntry(KeyStoreEntryWrapper keyStoreEntryWrapper) throws KeyStoreException {
        return this.updateKeyStoreEntryWrapper(keyStoreEntryWrapper);
    }

    /**
     * Get the managed ClientKeyStore instance
     *
     * @return
     */
    public ClientKeyStore getClientKeyStore() {
        return this.clientKeyStore;
    }

    /**
     * Get the KeyStore entries as a map.
     *
     * @return
     */
    public Map<String, KeyStoreEntryWrapper> getKeyStoreEntryMap() {
        return this.keyStoreEntryMap;
    }

    /**
     * Delete the key store entry identified by the given alias from the
     * KeyStore and from <code>this.KeyStoreEntryMap</code>. Important: <b>does
     * NOT reStore (persist) the file</b>.
     *
     * @param alias
     * @throws KeyStoreException
     */
    public void deleteEntry(String alias) throws KeyStoreException {
        // delete from the cached list and also from the keyStore. Do not want
        // to call loadKeyStoreWithOnlineEntryUpdate(); 
        this.keyStoreEntryMap.remove(alias);
        this.clientKeyStore.deleteEntry(alias);
        //this.clientKeyStore.reStore();
    }

    /**
     * Check for updates for all KeyStoreEntryWrappers. Does not update the
     * keyStore.
     */

    /**
     * Download the <b>latest</b> cert/CSR status that matches the given
     * KeyStoreEntryWrapper's public key from the server and update the
     * KeyStoreEntryWrapper's member {@link CertificateCSRInfo} object (does NOT
     * update the keyStore).
     * <p/>
     * If keyStoreEntryWrapper has KEY_PAIR_ENTRY type, get the PublicKey and
     * query our CA to see if it has a record of that PubKey. If recognised,
     * create a new <code>CertificateCSRInfo</code> from the PubKey and the
     * server response (XML) and add as a member object of the
     * <code>keyStoreEntryWrapper</code>.
     *
     * @param keyStoreEntryWrapper
     * @deprecated use checkEntryForUpdates2 instead
     */
    private void checkEntryForUpdates(KeyStoreEntryWrapper keyStoreEntryWrapper) throws KeyStoreException {
        // return if not KEY_PAIR_ENTRY
        if (!keyStoreEntryWrapper.getEntryType().equals(KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY)) {
            return;
        }

        // We do not want to check every possible keystore entry against
        // our CA - the keystore may have many different certs issued from
        // different CAs, therefore only continue if our certificate is 
        // issued by our CA or is a self-signed CSR entry (a Self-signed 
        // CSR cert is created by this tool and used for CSRs where 
        // issuer dn == subject dn). 
        // TODO: - need to check that this is the user's cert if this is
        // a cert chain (e.g. userCert - eScienceCA - eScience Root).
        // If this entry is a chain, getCertificate returns the first
        // element in that chain is returned.
        /*
         * String keyStoreAlias = keyStoreEntryWrapper.getAlias();
         * X509Certificate cert = (X509Certificate)
         * clientKeyStore.getKeyStoreCopy().getCertificate(keyStoreAlias); if (
         * !(cert.getSubjectDN().toString().equals(cert.getIssuerDN().toString())
         * || cert.getIssuerDN().toString().equals(
         * SysProperty.getValue("ngsca.issuer.dn") )) ) { return;
         *  }
         */
        String keyStoreAlias = keyStoreEntryWrapper.getAlias();
        X509Certificate cert = (X509Certificate) clientKeyStore.getCertificate(keyStoreAlias);

        // check if self signed
        boolean isSelfSignedCert = cert.getSubjectX500Principal().getName().equals(cert.getIssuerX500Principal().getName());
        // check if cert has known issuer DN
        boolean hasKnownIssuerDN = false;
        String[] allKnownDNs = SysProperty.getValue("ngsca.issuer.dn").split(";");
        for (String allKnownDN : allKnownDNs) {
            String keystoreCertIssuerDN = cert.getIssuerX500Principal().getName();
            //System.out.println("Comparing: ["+keystoreCertIssuerDN+"] ["+allKnownDNs[i]+"]");
            if (keystoreCertIssuerDN.equals(allKnownDN)) {
                hasKnownIssuerDN = true;
                break;
            }
        }

        if (isSelfSignedCert || hasKnownIssuerDN) {
            // ok, we either have a self signed cert (CSR) or the cert 
            // has a known issuer DN so we will continue on. 
        } else {
            return;
        }

        //String oldStatus = keyStoreEntryWrapper.getServerCertificateCSRInfo().getStatus();
        // Query CA and determine if it recognises this public key, 
        // if not, return as the CA will not know the status. 
        PublicKey keystorePublicKey = cert.getPublicKey();
        ResourcesPublicKey resourcesPublicKey = new ResourcesPublicKey(keystorePublicKey);
        if (resourcesPublicKey.isExist()) {
            return;
        }

        // doc would be null if not recognized by CA
        Document doc = resourcesPublicKey.getDocument();
        NodeList certNodes;
        NodeList csrNodes;
        try {
            certNodes = (NodeList) extractCertificateExpr.evaluate(doc, XPathConstants.NODESET);
            csrNodes = (NodeList) exptractCSR_Expr.evaluate(doc, XPathConstants.NODESET);
        } catch (XPathExpressionException ex) {
            // coding error, we should be able to parse the expected response
            throw new IllegalStateException("Could not parse server response", ex);
        }

        // Ok, this keyStore entry's publicKey is recognised by our CA so first nullify 
        // the serverCertCSRInfo before we re-set it.
        keyStoreEntryWrapper.setServerCertificateCSRInfo(null);

        // Iterate each <certificate/> (takes precidence). 
        // For the last <certificate>, create a new CertificateCSRInfo object
        // populated from the returned XML and set the keyStoreEntryWrapper's CertificateCSRInfo member object. 
        //
        // If no <certificate> elements were returned, iterate each <CSR/> node.
        // For the last <CSR>, create a new CertificateCSRInfo object populated
        // from the returned XML and set the KeyStoreEntryWrapper's CertificateCSRInfo object.
        // 
        // Otherwise, keyStoreEntryWrapper's CertificateCSRInfo member object remains null. 
        // ADD CertificateCSRInfo entries
        // =============================================
        if (certNodes.getLength() != 0) {
            // Iterate all the <certificate> XML nodes      
            // If there are multiple returned nodes, 
            // the LAST node is used. This is ok because the server 
            // gurantees that the last node is the latest. 
            for (int i = 0; i < certNodes.getLength(); i++) {
                Node _certNode = certNodes.item(i);
                if (_certNode.getNodeType() == Node.ELEMENT_NODE) {
                    Element _certElement = (Element) _certNode;
                    NodeList _idList = _certElement.getElementsByTagName("id");
                    Element _idElement = (Element) _idList.item(0);
                    String _id = _idElement.getChildNodes().item(0).getTextContent();

                    NodeList _statusList = _certElement.getElementsByTagName("status");
                    Element _statusElement = (Element) _statusList.item(0);
                    String _status = _statusElement.getChildNodes().item(0).getTextContent();

                    NodeList _ownerList = _certElement.getElementsByTagName("owner");
                    Element _ownerElement = (Element) _ownerList.item(0);
                    String _owner = _ownerElement.getChildNodes().item(0).getTextContent();

                    NodeList _roleList = _certElement.getElementsByTagName("role");
                    Element _roleElement = (Element) _roleList.item(0);
                    String _role = _roleElement.getChildNodes().item(0).getTextContent();

                    // 
                    String _useremail = null;
                    NodeList _useremailList = _certElement.getElementsByTagName("useremail");
                    Element _useremailElement = (Element) _useremailList.item(0);
                    if (_useremailElement != null) {
                        NodeList childNodes = _useremailElement.getChildNodes();
                        if (childNodes != null && childNodes.item(0) != null) {
                            _useremail = childNodes.item(0).getTextContent();
                        }
                    }

                    NodeList _startdateList = _certElement.getElementsByTagName("startdate");
                    Element _startdateElement = (Element) _startdateList.item(0);
                    String _startdate = _startdateElement.getChildNodes().item(0).getTextContent();

                    NodeList _enddateList = _certElement.getElementsByTagName("enddate");
                    Element _enddateElement = (Element) _enddateList.item(0);
                    String _enddate = _enddateElement.getChildNodes().item(0).getTextContent();

                    NodeList _lifedaysList = _certElement.getElementsByTagName("lifedays");
                    Element _lifedaysElement = (Element) _lifedaysList.item(0);
                    String _lifedays = _lifedaysElement.getChildNodes().item(0).getTextContent();

                    NodeList _renewList = _certElement.getElementsByTagName("renew");
                    Element _renewElement = (Element) _renewList.item(0);
                    String _renew = _renewElement.getChildNodes().item(0).getTextContent();

                    //***Add a new Certificate CertificateCSRInfo to keyStoreEntryWrapper***
                    CertificateCSRInfo certServerInfo = new CertificateCSRInfo();
                    certServerInfo.setIsCSR(false); // note !
                    certServerInfo.setOwner(_owner);
                    certServerInfo.setStatus(_status); // could be VALID or another cert status
                    certServerInfo.setRole(_role);
                    certServerInfo.setUserEmail(_useremail);
                    certServerInfo.setId(_id); // 
                    certServerInfo.setStartDate(_startdate);
                    certServerInfo.setEndDate(_enddate);
                    certServerInfo.setLifeDays(_lifedays);
                    certServerInfo.setRenew(_renew);
                    // note we do not set the public key info 
                    //serverInfo.setPublickey(EncryptUtil.getEncodedPublicKey(keystorePublicKey));
                    keyStoreEntryWrapper.setServerCertificateCSRInfo(certServerInfo);
                }
            }
        } else if (csrNodes.getLength() != 0) {
            // iterate all the <CSR> nodes
            for (int i = 0; i < csrNodes.getLength(); i++) {
                Node csrNode = csrNodes.item(i);
                if (csrNode.getNodeType() == Node.ELEMENT_NODE) {
                    Element _csrElement = (Element) csrNode;
                    NodeList _idList = _csrElement.getElementsByTagName("id");
                    Element _idElement = (Element) _idList.item(0);
                    String _id = _idElement.getChildNodes().item(0).getTextContent();

                    NodeList _statusList = _csrElement.getElementsByTagName("status");
                    Element _statusElement = (Element) _statusList.item(0);
                    String _status = _statusElement.getChildNodes().item(0).getTextContent();

                    NodeList _ownerList = _csrElement.getElementsByTagName("owner");
                    Element _ownerElement = (Element) _ownerList.item(0);
                    String _owner = _ownerElement.getChildNodes().item(0).getTextContent();

                    NodeList _roleList = _csrElement.getElementsByTagName("role");
                    Element _roleElement = (Element) _roleList.item(0);
                    String _role = _roleElement.getChildNodes().item(0).getTextContent();

                    NodeList _useremailList = _csrElement.getElementsByTagName("useremail");
                    Element _useremailElement = (Element) _useremailList.item(0);
                    String _useremail = _useremailElement.getChildNodes().item(0).getTextContent();

                    String description = "Your certificate has an unrecognized status";
                    if ("DELETED".equals(_status)) {
                        description = "Your certificate has been deleted from our CA.";
                    } else if ("NEW".equals(_status)) {
                        description = "Your certificate has been submitted and is awaiting approval.";
                    } else if ("RENEW".equals(_status)) {
                        description = "Your renewal certificate has been submitted and is awaiting approval.";
                    } else if ("APPROVED".equals(_status)) {
                        description = "Your certificate has been approved and is awaiting CA operator signing.";
                    }
                    //else if("VALID".equals(_status)){
                    // VALID is not an enum status for a CSR, only for a cert 
                    //}

                    //***Add a new CSR CertificateCSRInfo to keyStoreEntryWrapper***
                    CertificateCSRInfo csrServerInfo = new CertificateCSRInfo();
                    //serverInfo.setPublickey(EncryptUtil.getEncodedPublicKey(keystorePublicKey));
                    csrServerInfo.setIsCSR(true); // note !
                    csrServerInfo.setOwner(_owner);
                    csrServerInfo.setRole(_role);
                    csrServerInfo.setUserEmail(_useremail);
                    csrServerInfo.setId(_id);
                    csrServerInfo.setDescription(description);
                    csrServerInfo.setStatus(_status);
                    // note we do not set the public key or date info.
                    keyStoreEntryWrapper.setServerCertificateCSRInfo(csrServerInfo);
                }
            }
        }
    }

    /**
     * If the given {@link KeyStoreEntryWrapper} has both a <tt>VALID</tt>
     * status and a known certificate serial ID (according to the CA server),
     * download the <b>latest</b> certificate and update
     * <code>this.clientKeyStore</code> (note, the keyStore is NOT reStored to
     * disk).
     * <p>
     * There are a number of pre-conditions that must be satisfied for the
     * update to occur. First call
     * {@link #onlineUpdateKeyStoreEntry(uk.ngs.ca.certificate.management.KeyStoreEntryWrapper)},
     * then check the following pre-conditions;
     * <ul>
     * <li>It is of type
     * {@link KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE#KEY_PAIR_ENTRY}</li>
     * <li>It has a member {@link CertificateCSRInfo} object with a status of
     * 'VALID'</li>
     * <li>The {@link CertificateCSRInfo} object has a serial ID for this
     * certificate.</li>
     * </ul>
     * If these pre-conditions are true, then download the cert from the CA
     * server and compare it to the cert in the managed keyStore. If the two
     * certificates are identical, we do not need to update/replace the cert in
     * our keyStore so return false.
     * <p>
     * If the two certificates are different, then either;
     * <ul>
     * <li>The certificate for this entry has changed on the server (maybe some
     * new attributes have been added)</li>
     * <li>The certificate in our keyStore was a self-signed CSR cert which has
     * just been signed on the server.</li>
     * </ul>
     * Therefore, proceed to compare the PublicKey of the downloaded cert with
     * the PubKey of keyStore cert to ensure they correspond. If the keys are
     * identical, then replace the keyStore cert entry with the newly downloaded
     * cert under the same alias (the private key already resides in keyStore).
     *
     * @param keyStoreEntryWrapper
     * @return true if <code>this.clientKeyStore</code> was updated, otherwise
     * false.
     * @deprecated This method will be combined into checkEntryForUpdates2
     */
    private boolean updateKeyStoreEntryWithCert_IfVALID(KeyStoreEntryWrapper keyStoreEntryWrapper) {

        if (keyStoreEntryWrapper.getEntryType().equals(KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY)
                && keyStoreEntryWrapper.getServerCertificateCSRInfo() != null
                && "VALID".equals(keyStoreEntryWrapper.getServerCertificateCSRInfo().getStatus())
                && keyStoreEntryWrapper.getServerCertificateCSRInfo().getId() != null) {

            // Download the cert from server by passing the id (dont think this returns a cert chain)
            X509Certificate downloadedCert
                    = (new CertificateDownload(keyStoreEntryWrapper.getServerCertificateCSRInfo().getId()))
                    .getCertificate();

            if (downloadedCert == null) {
                // maybe we temporarily lost connection or the code that downloaded 
                // the certificate above returned null? 
                // Should probably report some kind of issue here to flag to the user. 
                return false;
            } else {
                try {
                    PublicKey downloadedPublicKey = downloadedCert.getPublicKey();
                    if (downloadedPublicKey == null) {
                        return false;
                    }
                    Certificate[] ksChain = this.clientKeyStore
                            .getCertificateChain(keyStoreEntryWrapper.getAlias());
                    if (ksChain == null) {
                        // the keystore entry may have been deleted in another thread.
                        return false;
                    }
                    PublicKey keystorePublicKey = ksChain[0].getPublicKey();

                    // We only want to update the clientKeyStore cert IF there 
                    // were changes to the cert on the server. We do not want to 
                    // replace each/every cert if it is identical to what we already have. 
                    X509Certificate x509 = this.clientKeyStore.getX509Certificate(keyStoreEntryWrapper.getAlias());
                    if (x509 == null) {
                        return false;
                    }
                    // Full chain: downloaded cert, every intermediate, root.
                    X509Certificate[] chain = fullChainFor(downloadedCert, ksChain);
                    if (x509.equals(downloadedCert) && Arrays.equals(ksChain, chain)) {
                        return false;
                    }

                    // Ok, they are not the same so either; 
                    //  a) the cert has changed on the server (e.g. maybe some new usage extensions were addeed)
                    //  b) the cert we have in the keyStore is a self-signed CSR
                    // Regardless, check that the public keys are the same 
                    // (they must be identical for the private key to match) 
                    if (downloadedPublicKey.equals(keystorePublicKey)) {
                        // Replace the certificate chain
                        PrivateKey privateKey
                                = (PrivateKey) this.clientKeyStore.getKey(keyStoreEntryWrapper.getAlias(), mKeystorePASSPHRASE);

                        // Maybe the key was removed in an external process? 
                        // (keyStore is a normal pkcs12 that can be accessed from command line) 
                        if (privateKey == null) {
                            return false;
                        }
                        // Replace keystore entry with the new downloaded cert, its full
                        // issuer chain and its corresponding key (i.e. replaces the
                        // self-signed cert that was used to do the CSR, or a stored
                        // chain that was missing its intermediate/root certificates).
                        System.out.println("Replacing: [" + keyStoreEntryWrapper.getAlias() + "] with downloaded cert");

                        // Synchronize composite action on same lock so that 
                        // it is an atomic. The lock  is reentrant so we can call 
                        // out to nested synchronized methods locked by the same lock. 
                        synchronized (this.clientKeyStore) {
                            this.clientKeyStore.deleteEntry(keyStoreEntryWrapper.getAlias());
                            this.clientKeyStore.setKeyEntry(keyStoreEntryWrapper.getAlias(), privateKey, mKeystorePASSPHRASE, chain);
                        }
                        // ok, we have have replaced this cert, so we need to
                        // update the ketStoreEntryWrapper for this entry.
                        // Note, no need to update online info (this.initCertCSRInfo_WithOnlineCheck(keyStoreEntryWrapper));
                        // or the alias as these have not changed. 
                        keyStoreEntryWrapper.setX500PrincipalName(chain[0].getSubjectX500Principal().toString());
                        keyStoreEntryWrapper.setIssuerName(chain[0].getIssuerX500Principal().toString());
                        keyStoreEntryWrapper.setNotAfter(chain[0].getNotAfter());
                        keyStoreEntryWrapper.setNotBefore(chain[0].getNotBefore());
                        return true;
                    }
                } catch (Exception ex) {
                    Logger.getLogger(ClientKeyStoreCaServiceWrapper.class.getName()).log(Level.SEVERE, null, ex);
                    throw new IllegalStateException(ex);
                }
            }
        }
        return false;
    }

    /**
     * Download and update the {@link CertificateCSRInfo} for the given
     * KeyStoreEntryWrapper and optionally update
     * <code>this.clientKeyStore</code> with a newly downloaded certificate if
     * an update is available. Important note: the keyStore is NOT reStored to
     * disk.
     * <p>
     * The update details are as follows:
     * <p>
     * a) Update the <code>CertificateCSRInfo</code> object. If
     * keyStoreEntryWrapper has KEY_PAIR_ENTRY type, get the PublicKey and use
     * it to query our CA to see if it has a record of that PubKey. If known,
     * create a new <code>CertificateCSRInfo</code> from the server
     * response(XML) and add update the
     * <code>keyStoreEntryWrapper.CertificateCSRInfo</code> object.
     * <p>
     * b) Optionally update the corresponding KeyStore certificate if the
     * following pre-conditions are met:
     * <ul>
     * <li>KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE has value of KEY_PAIR_ENTRY
     * representing a local cert or CSR</li>
     * <li>Updated KeyStoreEntryWrapper's {@link CertificateCSRInfo} object has
     * a status of 'VALID'</li>
     * <li>Updated KeyStoreEntryWrapper's {@link CertificateCSRInfo} object has
     * a serial ID value.</li>
     * <li>Updated KeyStoreEntryWrapper X509Certificate is DIFFERENT from the
     * downloaded X509Certificate (If the two certificates are identical, we do
     * not need to update/replace the cert in our keyStore so return false)</li>
     * <li>KeyStoreEntryWrapper X059Certificate.publicKey is the SAME as the
     * downloaded X509Cert.publicKey (they must be the same for the local
     * private key to match)</li>
     * </ul>
     * <p>
     * If the two certificates are DIFFERENT but have the SAME public keys, then
     * either;
     * <ul>
     * <li>The certificate for this entry has changed on the server without
     * changing the serial_id (maybe some new attributes have been added)</li>
     * <li>The certificate has been re-issued with the same public key which
     * changes the certificate serial_id (for whatever reason)</li>
     * <li>The certificate in our keyStore was a self-signed CSR cert which has
     * just been signed on the server and made available for download.</li>
     * </ul>
     *
     * @param keyStoreEntryWrapper
     * @return True if and only if the keyStore was updated with a new
     * certificate.
     */
    private boolean updateKeyStoreEntryWrapper(KeyStoreEntryWrapper keyStoreEntryWrapper) throws KeyStoreException {
        // return if not KEY_PAIR_ENTRY
        if (!keyStoreEntryWrapper.getEntryType().equals(KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY)) {
            return false;
        }

        // We do not want to check every possible keystore entry against
        // our CA - the keystore may have many different certs issued from
        // different CAs, therefore only continue if our certificate is 
        // issued by our CA or is a self-signed CSR entry (a Self-signed 
        // CSR cert is created by this tool and used for CSRs where 
        // issuer dn == subject dn). 
        // TODO: - need to check that this is the user's cert if this is
        // a cert chain (e.g. userCert - eScienceCA - eScience Root).
        // If this entry is a chain, getCertificate returns the first
        // element in that chain is returned.
        /*
         * String keyStoreAlias = keyStoreEntryWrapper.getAlias();
         * X509Certificate cert = (X509Certificate)
         * clientKeyStore.getKeyStoreCopy().getCertificate(keyStoreAlias); if (
         * !(cert.getSubjectDN().toString().equals(cert.getIssuerDN().toString())
         * || cert.getIssuerDN().toString().equals(
         * SysProperty.getValue("ngsca.issuer.dn") )) ) { return;
         *  }
         */
        String keyStoreAlias = keyStoreEntryWrapper.getAlias();
        X509Certificate cert = (X509Certificate) clientKeyStore.getCertificate(keyStoreAlias);

        // check if self signed
        boolean isSelfSignedCert = cert.getSubjectX500Principal().getName().equals(cert.getIssuerX500Principal().getName());
        // check if cert has known issuer DN
        boolean hasKnownIssuerDN = false;
        String[] allKnownDNs = SysProperty.getValue("ngsca.issuer.dn").split(";");
        for (String allKnownDN : allKnownDNs) {
            String keystoreCertIssuerDN = cert.getIssuerX500Principal().getName();
            //System.out.println("Comparing: ["+keystoreCertIssuerDN+"] ["+allKnownDNs[i]+"]");
            if (keystoreCertIssuerDN.equals(allKnownDN)) {
                hasKnownIssuerDN = true;
                break;
            }
        }

        if (isSelfSignedCert || hasKnownIssuerDN) {
            // ok, we either have a self signed cert (CSR) or the cert 
            // has a known issuer DN so we will continue on. 
        } else {
            return false;
        }
        //cert.verify(ukCAPublicKey);

        //String oldStatus = keyStoreEntryWrapper.getServerCertificateCSRInfo().getStatus();
        // Query CA and determine if it recognises this public key, 
        // if not, return as the CA will not know the status. 
        PublicKey keystorePublicKey = cert.getPublicKey();
        ResourcesPublicKey resourcesPublicKey = new ResourcesPublicKey(keystorePublicKey);
        if (resourcesPublicKey.isExist()) {
            return false;
        }

        // doc would be null if not recognized by CA
        Document doc = resourcesPublicKey.getDocument();
        NodeList certNodes;
        NodeList csrNodes;
        try {
            certNodes = (NodeList) extractCertificateExpr.evaluate(doc, XPathConstants.NODESET);
            csrNodes = (NodeList) exptractCSR_Expr.evaluate(doc, XPathConstants.NODESET);
        } catch (XPathExpressionException ex) {
            // coding error, we should be able to parse the expected response
            throw new IllegalStateException("Could not parse server response", ex);
        }

        // Ok, this keyStore entry's publicKey is recognised by our CA so first nullify 
        // the serverCertCSRInfo before we re-set it.
        keyStoreEntryWrapper.setServerCertificateCSRInfo(null);

        // Iterate each <certificate/> (takes precidence). 
        // For the last <certificate>, create a new CertificateCSRInfo object
        // populated from the returned XML and set the keyStoreEntryWrapper's CertificateCSRInfo member object. 
        //
        // If no <certificate> elements were returned, iterate each <CSR/> node.
        // For the last <CSR>, create a new CertificateCSRInfo object populated
        // from the returned XML and set the KeyStoreEntryWrapper's CertificateCSRInfo object.
        // 
        // Otherwise, keyStoreEntryWrapper's CertificateCSRInfo member object remains null. 
        // ADD CertificateCSRInfo entries
        // =============================================
        boolean certUpdatedInKeyStore = false;
        if (certNodes.getLength() != 0) {
            String lastDownloadedX509CertString = null;

            // Iterate all the <certificate> XML nodes      
            // If there are multiple returned nodes, 
            // the LAST node is used. This is ok because the server 
            // gurantees that the last node is the latest. 
            for (int i = 0; i < certNodes.getLength(); i++) {
                Node _certNode = certNodes.item(i);
                if (_certNode.getNodeType() == Node.ELEMENT_NODE) {
                    Element _certElement = (Element) _certNode;

                    NodeList _idList = _certElement.getElementsByTagName("id");
                    Element _idElement = (Element) _idList.item(0);
                    String _id = _idElement.getChildNodes().item(0).getTextContent();

                    NodeList _x509List = _certElement.getElementsByTagName("X509Certificate");
                    if (_x509List != null) {
                        Element _x509Element = (Element) _x509List.item(0);
                        lastDownloadedX509CertString = _x509Element.getChildNodes().item(0).getTextContent();
                    }

                    NodeList _statusList = _certElement.getElementsByTagName("status");
                    Element _statusElement = (Element) _statusList.item(0);
                    String _status = _statusElement.getChildNodes().item(0).getTextContent();

                    NodeList _ownerList = _certElement.getElementsByTagName("owner");
                    Element _ownerElement = (Element) _ownerList.item(0);
                    String _owner = _ownerElement.getChildNodes().item(0).getTextContent();

                    NodeList _roleList = _certElement.getElementsByTagName("role");
                    Element _roleElement = (Element) _roleList.item(0);
                    String _role = _roleElement.getChildNodes().item(0).getTextContent();

                    // 
                    String _useremail = null;
                    NodeList _useremailList = _certElement.getElementsByTagName("useremail");
                    Element _useremailElement = (Element) _useremailList.item(0);
                    if (_useremailElement != null) {
                        NodeList childNodes = _useremailElement.getChildNodes();
                        if (childNodes != null && childNodes.item(0) != null) {
                            _useremail = childNodes.item(0).getTextContent();
                        }
                    }

                    NodeList _startdateList = _certElement.getElementsByTagName("startdate");
                    Element _startdateElement = (Element) _startdateList.item(0);
                    String _startdate = _startdateElement.getChildNodes().item(0).getTextContent();

                    NodeList _enddateList = _certElement.getElementsByTagName("enddate");
                    Element _enddateElement = (Element) _enddateList.item(0);
                    String _enddate = _enddateElement.getChildNodes().item(0).getTextContent();

                    NodeList _lifedaysList = _certElement.getElementsByTagName("lifedays");
                    Element _lifedaysElement = (Element) _lifedaysList.item(0);
                    String _lifedays = _lifedaysElement.getChildNodes().item(0).getTextContent();

                    NodeList _renewList = _certElement.getElementsByTagName("renew");
                    Element _renewElement = (Element) _renewList.item(0);
                    String _renew = _renewElement.getChildNodes().item(0).getTextContent();

                    //***Update KeyStoreWrapper with a new CertificateCSRInfo object***
                    CertificateCSRInfo certServerInfo = new CertificateCSRInfo();
                    certServerInfo.setIsCSR(false); // note !
                    certServerInfo.setOwner(_owner);
                    certServerInfo.setStatus(_status); // could be VALID or another cert status like REVOKED
                    certServerInfo.setRole(_role);
                    certServerInfo.setUserEmail(_useremail);
                    certServerInfo.setId(_id); // 
                    certServerInfo.setStartDate(_startdate);
                    certServerInfo.setEndDate(_enddate);
                    certServerInfo.setLifeDays(_lifedays);
                    certServerInfo.setRenew(_renew);
                    // note we do not set the public key info 
                    //serverInfo.setPublickey(EncryptUtil.getEncodedPublicKey(keystorePublicKey));
                    keyStoreEntryWrapper.setServerCertificateCSRInfo(certServerInfo);
                }
            }
            if (lastDownloadedX509CertString != null) {
                try (InputStream inputStream = new ByteArrayInputStream(lastDownloadedX509CertString.getBytes())) {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509Certificate downloadedCert = (X509Certificate) cf.generateCertificate(inputStream);
                    // update our certificate in our keyStore with the downloadedCert (or not)
                    if (this.updateKeyStoreEntryWithCert(keyStoreEntryWrapper, downloadedCert)) {
                        certUpdatedInKeyStore = true;
                    }
                } catch (CertificateException | IOException ex) {
                    // maybe the server is returning junk? we should continue on and not return (defensive)
                    Logger.getLogger(ClientKeyStoreCaServiceWrapper.class.getName()).log(Level.SEVERE, null, ex);
                }
            }

        } else if (csrNodes.getLength() != 0) {
            // iterate all the <CSR> nodes
            for (int i = 0; i < csrNodes.getLength(); i++) {
                Node csrNode = csrNodes.item(i);
                if (csrNode.getNodeType() == Node.ELEMENT_NODE) {
                    Element _csrElement = (Element) csrNode;
                    NodeList _idList = _csrElement.getElementsByTagName("id");
                    Element _idElement = (Element) _idList.item(0);
                    String _id = _idElement.getChildNodes().item(0).getTextContent();

                    NodeList _statusList = _csrElement.getElementsByTagName("status");
                    Element _statusElement = (Element) _statusList.item(0);
                    String _status = _statusElement.getChildNodes().item(0).getTextContent();

                    NodeList _ownerList = _csrElement.getElementsByTagName("owner");
                    Element _ownerElement = (Element) _ownerList.item(0);
                    String _owner = _ownerElement.getChildNodes().item(0).getTextContent();

                    NodeList _roleList = _csrElement.getElementsByTagName("role");
                    Element _roleElement = (Element) _roleList.item(0);
                    String _role = _roleElement.getChildNodes().item(0).getTextContent();

                    NodeList _useremailList = _csrElement.getElementsByTagName("useremail");
                    Element _useremailElement = (Element) _useremailList.item(0);
                    String _useremail = _useremailElement.getChildNodes().item(0).getTextContent();

                    String description = "Your certificate has an unrecognized status";
                    if ("DELETED".equals(_status)) {
                        description = "Your certificate has been deleted from our CA.";
                    } else if ("NEW".equals(_status)) {
                        description = "Your certificate has been submitted and is awaiting approval.";
                    } else if ("RENEW".equals(_status)) {
                        description = "Your renewal certificate has been submitted and is awaiting approval.";
                    } else if ("APPROVED".equals(_status)) {
                        description = "Your certificate has been approved and is awaiting CA operator signing.";
                    }

                    //***Add a new CSR CertificateCSRInfo to keyStoreEntryWrapper***
                    CertificateCSRInfo csrServerInfo = new CertificateCSRInfo();
                    //serverInfo.setPublickey(EncryptUtil.getEncodedPublicKey(keystorePublicKey));
                    csrServerInfo.setIsCSR(true); // note !
                    csrServerInfo.setOwner(_owner);
                    csrServerInfo.setRole(_role);
                    csrServerInfo.setUserEmail(_useremail);
                    csrServerInfo.setId(_id);
                    csrServerInfo.setDescription(description);
                    csrServerInfo.setStatus(_status);
                    // note we do not set the public key or date info.
                    keyStoreEntryWrapper.setServerCertificateCSRInfo(csrServerInfo);
                }
            }
        }
        return certUpdatedInKeyStore;
    }

    /**
     * Update keyStoreEntryWrapper with the downloadedCert and return true if
     * the following pre-conditions are met.
     * <ul>
     * <li>KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE has value of
     * KEY_PAIR_ENTRY</li>
     * <li>KeyStoreEntryWrapper's {@link CertificateCSRInfo} object has a status
     * of 'VALID'</li>
     * <li>KeyStoreEntryWrapper's {@link CertificateCSRInfo} object has a serial
     * ID for this certificate.</li>
     * <li>KeyStoreEntryWrapper represents a local X509Certificate (i.e. cert or
     * CSR)</li>
     * <li>KeyStoreEntryWrapper X059Certificate is DIFFERENT from the downloaded
     * X509Certificate</li>
     * <li>KeyStoreEntryWrapper X059Certificate.publicKey is the SAME as the
     * downloaded X509Cert.publicKey</li>
     * </ul>
     *
     * @param keyStoreEntryWrapper
     * @param downloadedX509
     * @return
     */
    private boolean updateKeyStoreEntryWithCert(
            KeyStoreEntryWrapper keyStoreEntryWrapper, X509Certificate downloadedX509) {

        if (keyStoreEntryWrapper.getEntryType().equals(KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY)
                && keyStoreEntryWrapper.getServerCertificateCSRInfo() != null
                && "VALID".equals(keyStoreEntryWrapper.getServerCertificateCSRInfo().getStatus())
                && keyStoreEntryWrapper.getServerCertificateCSRInfo().getId() != null) {

            try {
                PublicKey downloadedPublicKey = downloadedX509.getPublicKey();
                if (downloadedPublicKey == null) {
                    return false;
                }
                Certificate[] ksChain = this.clientKeyStore
                        .getCertificateChain(keyStoreEntryWrapper.getAlias());
                if (ksChain == null) {
                    // the keystore entry may have been deleted in another thread.
                    return false;
                }
                PublicKey keystorePublicKey = ksChain[0].getPublicKey();

                // We only want to update the clientKeyStore cert IF there 
                // were changes to the cert on the server. We do not want to 
                // replace each/every cert if it is identical to what we already have. 
                X509Certificate localKeyStoreX509 = this.clientKeyStore.getX509Certificate(keyStoreEntryWrapper.getAlias());
                if (localKeyStoreX509 == null) {
                    return false;
                }
                // Full chain: downloaded cert, every intermediate, root.
                X509Certificate[] chain = fullChainFor(downloadedX509, ksChain);
                // VALUE equality, not instance equality. Same cert but a stored
                // chain that is missing parents still gets rewritten.
                if (localKeyStoreX509.equals(downloadedX509) && Arrays.equals(ksChain, chain)) {
                    return false;
                }

                // Ok, they are not the same so either; 
                //  a) the cert has changed on the server (e.g. maybe some new usage extensions were addeed)
                //  b) the cert we have in the keyStore is a self-signed CSR
                // Regardless, check that the public keys are the same 
                // (they must be identical for the private key to match) 
                if (downloadedPublicKey.equals(keystorePublicKey)) {
                    // Replace the certificate chain
                    PrivateKey keyStorePrivateKey
                            = (PrivateKey) this.clientKeyStore.getKey(keyStoreEntryWrapper.getAlias(), mKeystorePASSPHRASE);

                    // Maybe the key was removed in an external process? 
                    // (keyStore is a normal pkcs12 that can be accessed from command line) 
                    if (keyStorePrivateKey == null) {
                        return false;
                    }
                    // Replace keystore entry with the new downloaded cert, its full
                    // issuer chain and its corresponding key (i.e. replaces the
                    // self-signed cert that was used to do the CSR, or a stored
                    // chain that was missing its intermediate/root certificates).
                    System.out.println("Replacing: [" + keyStoreEntryWrapper.getAlias() + "] with downloaded cert");

                    // Synchronize composite action on same lock so that 
                    // it is an atomic. The lock  is reentrant so we can call 
                    // out to nested synchronized methods locked by the same lock. 
                    synchronized (this.clientKeyStore) {
                        this.clientKeyStore.deleteEntry(keyStoreEntryWrapper.getAlias());
                        this.clientKeyStore.setKeyEntry(keyStoreEntryWrapper.getAlias(), keyStorePrivateKey, mKeystorePASSPHRASE, chain);
                    }
                    // ok, we have have replaced this cert, so we need to
                    // update the ketStoreEntryWrapper for this entry.
                    // Note, no need to update online info (this.initCertCSRInfo_WithOnlineCheck(keyStoreEntryWrapper));
                    // or the alias as these have not changed. 
                    keyStoreEntryWrapper.setX500PrincipalName(chain[0].getSubjectX500Principal().toString());
                    keyStoreEntryWrapper.setIssuerName(chain[0].getIssuerX500Principal().toString());
                    keyStoreEntryWrapper.setNotAfter(chain[0].getNotAfter());
                    keyStoreEntryWrapper.setNotBefore(chain[0].getNotBefore());
                    return true;
                }
            } catch (Exception ex) {
                Logger.getLogger(ClientKeyStoreCaServiceWrapper.class.getName()).log(Level.SEVERE, null, ex);
                throw new IllegalStateException(ex);
            }
        }
        return false;
    }

}
