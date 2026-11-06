README
David Meredith 
Disclaimer - Much of the code needs refactoring (many parts are poorly written 
with 3rd party legacy). 

Requirements
===============
Java JDK 1.11 +
Maven
netbeans 8.2+ (it's used for building the GUI)

CertWizard is a java client tool to access and manage user/host certificates. 
It is the client gui for the corresponding (Restlet based) CA-Server, which it
talks to over HTTPS using the JDK's java.net.http client (see
uk.ngs.ca.common.CaHttpClient for timeouts, retries and offline handling).  

CertWizard supports the following functions:

1. Working either online or offline.
2. Apply for / Request a new user (host or personal) certificate.
3. Import user certificate from pkcs12 file.
4. Export user certificate to pkcs12 file.
5. Renew user certificate.
6. Revoke user certificate.
7. Remove user certificate from CertWizard.
8. Create user cert/key pem files (known as Install in the tool).


Configuration:
===============
1) Copy 'uk/ngs/ca/tools/property/template.configure.properties' 
         to:
        'uk/ngs/ca/tools/property/configure.properties' (and modify as required)

2) Modify the copied properties file as required.  
    If you want to access a different CA server, just overwrite configure.properties by
    using the above template files.

3) Update the root CA certificates at src/main/resources/escience*.pem

This file is configured with the UK eScience CA chain (CA cert and root) so it can
be used against cwiz-live and cwiz.ca without modification.


Build / Compile
====================

mvn clean
mvn package -DskipTests # this skips running tests

Running:
===========
cd into the dist dir and run: 
java -jar Certwizard.jar

An executable installer for Windows is also built if you build this on Windows, 
which includes a slimmed down JRE 11 so the user doesn't need Java installed.


 
Code Signing for deployment via Java WebStart as a RIA (Rich Internet App)
===========================================================================
Java Web Start is no longer supported! This is left here for historical reference.

To deploy Cwiz via Java WebStart, you need to sign all the dist/**/*.jar files. To do this, 
you can use either:
a) the 'SignDistJars' ant target in the build.xml file. This target requires 
the 'env.properties' file (use the provided 'sample.env.properties' as a template).  
In this file, specify your code-signing certificate and the corresponding details, 
you can then run this ant target to sign all the dist/**/*.jar files. 

b) use jarsigner directly on the command line: 
   e.g.  
jarsigner.exe -keystore ./Comodo-CodeSign.p12 -storetype pkcs12 <jarfiletosign.jar> cert_alias
  or, for many jars in dir: 
for i in dist/**/*.jar; do jarsigner.exe -keystore ./mykeystore.p12 -storepass somepassword -storetype pkcs12 $i "cert_alias" ; done

To verify the jar after signing, you can use (where [cert_alias] is optional):
jarsigner.exe -verify -keystore ./Comodo-CodeSign.p12 -storetype pkcs12 -storepass somepassword weakssl.jar [cert_alias]

Signing Notes: 
---------------
+) Permissions attribute in jar manifest: 
We need to deploy via WebStart using a single .jnlp file (see myproxy.jnlp) rather 
than using multiple jnlp files linked using jnlp <extensions/>. In doing this, 
all the jars must be signed using the same code-sign signature. 
In addition, deploying using a single .jnlp file means the 'Permissions' manifest 
file attribute defined in the *main* jar file will also apply to all the other jars. 
The Permissions mf attribute is now mandatory as of JDK 1.7u51 (January 2014).  
If another jar is loaded as a jnlp <extension/>, it appears that the Permissions 
attribute needs to be added to the jar using:  
  'jar ufm some.jar manifestUpdates.txt' 
(where manifestUpdates.txt file defines the manifest updates, e.g. adding the 
Permissions mf attribute followed by a newline) e.g: 
Permissions: all-permissions 

See: http://docs.oracle.com/javase/tutorial/deployment/jar/modman.html

Updating digitally signed jars is problematic - you may first need to remove the jar's 
existing signature (can remove jar signatures using a zip utility), update the jar's mf 
file as described above, and then re-sign the jar.  

+) It is important that all the jars in a jnlp are signed using the same signature 
algorithm. If you do not, you may encounter the following error:
 'java.io.IOException: invalid SHA1 signature file digest for org/bouncycastle/asn1/ocsp/ResponderID.class' 

This exception occurred because the BC jar was signed using SHA1, whilst all the other jars 
were signed using SHA256 (the JDK1.7 default is to sign using SHA256, whilst JDK1.6 uses SHA1). 
You have been warned - see: http://www.captaincasademo.com/forum/posts/list/1831.page 

Note, to get around this, you can either sign the jar file using the same alg 
(e.g. if jar is already signed using SHA1 you may need to specify digestalg="SHA1" sigalg="SHA1"), or 
Use a zip tool like winrar and delete the existing signatures in META-INF, e.g. SOME_SIG_NAME.SF and SOME_SIG_NAME.RSA
then resign with your code-sign cert. 



JCE/JCA code signing for cryptography extensions
=================================================
This is left here for historical reference, NOT required, we don't modify BC any more!

This application deploys Java crytpo libraries - the 'bcprov-jdk15-166.jar' from 
Bouncy Castle. This library needs to be signed by a special JCA/JCE certificate that
can be requested free from Oracle (you can't use your normal code-sign cert, it has
to be a special JCE code-sign cert as described at the link below). Note, this jar  
has already been signed by BC's JCE code-sign cert but you can replace the 
BC JCE signature with your own signature (remove the BC signature using a zip util and 
re-sign as normal using jarsigner and your JCE code-sign cert).   
 
Getting a JCE code sign cert: 
http://www.oracle.com/technetwork/java/javase/tech/getcodesigningcertificate-361306.html

Note, If you are deploying via webstart, this lib must therefore be signed twice:  
  a) the BC JCE signature (or another signature from a JCA signing cert) 
     verifying this jar is a valid JCA provider  
  b) the normal code-sign signature for Webstart/RIA deployment. 

  (code signing for Webstart deployment and signing a jar as a valid JCE/JCA provider are two 
  separate things !)   

   http://www.oracle.com/technetwork/java/javase/tech/getcodesigningcertificate-361306.html
   http://docs.oracle.com/javase/7/docs/technotes/guides/jweb/no_redeploy.html#permissions


Signing stuff: 
https://blogs.oracle.com/java-platform-group/entry/new_security_requirements_for_rias 
http://www.oracle.com/technetwork/java/javase/overview/ria-checklist-2055184.html 
http://stackoverflow.com/questions/20218467/what-is-jce-code-signing-ca 
http://docs.oracle.com/javase/tutorial/deployment/jar/intro.html 
http://docs.oracle.com/javase/7/docs/technotes/guides/jweb/manifest.html 
http://docs.oracle.com/javase/tutorial/deployment/jar/modman.html 
http://www.oracle.com/technetwork/java/javase/tech/getcodesigningcertificate-361306.html 
http://stackoverflow.com/questions/8176166/invalid-sha1-signature-file-digest 
http://stackoverflow.com/questions/11673707/java-web-start-jar-signing-issue 
http://www.captaincasademo.com/forum/posts/list/1831.page 


TODOs:
======
There are lots of to do items. Much of the code needs refactoring (many parts 
are poorly written with 3rd party legacy): 

- Export multiple certificates into a PKCS12 file (currently, can only export one at a time)  
- When exporting certs, need to change the perms on *nix box much like 
  when installing the pem files (think this may be done - check).  
- Edit/choose Colours 
- Apply needs fixing for the regex pattern to prevent accented chars. 
