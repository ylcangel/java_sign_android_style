package com.angeltoms.signer;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 完全依照Android源码实现的签名工具类 同时添加了从apk中解析签名获取签名byte数组或者byte数组对应的字符串
 *
 * @author AngelToms
 */
public class SignatureUtils {

//		1 MANIFEST.MF中的各SHA-1值 == SHA-1(除META-INF目录外的文件)；
//		2 CERT.SF中各值 == (SHA-1 + Base64)(MANIFEST.MF文件及各子项)；
//		3 CERT.RSA/DSA/EC == 公钥＋加密算法信息等；
    private final byte[] mSignature;
    private int mHashCode;
    private boolean mHaveHashCode;

    /**
     * Create Signature from an existing raw byte array.
     */
    public SignatureUtils(byte[] signature) {
        mSignature = (byte[]) signature.clone();
    }

    private static final int parseHexDigit(int nibble) {
        if ('0' <= nibble && nibble <= '9') {
            return nibble - '0';
        } else if ('a' <= nibble && nibble <= 'f') {
            return nibble - 'a' + 10;
        } else if ('A' <= nibble && nibble <= 'F') {
            return nibble - 'A' + 10;
        } else {
            throw new IllegalArgumentException("Invalid character " + nibble + " in hex string");
        }
    }

    /**
     * Create Signature from a text representation previously returned by
     * {@link #toChars} or {@link #toCharsString()}. Signatures are expected to
     * be a hex-encoded ASCII string.
     *
     * @param text hex-encoded string representing the signature
     * @throws IllegalArgumentException when signature is odd-length
     */
    public SignatureUtils(String text) {
        final byte[] input = text.getBytes();
        final int N = input.length;

        if (N % 2 != 0) {
            throw new IllegalArgumentException("text size " + N + " is not even");
        }

        final byte[] sig = new byte[N / 2];
        int sigIndex = 0;

        for (int i = 0; i < N;) {
            final int hi = parseHexDigit(input[i++]);
            final int lo = parseHexDigit(input[i++]);
            sig[sigIndex++] = (byte) ((hi << 4) | lo);
        }

        mSignature = sig;
    }

    /**
     * Encode the Signature as ASCII text.
     */
    public char[] toChars() {
        return toChars(null, null);
    }

    /**
     * Encode the Signature as ASCII text in to an existing array.
     *
     * @param existingArray Existing char array or null.
     * @param outLen Output parameter for the number of characters written in to
     * the array.
     * @return Returns either <var>existingArray</var> if it was large enough to
     * hold the ASCII representation, or a newly created char[] array if needed.
     */
    public char[] toChars(char[] existingArray, int[] outLen) {
        byte[] sig = mSignature;
        final int N = sig.length;
        final int N2 = N * 2;
        char[] text = existingArray == null || N2 > existingArray.length
                ? new char[N2] : existingArray;
        for (int j = 0; j < N; j++) {
            byte v = sig[j];
            int d = (v >> 4) & 0xf;
            text[j * 2] = (char) (d >= 10 ? ('a' + d - 10) : ('0' + d));
            d = v & 0xf;
            text[j * 2 + 1] = (char) (d >= 10 ? ('a' + d - 10) : ('0' + d));
        }
        if (outLen != null) {
            outLen[0] = N;
        }
        return text;
    }

    /**
     * Return the result of {@link #toChars()} as a String.
     */
    public String toCharsString() {
        String str = new String(toChars());
        return str;
    }

    /**
     * @return the contents of this signature as a byte array.
     */
    public byte[] toByteArray() {
        byte[] bytes = new byte[mSignature.length];
        System.arraycopy(mSignature, 0, bytes, 0, mSignature.length);
        return bytes;
    }

    /**
     * 获取公钥 Returns the public key for this signature.
     *
     * @throws CertificateException when Signature isn't a valid X.509
     * certificate; shouldn't happen.
     * @hide
     */
    public PublicKey getPublicKey() throws CertificateException {
        final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        final ByteArrayInputStream bais = new ByteArrayInputStream(mSignature);
        final Certificate cert = certFactory.generateCertificate(bais);
        return cert.getPublicKey();
    }

    /**
     * 源码中不存在此逻辑
     *
     * @return 证书
     * @throws CertificateException
     */
    public Certificate getCert() throws CertificateException {
        final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        final ByteArrayInputStream bais = new ByteArrayInputStream(mSignature);
        final Certificate cert = certFactory.generateCertificate(bais);
        return cert;

    }

    public boolean equals(Object obj) {
        try {
            if (obj != null) {
                SignatureUtils other = (SignatureUtils) obj;
                return this == other || Arrays.equals(mSignature, other.mSignature);
            }
        } catch (ClassCastException e) {
        }
        return false;
    }

    public int hashCode() {
        if (mHaveHashCode) {
            return mHashCode;
        }
        mHashCode = Arrays.hashCode(mSignature);
        mHaveHashCode = true;
        return mHashCode;
    }

    public int describeContents() {
        return 0;
    }

    /**
     * Test if given {@link Signature} sets are exactly equal.
     *
     * @hide
     */
    public static boolean areExactMatch(SignatureUtils[] a, SignatureUtils[] b) {
        return ArrayUtils.containsAll(a, b) && ArrayUtils.containsAll(b, a);
    }

    public static X509Certificate readSignatureBlock(InputStream in) throws IOException, GeneralSecurityException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Collection<? extends java.security.cert.Certificate> certs
                = cf.generateCertificates(in);

        return (X509Certificate) certs.iterator().next();
    }

    /**
     * 源码中不存在此逻辑
     *
     * @param certPath 证书路径
     * @throws Exception
     */
    public static void parseCert(String certPath) throws Exception {
        X509Certificate publicKey = readSignatureBlock(new FileInputStream(new File(certPath)));
        byte[] signatrueBytes = publicKey.getEncoded();

        System.out.print("signatures:");
        System.out.println(HexUtil.bytesToHex(signatrueBytes));
        System.out.println("issuer:" + publicKey.getIssuerDN());
        System.out.println("subject:" + publicKey.getSubjectDN());
        System.out.println(publicKey.getPublicKey());
    }

    private static boolean isSignatureBlock(String name) {
        if (!name.startsWith("META-INF/")) {
            return false;
        }
        name = name.toUpperCase(Locale.US);
        return name.endsWith(".RSA")
                || name.endsWith(".DSA")
                || name.endsWith(".EC");
    }

    /**
     * 新添加从apk中解析签名 返回的数据： - derBytes → 等价 new Signature(byte[]) - hexString →
     * 等价 new Signature(String)
     */
    public static List<SignatureUtils> parseV1Signatures(String apkPath) throws Exception {
        List<SignatureUtils> signatures = new ArrayList<>();

        ZipFile zipFile = new ZipFile(apkPath);
        Enumeration<? extends ZipEntry> entries = zipFile.entries();

        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String name = entry.getName();

            if (isSignatureBlock(name)) {
                InputStream is = zipFile.getInputStream(entry);

                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                Collection<? extends Certificate> certs = cf.generateCertificates(is);

                for (Certificate cert : certs) {
                    if (cert instanceof X509Certificate) {
                        byte[] der = cert.getEncoded();
                        signatures.add(new SignatureUtils(der));
                    }
                }

                is.close();
            }
        }

        zipFile.close();
        return signatures;
    }

    public static void main(String[] args) throws Exception {

        SignatureUtils sig1 = new SignatureUtils("30820253308201bca00302010202044b9dd8e7300d06092a864886f70d0101050500306d310b300906035504061302434e3111300f060355040813085368616e676861693111300f060355040713085368616e6768616931133011060355040a130a426169647520496e632e31133011060355040b130a426169647520496e632e310e300c0603550403130542616964753020170d3130303331353036353131395a180f32303634313231363036353131395a306d310b300906035504061302434e3111300f060355040813085368616e676861693111300f060355040713085368616e6768616931133011060355040a130a426169647520496e632e31133011060355040b130a426169647520496e632e310e300c06035504031305426169647530819f300d06092a864886f70d010101050003818d00308189028181009c7a58a39572c4b379ddfca6765e95d3aec69fe362ce622e629647cf441b9e4b7b695e540fd29b7da7b2ab64793089f2b69112d11ac5776973dd68cff88b671826c1286e57c7294c76c7c118ae41bf9336ff9ae0aa90c65ed7db0749ff137b815b6d3b53abaad72d7817b0b8900caef12eea13d12baf0b8cb30543bfb3489c230203010001300d06092a864886f70d01010505000381810063231fb3859d01f75cd7ed810aa5c08eb8fba5b7b7bf11f2c65ae70aa69365b7c985334a38be2c6712c77a1b8aa09d1ae84b51b0062968734700f795b08a7ff5dd73751cd63254f211cb6386fa733690d826b44c169f76c23b82f813b15c1da47a2be69369cd75bf7cdaa337d2ea38726a778583838409b482efc126f7e668b3");
        System.out.println("-------------------------------------------------------------");
        System.out.println("signatures:" + sig1.toCharsString());
        X509Certificate xcert = (X509Certificate) sig1.getCert();
        System.out.println("issuer:" + xcert.getIssuerDN());
        System.out.println("subject:" + xcert.getSubjectDN());
        System.out.println(xcert.getPublicKey());

        System.out.println("-------------------------------------------------------------");

        URL url = SignatureUtils.class.getResource("/TEST.RSA");
        if (url == null) {
            throw new RuntimeException("TEST.RSA not found in classpath");
        }
        String path = url.getPath();

        System.out.println(path);
        System.out.println("-------------------------------------------------------------");
        parseCert(path);

        System.out.println("-------------------------------------------------------------");

        url = SignatureUtils.class.getResource("/app_test.apk");
        if (url == null) {
            throw new RuntimeException("app_test.apk not found in classpath");
        }
        path = url.getPath();

        System.out.println(path);

        System.out.println("-------------------------------------------------------------");
        List<SignatureUtils> signs = parseV1Signatures(path);
        for (Iterator<SignatureUtils> it = signs.iterator(); it.hasNext();) {
            SignatureUtils sign = it.next();
            System.out.println("signatures:" + sign.toCharsString());
            X509Certificate cert = (X509Certificate) sign.getCert();
            System.out.println("issuer:" + cert.getIssuerDN());
            System.out.println("subject:" + cert.getSubjectDN());
            System.out.println(cert.getPublicKey());
        }
    }

}
