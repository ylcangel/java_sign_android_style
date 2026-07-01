/**
 * 完全依照Android源码实现的签名工具类 同时添加了从apk中解析签名获取签名byte数组或者byte数组对应的字符串
 *
 * @Author: AngelToms
 */

package brut.androlib.repacker;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class SignatureUtils {

    // 1 MANIFEST.MF中的各SHA-1值 == SHA-1(除META-INF目录外的文件)；
    // 2 CERT.SF中各值 == (SHA-1 + Base64)(MANIFEST.MF文件及各子项)；
    // 3 CERT.RSA/DSA/EC == 公钥＋加密算法信息等；
    private final byte[] mSignature;
    private int mHashCode;
    private boolean mHaveHashCode;
    private Certificate[] mCertificateChain;

    /**
     * APK Signature Scheme v3 includes support for adding a proof-of-rotation
     * record that
     * contains two pieces of information:
     * 1) the past signing certificates
     * 2) the flags that APK wants to assign to each of the past signing
     * certificates.
     *
     * These flags represent the second piece of information and are viewed as
     * capabilities.
     * They are an APK's way of telling the platform: "this is how I want to trust
     * my old certs,
     * please enforce that." This is useful for situation where this app itself is
     * using its
     * signing certificate as an authorization mechanism, like whether or not to
     * allow another
     * app to have its SIGNATURE permission. An app could specify whether to allow
     * other apps
     * signed by its old cert 'X' to still get a signature permission it defines,
     * for example.
     */
    private int mFlags;

    /**
     * Create Signature from an existing raw byte array.
     */
    public SignatureUtils(byte[] signature) {
        mSignature = (byte[]) signature.clone();
        mCertificateChain = null;
    }

    /**
     * Create signature from a certificate chain. Used for backward
     * compatibility.
     *
     * @throws CertificateEncodingException
     * @hide
     */
    public SignatureUtils(Certificate[] certificateChain) throws CertificateEncodingException {
        mSignature = certificateChain[0].getEncoded();
        if (certificateChain.length > 1) {
            mCertificateChain = Arrays.copyOfRange(certificateChain, 1, certificateChain.length);
        }
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
     * Copy constructor that creates a new instance from the provided {@code other}
     * Signature.
     *
     * @hide
     */
    public SignatureUtils(SignatureUtils other) {
        mSignature = other.mSignature.clone();
        Certificate[] otherCertificateChain = other.mCertificateChain;
        if (otherCertificateChain != null && otherCertificateChain.length > 1) {
            mCertificateChain = Arrays.copyOfRange(otherCertificateChain, 1,
                    otherCertificateChain.length);
        }
        mFlags = other.mFlags;
    }

    /**
     * Sets the flags representing the capabilities of the past signing certificate.
     * 
     * @hide
     */
    public void setFlags(int flags) {
        this.mFlags = flags;
    }

    /**
     * Returns the flags representing the capabilities of the past signing
     * certificate.
     * 
     * @hide
     */
    public int getFlags() {
        return mFlags;
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
     * @param outLen        Output parameter for the number of characters written in
     *                      to
     *                      the array.
     * @return Returns either <var>existingArray</var> if it was large enough to
     *         hold the ASCII representation, or a newly created char[] array if
     *         needed.
     */
    public char[] toChars(char[] existingArray, int[] outLen) {
        byte[] sig = mSignature;
        final int N = sig.length;
        final int N2 = N * 2;
        char[] text = existingArray == null || N2 > existingArray.length
                ? new char[N2]
                : existingArray;
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
     *                              certificate; shouldn't happen.
     * @hide
     */
    public PublicKey getPublicKey() throws CertificateException {
        final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        final ByteArrayInputStream bais = new ByteArrayInputStream(mSignature);
        final Certificate cert = certFactory.generateCertificate(bais);
        return cert.getPublicKey();
    }

    /**
     * Used for compatibility code that needs to check the certificate chain
     * during upgrades.
     *
     * @throws CertificateEncodingException
     * @hide
     */
    public SignatureUtils[] getChainSignatures() throws CertificateEncodingException {
        if (mCertificateChain == null) {
            return new SignatureUtils[] { this };
        }

        SignatureUtils[] chain = new SignatureUtils[1 + mCertificateChain.length];
        chain[0] = this;

        int i = 1;
        for (Certificate c : mCertificateChain) {
            chain[i++] = new SignatureUtils(c.getEncoded());
        }

        return chain;
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
        Collection<? extends java.security.cert.Certificate> certs = cf.generateCertificates(in);

        return (X509Certificate) certs.iterator().next();
    }

    /**
     * Test if given {@link Signature} sets are effectively equal. In rare
     * cases, certificates can have slightly malformed encoding which causes
     * exact-byte checks to fail.
     * <p>
     * To identify effective equality, we bounce the certificates through an
     * decode/encode pass before doing the exact-byte check. To reduce attack
     * surface area, we only allow a byte size delta of a few bytes.
     *
     * @throws CertificateException if the before/after length differs
     *                              substantially, usually a signal of something
     *                              fishy going on.
     * @hide
     */
    public static boolean areEffectiveMatch(SignatureUtils[] a, SignatureUtils[] b)
            throws CertificateException {
        final CertificateFactory cf = CertificateFactory.getInstance("X.509");

        final SignatureUtils[] aPrime = new SignatureUtils[a.length];
        for (int i = 0; i < a.length; i++) {
            aPrime[i] = bounce(cf, a[i]);
        }
        final SignatureUtils[] bPrime = new SignatureUtils[b.length];
        for (int i = 0; i < b.length; i++) {
            bPrime[i] = bounce(cf, b[i]);
        }

        return areExactMatch(aPrime, bPrime);
    }

    /**
     * Bounce the given {@link Signature} through a decode/encode cycle.
     *
     * @throws CertificateException if the before/after length differs
     *                              substantially, usually a signal of something
     *                              fishy going on.
     * @hide
     */
    public static SignatureUtils bounce(CertificateFactory cf, SignatureUtils s) throws CertificateException {
        final InputStream is = new ByteArrayInputStream(s.mSignature);
        final X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
        final SignatureUtils sPrime = new SignatureUtils(cert.getEncoded());

        if (Math.abs(sPrime.mSignature.length - s.mSignature.length) > 2) {
            throw new CertificateException("Bounced cert length looks fishy; before "
                    + s.mSignature.length + ", after " + sPrime.mSignature.length);
        }

        return sPrime;
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

    // ==================== V2 签名解析核心逻辑 ====================

    private static final int V2_SCHEME_BLOCK_ID = 0x7109871a;

    private static final int ZIP_EOCD_REC_MIN_SIZE = 22;
    private static final int ZIP_EOCD_REC_SIG = 0x06054b50;
    private static final int ZIP_EOCD_CENTRAL_DIR_SIZE_FIELD_OFFSET = 12;
    private static final int ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET = 16;
    // ZIP64 相关的常量
    private static final int ZIP64_EOCD_LOCATOR_SIZE = 20;
    private static final int ZIP64_EOCD_LOCATOR_SIG_REVERSE_BYTE_ORDER = 0x504b0607; // 大端序下的 0x07064b50

    private static final int UINT16_MAX_VALUE = 0xffff;

    private static final long APK_SIG_BLOCK_MAGIC_HI = 0x3234206b636f6c42L;
    private static final long APK_SIG_BLOCK_MAGIC_LO = 0x20676953204b5041L;
    private static final int APK_SIG_BLOCK_MIN_SIZE = 32;

    public static List<SignatureUtils> parseV2Signatures(String apkPath) throws Exception {
        List<SignatureUtils> signaturesUtils = new ArrayList<>();

        try (RandomAccessFile apk = new RandomAccessFile(apkPath, "r")) {
            // 1. 寻找 EOCD (End of Central Directory) 并获取中央目录的偏移量
            long fileSize = apk.length();
            if (fileSize < ZIP_EOCD_REC_MIN_SIZE) {
                throw new Exception(
                        "Not an APK file: ZIP file length is too short to be an APK");
            }

            long eocdOffset = -1;
            // 简单起见，假设注释长度为0，直接从末尾倒数 22 字节寻找
            apk.seek(fileSize - ZIP_EOCD_REC_MIN_SIZE);
            byte[] eocd = new byte[ZIP_EOCD_REC_MIN_SIZE];
            apk.readFully(eocd);
            ByteBuffer eocdBuffer = ByteBuffer.wrap(eocd).order(ByteOrder.LITTLE_ENDIAN);
            eocdOffset = fileSize - ZIP_EOCD_REC_MIN_SIZE;

            if (eocdBuffer.getInt(0) != ZIP_EOCD_REC_SIG) {
                // 如果找不到，说明可能有 ZIP 注释，需要从后往前扫描 EOCD 签名
                long maxCommentSize = Math.min(fileSize - ZIP_EOCD_REC_MIN_SIZE, UINT16_MAX_VALUE);
                boolean found = false;
                for (int i = 0; i <= maxCommentSize; i++) {
                    apk.seek(fileSize - ZIP_EOCD_REC_MIN_SIZE - i);
                    if (apk.readInt() == ZIP_EOCD_REC_SIG) { // Big Endian 对应 0x06054b50
                        apk.seek(fileSize - ZIP_EOCD_REC_MIN_SIZE - i);
                        eocdOffset = fileSize - ZIP_EOCD_REC_MIN_SIZE - i;
                        apk.readFully(eocd);
                        eocdBuffer = ByteBuffer.wrap(eocd).order(ByteOrder.LITTLE_ENDIAN);
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    throw new Exception(
                            "Not an APK file: ZIP End of Central Directory record not found");
                }
            }

            if (isZip64EndOfCentralDirectoryLocatorPresent(apk, eocdOffset)) {
                throw new Exception("ZIP64 APKs are not supported");
            }

            // 获取中央目录的起始位置
            long centralDirOffset = eocdBuffer.getInt(ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET) & 0xffffffffL;
            if (centralDirOffset > eocdOffset) {
                throw new Exception(
                        "ZIP Central Directory offset out of range: " + centralDirOffset
                                + ". ZIP End of Central Directory offset: " + eocdOffset);
            }

            long centralDirSize = eocdBuffer.getInt(ZIP_EOCD_CENTRAL_DIR_SIZE_FIELD_OFFSET) & 0xffffffffL;
            if (centralDirOffset + centralDirSize != eocdOffset) {
                throw new Exception(
                        "ZIP Central Directory is not immediately followed by End of Central"
                                + " Directory");
            }

            // 2. 验证中央目录前方是否存在 APK Signing Block
            // FORMAT:
            // OFFSET DATA TYPE DESCRIPTION
            // * @+0 bytes uint64: size in bytes (excluding this field)
            // * @+8 bytes payload
            // * @-24 bytes uint64: size in bytes (same as the one above)
            // * @-16 bytes uint128: magic
            if (centralDirOffset < APK_SIG_BLOCK_MIN_SIZE) {
                throw new Exception(
                        "APK too small for APK Signing Block. ZIP Central Directory offset: "
                                + centralDirOffset);
            }

            apk.seek(centralDirOffset - 24); // 减去 foot size + magic size
            byte[] footer = new byte[24];
            apk.readFully(footer);
            ByteBuffer footerBuf = ByteBuffer.wrap(footer).order(ByteOrder.LITTLE_ENDIAN);

            // 验证魔数 "APK Sig Block 42"
            long blockSize = footerBuf.getLong(0);
            if (footerBuf.getLong(8) != APK_SIG_BLOCK_MAGIC_LO || footerBuf.getLong(16) != APK_SIG_BLOCK_MAGIC_HI) {
                throw new Exception(
                        "No APK Signing Block before ZIP Central Directory");
            }

            if ((blockSize < footerBuf.capacity())
                    || (blockSize > Integer.MAX_VALUE - 8)) {
                throw new Exception(
                        "APK Signing Block size out of range: " + blockSize);
            }

            // 3. 读取整个签名块
            long blockStartOffset = centralDirOffset - 8 - blockSize;
            if (blockStartOffset < 0) {
                throw new Exception(
                        "APK Signing Block offset out of range: " + blockStartOffset);
            }

            apk.seek(blockStartOffset);
            byte[] blockBytes = new byte[(int) blockSize + 8]; // 包含header size大小
            apk.readFully(blockBytes);
            ByteBuffer totalBuf = ByteBuffer.wrap(blockBytes).order(ByteOrder.LITTLE_ENDIAN);
            totalBuf.position(8);
            totalBuf.limit(totalBuf.capacity() - 24);
            ByteBuffer blockBuf = totalBuf.slice().order(ByteOrder.LITTLE_ENDIAN);

            // 4. 在签名块中循环查找 V2 ID (0x7109871a)
            ByteBuffer v2Block = null;

            while (blockBuf.hasRemaining()) {

                long len = blockBuf.getLong();
                int id = blockBuf.getInt();
                if (id == V2_SCHEME_BLOCK_ID) {
                    byte[] v2Data = new byte[(int) len - 4];
                    blockBuf.get(v2Data);
                    v2Block = ByteBuffer.wrap(v2Data).order(ByteOrder.LITTLE_ENDIAN);
                    break;
                } else {
                    blockBuf.position(blockBuf.position() + (int) len - 4);
                }
            }

            if (v2Block == null) {
                throw new Exception(
                        "No block with ID " + V2_SCHEME_BLOCK_ID + " in APK Signing Block.");
            }

            // 5. 解析 V2 签名结构，逐层剥离取出证书
            // 对应源码signers = getLengthPrefixedSlice(signatureInfo.signatureBlock);
            int signersLength = v2Block.getInt();
            ByteBuffer signers = v2Block.slice().order(ByteOrder.LITTLE_ENDIAN);
            signers.limit(signersLength); //
            v2Block.position(v2Block.position() + signersLength);

            while (signers.hasRemaining()) { // 对应源码signers.hasRemaining()
                // 对应源码ByteBuffer signer = getLengthPrefixedSlice(signers);
                int signerLength = signers.getInt();
                ByteBuffer signer = signers.slice().order(ByteOrder.LITTLE_ENDIAN);
                signer.limit(signerLength);
                signers.position(signers.position() + signerLength);

                //////////////////////////////////////////////////////////////////////////
                // signer的内部结构
                // 对应源码ByteBuffer signedData = getLengthPrefixedSlice(signerBlock);
                int signedDataLength = signer.getInt();
                ByteBuffer signedData = signer.slice().order(ByteOrder.LITTLE_ENDIAN);
                signedData.limit(signedDataLength);
                signer.position(signer.position() + signedDataLength);

                // 对应源码ByteBuffer signatures = getLengthPrefixedSlice(signer);
                int signaturesLength = signer.getInt();
                ByteBuffer signatures = signer.slice().order(ByteOrder.LITTLE_ENDIAN);
                signatures.limit(signaturesLength);
                signer.position(signer.position() + signaturesLength);

                // 对应源码byte[] publicKeyBytes = readLengthPrefixedByteArray(signerBlock);
                int publicKeyLength = signer.getInt();
                byte[] publicKeyBytes = new byte[publicKeyLength];
                signer.get(publicKeyBytes);

                // 我们只关心证书序列，不需要解析签名和公钥，直接跳过
                signedData.clear();

                // signedData往内：算法序列、证书序列、额外属性。我们要找【证书序列】
                // 对应源码ByteBuffer digests = getLengthPrefixedSlice(signedData);
                // 先跳过前面的算法序列 (digests)
                int digestsLength = signedData.getInt(); // 读取 digests 序列的长度
                signedData.position(signedData.position() + digestsLength);

                // 拿到了证书序列 (certificates)
                // 对应源码ByteBuffer certificates = getLengthPrefixedSlice(signedData);
                int certificatesLength = signedData.getInt();
                ByteBuffer certificates = signedData.slice().order(ByteOrder.LITTLE_ENDIAN);
                certificates.limit(certificatesLength);
                signedData.position(signedData.position() + certificatesLength);

                while (certificates.hasRemaining()) { // 对应源码certificates.hasRemaining(
                    int certLength = certificates.getInt();
                    byte[] encodedCert = new byte[certLength];
                    certificates.get(encodedCert);
                    // 【可选验证】：如果你想确认读出来的数据对不对，可以直接用 Java 官方类库还原
                    // try {
                    // CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                    // X509Certificate certificate = (X509Certificate)
                    // certFactory.generateCertificate(new ByteArrayInputStream(encodedCert));
                    // System.out.println("issuer:" + certificate.getIssuerDN());
                    // System.out.println("subject:" + certificate.getSubjectDN());
                    // } catch (CertificateException e) {
                    // throw new SecurityException("Failed to decode certificate", e);
                    // }

                    signaturesUtils.add(new SignatureUtils(encodedCert));
                }

                // 对应源码ByteBuffer additionalAttrs = getLengthPrefixedSlice(signedData);
                // 略，不需要
                //////////////////////////////////////////////////////////////////////////
            }
        }
        return signaturesUtils;
    }

    private static boolean isZip64EndOfCentralDirectoryLocatorPresent(
            RandomAccessFile zip, long zipEndOfCentralDirectoryPosition) throws IOException {
        long locatorPosition = zipEndOfCentralDirectoryPosition - ZIP64_EOCD_LOCATOR_SIZE;
        if (locatorPosition < 0) {
            return false;
        }
        zip.seek(locatorPosition);
        return zip.readInt() == ZIP64_EOCD_LOCATOR_SIG_REVERSE_BYTE_ORDER;
    }

    public static void main(String[] args) throws Exception {

        SignatureUtils sig1 = new SignatureUtils(
                "30820253308201bca00302010202044b9dd8e7300d06092a864886f70d0101050500306d310b300906035504061302434e3111300f060355040813085368616e676861693111300f060355040713085368616e6768616931133011060355040a130a426169647520496e632e31133011060355040b130a426169647520496e632e310e300c0603550403130542616964753020170d3130303331353036353131395a180f32303634313231363036353131395a306d310b300906035504061302434e3111300f060355040813085368616e676861693111300f060355040713085368616e6768616931133011060355040a130a426169647520496e632e31133011060355040b130a426169647520496e632e310e300c06035504031305426169647530819f300d06092a864886f70d010101050003818d00308189028181009c7a58a39572c4b379ddfca6765e95d3aec69fe362ce622e629647cf441b9e4b7b695e540fd29b7da7b2ab64793089f2b69112d11ac5776973dd68cff88b671826c1286e57c7294c76c7c118ae41bf9336ff9ae0aa90c65ed7db0749ff137b815b6d3b53abaad72d7817b0b8900caef12eea13d12baf0b8cb30543bfb3489c230203010001300d06092a864886f70d01010505000381810063231fb3859d01f75cd7ed810aa5c08eb8fba5b7b7bf11f2c65ae70aa69365b7c985334a38be2c6712c77a1b8aa09d1ae84b51b0062968734700f795b08a7ff5dd73751cd63254f211cb6386fa733690d826b44c169f76c23b82f813b15c1da47a2be69369cd75bf7cdaa337d2ea38726a778583838409b482efc126f7e668b3");
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
		
		System.out.println("-------------------------------------------------------------");
        List<SignatureUtils> signv2s = null;
        try {
            signv2s = parseV2Signatures(path);
            if (!signv2s.isEmpty()) {
                for (Iterator<SignatureUtils> it = signv2s.iterator(); it.hasNext();) {
                    SignatureUtils sign = it.next();
                    System.out.println("signatures:" + sign.toCharsString());
                    X509Certificate cert = (X509Certificate) sign.getCert();
                    System.out.println("issuer:" + cert.getIssuerDN());
                    System.out.println("subject:" + cert.getSubjectDN());
                    System.out.println(cert.getPublicKey());
                }
            } else {
                System.out.println("No V2 signatures found.");
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse V2 signatures", e);
        }
    }

}
