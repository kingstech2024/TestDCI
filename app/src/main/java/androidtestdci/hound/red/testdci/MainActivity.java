package androidtestdci.hound.red.testdci;

//region Imports
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import android.Manifest;
import android.app.DownloadManager;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Environment;
import android.security.AttestedKeyPair;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x509.Extension;
import org.spongycastle.asn1.x509.SubjectKeyIdentifier;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.jcajce.JcaCertStore;
import org.spongycastle.cert.jcajce.JcaX509CertificateHolder;
import org.spongycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.spongycastle.cms.CMSProcessableByteArray;
import org.spongycastle.cms.CMSSignedData;
import org.spongycastle.cms.CMSSignedDataGenerator;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.ref.WeakReference;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import static android.app.admin.DevicePolicyManager.ID_TYPE_BASE_INFO;
import static android.app.admin.DevicePolicyManager.ID_TYPE_SERIAL;
//endregion

public class MainActivity extends AppCompatActivity {

    //region Callbacks
    // Callback to use when trying to suss out what the key generation and attestation quality situations are
    class SituationDeterminationComplete implements SituationDeterminationTask.OnSituationDeterminationComplete {
        public void onSituationDeterminationComplete(MainActivity.KeyGenerationSituation kgs, AttestationQualitySituation as) {
            m_kgs = kgs;
            m_as = as;
            setComponentNameAndFlagsPerSituation();
            enableButtons();
            Toast.makeText(getApplicationContext(), "Key generation situation: " + m_kgs.name(), Toast.LENGTH_LONG).show();
        }
    }

    class GetCertChainComplete implements GetCertChainTask.OnGetCertChainComplete {
        public void onGetCertChainComplete(X509Certificate[] chain) {
            if (null == chain) {
                Log.e(MainActivity.TAG, "Get certificate chain completed but no chain was made available");
                return;
            }
            try {
                CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

                CMSProcessableByteArray msg = new CMSProcessableByteArray("".getBytes());

                JcaCertStore store = new JcaCertStore(Arrays.asList(chain));
                gen.addCertificates(store);
                CMSSignedData signedData = gen.generate(msg);

                byte[] certificateChainAsP7 = signedData.getEncoded();

                //noinspection SpellCheckingInspection
                SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd_HHmmss");
                String currentDateandTime = sdf.format(new Date());

                File fileLocation = new File(Environment.getExternalStorageDirectory(), "certificateChain_" + currentDateandTime+ ".p7c");
                FileOutputStream outputStream = new FileOutputStream(fileLocation, false);
                outputStream.write(certificateChainAsP7);
                outputStream.close();

                DownloadManager downloadManager = (DownloadManager) getApplicationContext().getSystemService(DOWNLOAD_SERVICE);
                if(null != downloadManager) {
                    downloadManager.addCompletedDownload(fileLocation.getName(), fileLocation.getName(), true, "text/plain", fileLocation.getAbsolutePath(), fileLocation.length(), true);
                    Toast.makeText(getApplicationContext(), "Certificate chain file saved to Downloads folder", Toast.LENGTH_LONG).show();
                }
            } catch (Exception ex) {
                Log.e(MainActivity.TAG, "Failed to construct P7C with certificate chain",ex);
                throw new RuntimeException(ex);
            }
        }
    }

    // Callback to use when generating a key pair
    class KeyGenerationComplete implements KeyGenTask.OnKeyGenComplete {
        public void onKeyGenComplete(AttestedKeyPair akp)
        {
            if(null == akp)
            {
                Log.e(MainActivity.TAG, "Key generation completed by no attested key pair was made available");
                return;
            }

            try {
                List<Certificate> ar = akp.getAttestationRecord();
                CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
                try {
                    CMSProcessableByteArray msg = new CMSProcessableByteArray("".getBytes());

                    JcaCertStore store = new JcaCertStore(ar);
                    gen.addCertificates(store);
                    CMSSignedData signedData = gen.generate(msg);

                    byte[] attestationChainAsP7 = signedData.getEncoded();

                    SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd_HHmmss");
                    String currentDateandTime = sdf.format(new Date());

                    File fileLocation = new File(Environment.getExternalStorageDirectory(), "attestedKeyPair_" + currentDateandTime + ".p7c");
                    FileOutputStream outputStream = new FileOutputStream(fileLocation, false);
                    outputStream.write(attestationChainAsP7);
                    outputStream.close();

                    DownloadManager downloadManager = (DownloadManager) getApplicationContext().getSystemService(DOWNLOAD_SERVICE);
                    if(null != downloadManager) {
                        downloadManager.addCompletedDownload(fileLocation.getName(), fileLocation.getName(), true, "text/plain", fileLocation.getAbsolutePath(), fileLocation.length(), true);
                        Toast.makeText(getApplicationContext(), "Attestation chain file saved to Downloads folder", Toast.LENGTH_LONG).show();
                    }
                } catch (Exception ex) {
                    Log.e(MainActivity.TAG, "Failed to construct P7C with attestation chain",ex);
                    return;
                }

                KeyPair kp = akp.getKeyPair();
                byte[] pubKeyBytes = kp.getPublic().getEncoded();
                KeyFactory kf = KeyFactory.getInstance("RSA");
                m_publicKey = kf.generatePublic(new X509EncodedKeySpec(pubKeyBytes));

                Button btn = findViewById(R.id.installCaSignedCertificate);
                btn.setEnabled(true);
            }
            catch(Exception e) {
                Log.e(MainActivity.TAG, "Key generation failed: " + e.getMessage());
            }
        }
    }
    //endregion

    //region Key generation and attestation quality enum definitions
    public enum KeyGenerationSituation {
        // The app is configured as the device owner and is operating on a device that supports
        // including device IDs in attestations.
        DEVICE_OWNER,
        // The app is configured as the profile owner and is operating on a device that supports
        // including device IDs in attestations.
        PROFILE_OWNER,
        // The app is configured as a delegated certificate installer by the device owner and is
        // operating on a device that supports including device IDs in attestations.
        DEVICE_OWNER_DELEGATE,
        // The app is configured as a delegated certificate installer by the profile owner and is
        // operating on a device that supports including device IDs in attestations.
        PROFILE_OWNER_DELEGATE,
        // The app is configured as the device owner and is operating on a device that does not
        // support including device IDs in attestations.
        DEVICE_OWNER_NO_DEVICE_ID_SUPPORT,
        // The app is configured as the profile owner and is operating on a device that does not
        // support including device IDs in attestations.
        PROFILE_OWNER_NO_DEVICE_ID_SUPPORT,
        // The app is configured as a delegated certificate installer by the device owner and is
        // operating on a device that does not support including device IDs in attestations.
        DEVICE_OWNER_DELEGATE_NO_DEVICE_ID_SUPPORT,
        // The app is configured as a delegated certificate installer by the device owner and is
        // operating on a device that does not support including device IDs in attestations.
        PROFILE_OWNER_DELEGATE_NO_DEVICE_ID_SUPPORT,
        // The device does not support generation of hardware keys (at least in current context).
        HARDWARE_KEY_GENERATION_NOT_SUPPORTED,
        // The key generation situation is not yet known.
        KEY_GENERATION_SITUATION_UNKNOWN
    }

    public enum AttestationQualitySituation {
        // The hardware (in current context) supports generating hardware attestations including a
        // device ID
        HARDWARE_ATTESTATION_WITH_DEVICE_ID,
        // The hardware (in current context) supports generating hardware attestations but not
        // including a device ID
        HARDWARE_ATTESTATION_WITHOUT_DEVICE_ID,
        // The hardware (in current context) does not support hardware attestations
        SOFTWARE_ATTESTATION,
        // The attestation quality situation is not yet known.
        ATTESTATION_QUALITY_SITUATION_UNKNOWN
    }
    //endregion

    //region Member variables
    // Logging tag
    public static final String TAG = "TestDci";

    // Alias for keys generated for analysis
    private static final String m_alias = "TestDciExampleKey";

    // Last observed key generation situation
    private static KeyGenerationSituation m_kgs = KeyGenerationSituation.KEY_GENERATION_SITUATION_UNKNOWN;

    // Last observed attestation quality situation
    private static AttestationQualitySituation m_as = AttestationQualitySituation.ATTESTATION_QUALITY_SITUATION_UNKNOWN;

    // Component name to use as of last key generation situation determination
    private ComponentName m_componentName = null;

    // Attestation flags to use as of last key generation situation determination
    private int m_idAttestationFlags = 0;

    // Last generated public key
    private PublicKey m_publicKey = null;

    private static final int REQUEST_WRITE_EXTERNAL_STORAGE = 1;
    //endregion

    //region Utility functions

    /**
     * setComponentNameAndFlagsPerSituation sets the member variables used for the component name
     * and flags parameters to the generateKeyPair and removeKeyPair API calls based on the status
     * of the app relative to device owner/policy owner/delegate status.
     */
    private void setComponentNameAndFlagsPerSituation() {
        Context context = getApplicationContext();
        if(KeyGenerationSituation.DEVICE_OWNER == m_kgs)
        {
            m_componentName = TestDciReceiver.getComponentName(context);
            m_idAttestationFlags = ID_TYPE_BASE_INFO | ID_TYPE_SERIAL;
        }
        else if(KeyGenerationSituation.PROFILE_OWNER == m_kgs)
        {
            m_componentName = TestDciReceiver.getComponentName(context);
            m_idAttestationFlags = ID_TYPE_BASE_INFO;
        }
        else if(KeyGenerationSituation.DEVICE_OWNER_DELEGATE == m_kgs)
        {
            m_componentName = null;
            m_idAttestationFlags = ID_TYPE_BASE_INFO | ID_TYPE_SERIAL;
        }
        else if(KeyGenerationSituation.PROFILE_OWNER_DELEGATE == m_kgs)
        {
            m_componentName = null;
            m_idAttestationFlags = ID_TYPE_BASE_INFO;
        }
        else if(KeyGenerationSituation.DEVICE_OWNER_NO_DEVICE_ID_SUPPORT == m_kgs)
        {
            m_componentName = TestDciReceiver.getComponentName(context);
            m_idAttestationFlags = 0;
        }
        else if(KeyGenerationSituation.PROFILE_OWNER_NO_DEVICE_ID_SUPPORT == m_kgs)
        {
            m_componentName = TestDciReceiver.getComponentName(context);
            m_idAttestationFlags = 0;
        }
        else if(KeyGenerationSituation.DEVICE_OWNER_DELEGATE_NO_DEVICE_ID_SUPPORT == m_kgs)
        {
            m_componentName = null;
            m_idAttestationFlags = 0;
        }
        else if(KeyGenerationSituation.PROFILE_OWNER_DELEGATE_NO_DEVICE_ID_SUPPORT == m_kgs)
        {
            m_componentName = null;
            m_idAttestationFlags = 0;
        }
        else
        {
            Log.e(MainActivity.TAG, "Unrecognized key generation situation: " + m_kgs.name());
        }
    }

    private byte[] getDigest(SubjectPublicKeyInfo subjectPublicKey)
    {
        SHA1Digest digest = new SHA1Digest();
        byte[]  resBuf = new byte[digest.getDigestSize()];

        // this should be guaranteed to be non-null at this point
        byte[] bytes = subjectPublicKey.getPublicKeyData().getBytes();
        digest.update(bytes, 0, bytes.length);
        digest.doFinal(resBuf, 0);
        return resBuf;
    }

    /**
     * disableButton disables all buttons except the situation determination button.
     */
    private void disableButtons()
    {
        Button btn = findViewById(R.id.generateKey);
        btn.setEnabled(false);

        btn = findViewById(R.id.saveCertificationPath);
        btn.setEnabled(false);

        btn = findViewById(R.id.installCaSignedCertificate);
        btn.setEnabled(false);

        btn = findViewById(R.id.deleteKey);
        btn.setEnabled(false);
    }

    /**
     * enableButtons enables buttons that may function after situation is determined. The
     * installCaSignedCertificate button is disabled until generate key is clicked, since that
     * sets up a public key value used in the CA-signed cert.
     */
    private void enableButtons()
    {
        Button btn = findViewById(R.id.generateKey);
        btn.setEnabled(true);

        btn = findViewById(R.id.saveCertificationPath);
        btn.setEnabled(true);

        // enabled when key generation succeeds
        // btn = findViewById(R.id.installCaSignedCertificate);
        // btn.setEnabled(true);

        btn = findViewById(R.id.deleteKey);
        btn.setEnabled(true);
    }
    //endregion

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        disableButtons();

        // files are saved internally then moved to downloads folder to facilitate exporting for analysis off the device.
        if (ContextCompat.checkSelfPermission(MainActivity.this, Manifest.permission.INTERNET) != PackageManager.PERMISSION_GRANTED ||
                ContextCompat.checkSelfPermission(MainActivity.this, Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(MainActivity.this, new String[]{Manifest.permission.INTERNET, Manifest.permission.WRITE_EXTERNAL_STORAGE},REQUEST_WRITE_EXTERNAL_STORAGE);
        }
    }

    //region Button click handlers

    /**
     * determineSituation interrogates the DevicePolicyManager and performs some trial/error key
     * generation to determine if the app is functioning as a device owner, a profile owner or a
     * delegate of another app functioning as a device owner or profile owner. It sets up the
     * m_componentName and m_idAttestationFlags members that are used inside generateKey and
     * deleteKey.
     * @param view Button that was clicked
     */
    public void determineSituation(View view) {
        MainActivity.SituationDeterminationComplete sdc = new MainActivity.SituationDeterminationComplete();
        SituationDeterminationTask sdt = new SituationDeterminationTask(new WeakReference<>(getApplicationContext()), sdc);
        try {
            sdt.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
        }
        catch(Exception e) {
            Log.e(MainActivity.TAG, "Key generation situation determination task failed: " + e.getMessage());
        }
    }

    /**
     * generateKey generates a fresh key pair using the m_alias name and the component name and flags
     * values sussed out by the situation determination method.
     * @param view Button that was clicked
     */
    public void generateKey(View view) {
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                m_alias,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY | KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(2048)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC, KeyProperties.BLOCK_MODE_CTR, KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1, KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS, KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setUnlockedDeviceRequired(true)
                .setAttestationChallenge("challenge".getBytes());

        KeyGenParameterSpec keySpec = builder.build();

        MainActivity.KeyGenerationComplete kgc = new MainActivity.KeyGenerationComplete();
        KeyGenTask kgt = new KeyGenTask(new WeakReference<>(getApplicationContext()), keySpec, m_componentName, m_idAttestationFlags, kgc);
        try {
            kgt.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
        }
        catch(Exception e) {
            Log.e(MainActivity.TAG, "Key generation task failed: " + e.getMessage());
        }
    }

    /**
     * saveCertificationPath is provided as a button to enable demonstration of difference between
     * values returned before and after installing a CA-signed certificate.
     * @param view Button that was clicked
     */
    public void saveCertificationPath(View view) {
        MainActivity.GetCertChainComplete gccc = new MainActivity.GetCertChainComplete();
        GetCertChainTask sdt = new GetCertChainTask(new WeakReference<>(getApplicationContext()), m_alias, gccc);
        try {
            sdt.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
        }
        catch(Exception e) {
            Log.e(MainActivity.TAG, "Get certification path task failed: " + e.getMessage());
        }
    }

    public void installCaSignedCertificate(View view) {
        try {
            // Set up a signer
            JcaContentSignerBuilder signerBuilder;
            signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");

            //Read the type of device for inclusion in the DN
            String device_type = "Name";

            //Prepare a DN for the self-signed certificate with the device type as the least specific
            //RDN followed by the serial number then the random UUID.
            //noinspection StringBufferReplaceableByString
            StringBuilder sb = new StringBuilder();
            sb.append("O=");
            sb.append(device_type);
            sb.append(",OU=");
            sb.append("Serial");
            sb.append(",CN=");
            sb.append("UUID");

            //The self-signed certificate will contain DN as described above, a 5 year validity period
            //a subject key identifier extension and the 2048-bit RSA key generated above.
            BigInteger serial = new BigInteger(16, new SecureRandom());
            //signature is set by JcaContentSignerBuilder
            //X500Name issuer = new X500Name(sb.toString());
            Calendar cal = Calendar.getInstance();
            cal.add(Calendar.DATE, -1);
            Date notBefore = cal.getTime();
            cal.add(Calendar.DATE, 365 * 5);
            Date notAfter = cal.getTime();
            //noinspection UnnecessaryLocalVariable
            X500Name subject = new X500Name(sb.toString());

            KeyStore keystore = KeyStore.getInstance("PKCS12");
            InputStream is = getApplicationContext().getResources().openRawResource(R.raw.good_ca_cert);
            keystore.load(is, "password".toCharArray());
            Enumeration<String> aliases = keystore.aliases();
            String alias = aliases.nextElement();
            X509Certificate issuerCert = (X509Certificate)keystore.getCertificate(alias);
            PrivateKey privateKey = (PrivateKey)keystore.getKey(alias, "password".toCharArray());
            X500Name issuer = new JcaX509CertificateHolder(issuerCert).getSubject();

            //Put the pieces together
            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    issuer, serial, notBefore, notAfter, subject, m_publicKey);
            certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                    new SubjectKeyIdentifier(getDigest(SubjectPublicKeyInfo.getInstance(m_publicKey.getEncoded()))));

            //Sign the certificate
            X509CertificateHolder idHolder = certBuilder.build(signerBuilder.build(privateKey));
            if (null == idHolder) {
                String errorString = "Failed to sign self-signed device certificate";
                Log.e(MainActivity.TAG, errorString);
                return;
            }

            //Encode the certificate
            X509Certificate device_cert = (X509Certificate) CertificateFactory.getInstance(
                    "X509").generateCertificate(new ByteArrayInputStream(idHolder.getEncoded()));
            if (null != device_cert) {
                byte[] encCert = device_cert.getEncoded();

                final DevicePolicyManager manager =
                        (DevicePolicyManager) getApplicationContext().getSystemService(Context.DEVICE_POLICY_SERVICE);
                if(null != manager) {
                    ArrayList<Certificate> l = new ArrayList<>();
                    l.add(device_cert);
                    manager.setKeyPairCertificate(m_componentName, m_alias, l, true);
                    Toast.makeText(getApplicationContext(), "Successfully associated CA-signed certificate with key", Toast.LENGTH_LONG).show();
                }
            }
        }
        catch(Exception e) {
            Log.e(MainActivity.TAG, e.getMessage());
        }
    }

    public void deleteKey(View view) {
        try {
            final DevicePolicyManager dpm = (DevicePolicyManager) getApplicationContext().getSystemService(Context.DEVICE_POLICY_SERVICE);
            if(null != dpm) {
                dpm.removeKeyPair(m_componentName, m_alias);
                Toast.makeText(getApplicationContext(), "Successfully deleted key", Toast.LENGTH_LONG).show();
            }
        }
        catch(Exception e) {
            Log.e(MainActivity.TAG, "Unexpected exception in deleteKey: " + e.getMessage());
        }

        Button btn = findViewById(R.id.saveCertificationPath);
        btn.setEnabled(false);

        btn = findViewById(R.id.installCaSignedCertificate);
        btn.setEnabled(false);

        btn = findViewById(R.id.deleteKey);
        btn.setEnabled(false);
    }
    //endregion
}
