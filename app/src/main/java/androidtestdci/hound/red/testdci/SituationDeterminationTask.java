package androidtestdci.hound.red.testdci;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.os.AsyncTask;
import android.os.Build;
import android.security.AttestedKeyPair;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.lang.ref.WeakReference;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

import static android.app.admin.DevicePolicyManager.ID_TYPE_SERIAL;

/**
 * SituationDeterminationTask uses a combination of DevicePolicyManager APIs (isDeviceOwnerApp and
 * isProfileOwnerApp) and, if necessary, trial and error key generation to determine if the app
 * is able to use the new generateKeyPair API and how the componentName and flags parameters may be
 * used. Additionally, where generateKeyPair can be used, the quality of the attestation record
 * is read (i.e., hardware-protected or software-protected).
 *
 * The aim of this task is to determine if hardware attestation support is available, thus software
 * attestations are not scrutinized to same depth.
 */
class SituationDeterminationTask extends AsyncTask<Void, Void, Void> {

    // interface for callback
    interface OnSituationDeterminationComplete {
        void onSituationDeterminationComplete(MainActivity.KeyGenerationSituation kgs, MainActivity.AttestationQualitySituation as);
    }

    //region Member variables
    //Application context provided by the caller
    private final WeakReference<Context> m_ctx;

    // Callback function to notify upon completion
    private final OnSituationDeterminationComplete m_callback;

    // Alias for keys generated when determining key generation and attestation quality situations
    private static final String m_sniffAlias = "testdci_delegation_check";

    // Last observed key generation situation
    private MainActivity.KeyGenerationSituation m_kgs = MainActivity.KeyGenerationSituation.KEY_GENERATION_SITUATION_UNKNOWN;

    // Last observed attestation quality situation
    private static MainActivity.AttestationQualitySituation m_as = MainActivity.AttestationQualitySituation.ATTESTATION_QUALITY_SITUATION_UNKNOWN;
    //endregion

    //region Constructor and AsyncTask overrides
    public SituationDeterminationTask(WeakReference<Context> ctx, OnSituationDeterminationComplete callback) {
        m_ctx = ctx;
        m_callback = callback;
    }

    protected Void doInBackground(Void... params) {
        try {
            m_kgs = whatsTheSituation(m_ctx.get());
        }
        catch (Exception e) {
            Log.e(MainActivity.TAG, "SituationDeterminationTask failed: " + e.getMessage());
        }
        return null;
    }
    //endregion

    protected void onPostExecute(Void unused)
    {
        if(null != m_callback) {
            m_callback.onSituationDeterminationComplete(m_kgs, m_as);
        }
    }

    //region Helper methods to determine key generation and attestation quality situations
    /**
     * certHasHardwareAttestation reads the KeyDescription extension from the first certificate in
     * the attestation record and reads the 14th byte, which should be the value of the
     * attestationSecurityLevel. For reliable results, the length fields should be inspected and/or
     * the value parsed with a BER decoder.
     *
     * @param akp AttestedKeyPair containing certificate to inspect
     * @return True is the 14th byte of the KeyDescription extension is 1 and False otherwise
     */
    private static boolean certHasHardwareAttestation(AttestedKeyPair akp) {
        /*
        The end entity certificate in the chain returned by the attestation record features
        a KeyDescription extension that is identified by 1.3.6.1.4.1.11129.2.1.17. The
        structure is defined as follows.

        KeyDescription ::= SEQUENCE {
            attestationVersion  INTEGER,
            attestationSecurityLevel  SecurityLevel,
            keymasterVersion  INTEGER,
            keymasterSecurityLevel  SecurityLevel,
            attestationChallenge  OCTET STRING,
            reserved  OCTET STRING,
            softwareEnforced  AuthorizationList,
            teeEnforced  AuthorizationList
        }

        SecurityLevel ::= ENUMERATED {
            software  (0),
            trustedEnvironment  (1)
        }

        As a quick check to see if the device is returning hardware or software-protected
        attestations, read the value of attestationSecurityLevel field. The value is returned
        as an OCTET STRING (i.e. the OCTET STRING field of the extension value). Here's a
        sample from a Pixel 2:

            04 82 01 33 30 82 01 2F 02 01 02 0A 01 01

        Assuming the length is always such that two bytes are required to encode it, the
        attestationSecurityLevel is in the 14th byte.
        */
        if(null != akp) {
            List<Certificate> ar = akp.getAttestationRecord();
            Certificate c = ar.get(0);
            X509Certificate xc = (X509Certificate) c;
            byte[] eb = xc.getExtensionValue("1.3.6.1.4.1.11129.2.1.17");
            byte attestationSecurityLevel = eb[13];
            return 0x01 == attestationSecurityLevel;
        }
        return false;
    }

    private boolean canGenerateKeyWithAttestation(DevicePolicyManager dpm, ComponentName componentName, int flags) {
        if(null == dpm)
            return false;

        try {
            dpm.removeKeyPair(componentName, m_sniffAlias);
        }
        catch(Exception e) {
            Log.e(MainActivity.TAG, "Unexpected exception removing key pair: " + e.getMessage());
        }

        AttestedKeyPair akp = null;
        KeyGenParameterSpec keySpec = new KeyGenParameterSpec.Builder(
                m_sniffAlias,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY | KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(2048)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC, KeyProperties.BLOCK_MODE_CTR, KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1, KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS, KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setAttestationChallenge("challenge".getBytes()).build();

        try {
            akp = dpm.generateKeyPair(componentName, "RSA", keySpec, flags);
        }
        catch(Exception e) {
            Log.e(MainActivity.TAG, "canGenerateKeyWithAttestation failed: " + e.getMessage());
        }

        boolean retval = false;
        if(null != akp) {
            retval = certHasHardwareAttestation(akp);
            dpm.removeKeyPair(componentName, m_sniffAlias);
        }

        return retval;
    }

    private boolean sniffSupportAsDeviceOwnerOrDelegate(Context context)
    {
        boolean retval = false;
        try
        {
            ComponentName componentName = null;

            final DevicePolicyManager dpm = (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
            if(null == dpm) {
                return false;
            }
            else if(dpm.isDeviceOwnerApp(context.getPackageName())) {
                //if we are a device owner, then component name must be non-null. else try as delegate
                componentName = TestDciReceiver.getComponentName(context);
            }

            // try to generate with ID_TYPE_SERIAL, which is only available to device owners or
            // device owner delegates.
            retval = canGenerateKeyWithAttestation(dpm, componentName, ID_TYPE_SERIAL);
        }
        catch(Exception e) {
            Log.e(MainActivity.TAG, "sniffSupportAsDeviceOwnerOrDelegate failed: " + e.getMessage());
        }
        return retval;
    }

    private boolean sniffSupportAsProfileOwnerOrDelegate(Context context)
    {
        boolean retval = false;
        try
        {
            ComponentName componentName = null;

            final DevicePolicyManager dpm = (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
            if(null == dpm) {
                return false;
            }
            else if(dpm.isProfileOwnerApp(context.getPackageName())) {
                componentName = TestDciReceiver.getComponentName(context);
            }

            // use 0 as the flags value since this method is not trying to determine if support for
            // device identification (available only to device owners or device owner delegates) is
            // supported
            retval = canGenerateKeyWithAttestation(dpm, componentName, 0);
        }
        catch(Exception e) {
            Log.e(MainActivity.TAG, "sniffSupportAsProfileOwnerOrDelegate failed: " + e.getMessage());
        }
        return retval;
    }

    /**
     * amIProfileOwner returns true if the application (as identified by the name returned by
     * context.getPackageName()) is indicated as a policy managed via
     * DevicePolicyManager.isProfileOwnerApp().
     *
     * @param context Application context
     * @return True is app is a profile owner and false otherwise
     */
    private boolean amIProfileOwner(Context context) {
        DevicePolicyManager devicePolicyManager = (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
        if(null != devicePolicyManager)
            return devicePolicyManager.isProfileOwnerApp(context.getPackageName());
        else
            return false;
    }

    /**
     * amIDeviceOwner returns true if the application (as identified by the name returned by
     * context.getPackageName()) is indicated as a policy managed via
     * DevicePolicyManager.isDeviceOwnerApp().
     *
     * This is useful to determine if key generation can proceed and whether or not device
     * identification can be included in an attestation.
     *
     * @param context Application context
     * @return True is app is a device owner and false otherwise
     */
    private boolean amIDeviceOwner(Context context) {
        DevicePolicyManager devicePolicyManager = (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
        if(null != devicePolicyManager)
            return devicePolicyManager.isDeviceOwnerApp(context.getPackageName());
        else
            return false;
    }

    private MainActivity.AttestationQualitySituation doesSystemSupportAttestedHardwareKeys(Context ctx) {
        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            if(sniffSupportAsDeviceOwnerOrDelegate(ctx)){
                Log.i(MainActivity.TAG, Build.MODEL + " device from " + Build.MANUFACTURER + " running " + Build.VERSION.SDK_INT + " supports attested hardware keys with device ID inclusion.");
                return MainActivity.AttestationQualitySituation.HARDWARE_ATTESTATION_WITH_DEVICE_ID;
            }
            else if(sniffSupportAsProfileOwnerOrDelegate(ctx)){
                Log.i(MainActivity.TAG, Build.MODEL + " device from " + Build.MANUFACTURER + " running " + Build.VERSION.SDK_INT + " supports attested hardware keys without device ID inclusion.");
                return MainActivity.AttestationQualitySituation.HARDWARE_ATTESTATION_WITHOUT_DEVICE_ID;
            }
        }
        Log.i(MainActivity.TAG, Build.MODEL + " device from " + Build.MANUFACTURER + " running " + Build.VERSION.SDK_INT + " does not support attested hardware keys.");
        return MainActivity.AttestationQualitySituation.SOFTWARE_ATTESTATION;
    }

    /**
     * whatsTheSituation is the entry point for this task. It uses doesSystemSupportAttestedHardwareKeys
     * to suss out if *hardware* attestations can be obtained. If so, further classification is
     * performed. For software, no further classification is performed because software attestations
     * are of no interest and need not be generated (i.e., challenege can be omitted when working
     * with devices or contexts that only emit software attestations).
     *
     * @param ctx Application context provided by caller
     * @return KeyGenerationSituation value
     */
    private MainActivity.KeyGenerationSituation whatsTheSituation(Context ctx) {
        m_as = doesSystemSupportAttestedHardwareKeys(ctx);

        if(MainActivity.AttestationQualitySituation.HARDWARE_ATTESTATION_WITH_DEVICE_ID == m_as) {
            // if we got an attestation quality that indicates device ID, then we know we are
            // either a device owner or a device owner delegate. figure out which (since this
            // impacts the componentName value passed to the generateKey API).
            if(amIDeviceOwner(ctx)){
                return MainActivity.KeyGenerationSituation.DEVICE_OWNER;
            }
            else {
                return MainActivity.KeyGenerationSituation.DEVICE_OWNER_DELEGATE;
            }
        }
        else if(MainActivity.AttestationQualitySituation.HARDWARE_ATTESTATION_WITHOUT_DEVICE_ID == m_as) {
            // if we got an attestation quality that indicates no device ID, then we know we are
            // either a profile owner or a profile owner delegate. figure out which (since this
            // impacts the componentName value passed to the generateKey API).
            if(amIDeviceOwner(ctx)){
                return MainActivity.KeyGenerationSituation.DEVICE_OWNER_NO_DEVICE_ID_SUPPORT;
            }
            else if(amIProfileOwner(ctx)) {
                return MainActivity.KeyGenerationSituation.PROFILE_OWNER_NO_DEVICE_ID_SUPPORT;
            }
            else {
                return MainActivity.KeyGenerationSituation.PROFILE_OWNER_DELEGATE_NO_DEVICE_ID_SUPPORT;
            }
        }
        return MainActivity.KeyGenerationSituation.HARDWARE_KEY_GENERATION_NOT_SUPPORTED;
    }
    //endregion
}