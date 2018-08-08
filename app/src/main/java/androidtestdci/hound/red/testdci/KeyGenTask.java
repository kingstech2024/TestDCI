package androidtestdci.hound.red.testdci;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.os.AsyncTask;
import android.security.AttestedKeyPair;
import android.security.keystore.KeyGenParameterSpec;
import android.util.Log;

import java.lang.ref.WeakReference;

class KeyGenTask extends AsyncTask<Void, Void, Void> {

    interface OnKeyGenComplete {
        void onKeyGenComplete(AttestedKeyPair akp);
    }

    //Application context provided by the caller
    private final WeakReference<Context> m_ctx;

    // Key generation parameter spec provided by the caller
    private final KeyGenParameterSpec m_spec;

    // Component name provided by caller (based on last key generation situation determination)
    private final ComponentName m_componentName;

    // Attestation flags provided by caller (based on last key generation situation determination)
    private final int m_idAttestationFlags;

    // Callback to invoke upon completion with the AttestedKeyPair
    private final OnKeyGenComplete m_callback;

    // AttestedKeyPair object returned by generatedKeyPair (for return to caller via callback)
    private AttestedKeyPair m_akp = null;

    //---------------------------------------------------------------------------------------------
    // Constructor
    //---------------------------------------------------------------------------------------------
    public KeyGenTask(WeakReference<Context> ctx, KeyGenParameterSpec spec, ComponentName componentName, int attestationFlags, OnKeyGenComplete callback) {
        m_ctx = ctx;
        m_spec = spec;
        m_componentName = componentName;
        m_idAttestationFlags = attestationFlags;
        m_callback = callback;
    }

    //---------------------------------------------------------------------------------------------
    // AsyncTask overrides
    //---------------------------------------------------------------------------------------------
    protected Void doInBackground(Void... params) {
        try {
            final DevicePolicyManager dpm = (DevicePolicyManager) m_ctx.get().getSystemService(Context.DEVICE_POLICY_SERVICE);
            if(null != dpm) {
                m_akp = dpm.generateKeyPair(m_componentName, "RSA", m_spec, m_idAttestationFlags);
            }
        }
        catch (Exception e) {
            Log.e(MainActivity.TAG, "Key generation task failed: " + e.getMessage());
        }
        return null;
    }

    protected void onPostExecute(Void unused)
    {
        if(null != m_callback)
        {
            m_callback.onKeyGenComplete(m_akp);
        }
    }
}