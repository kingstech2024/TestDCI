package androidtestdci.hound.red.testdci;

import android.content.Context;
import android.os.AsyncTask;
import android.security.KeyChain;
import android.util.Log;

import java.lang.ref.WeakReference;
import java.security.cert.X509Certificate;

class GetCertChainTask extends AsyncTask<Void, Void, Void> {

    interface OnGetCertChainComplete {
        void onGetCertChainComplete(X509Certificate[] chain);
    }

    //Application context provided by the caller
    private final WeakReference<Context> m_ctx;

    // Key generation parameter spec provided by the caller
    private final String m_alias;

    // Callback to invoke upon completion with the AttestedKeyPair
    private final OnGetCertChainComplete m_callback;

    // X509Certificate[] object returned by getCertificateChain (for return to caller via callback)
    private X509Certificate[] m_chain = null;

    //---------------------------------------------------------------------------------------------
    // Constructor
    //---------------------------------------------------------------------------------------------
    public GetCertChainTask(WeakReference<Context> ctx, String alias, OnGetCertChainComplete callback) {
        m_ctx = ctx;
        m_alias = alias;
        m_callback = callback;
    }

    //---------------------------------------------------------------------------------------------
    // AsyncTask overrides
    //---------------------------------------------------------------------------------------------
    protected Void doInBackground(Void... params) {
        try {
            m_chain = KeyChain.getCertificateChain(m_ctx.get(), m_alias);
        }
        catch (Exception e) {
            Log.e(MainActivity.TAG, "Read certificate chain task failed: " + e.getMessage());
        }
        return null;
    }

    protected void onPostExecute(Void unused)
    {
        if(null != m_callback)
        {
            m_callback.onGetCertChainComplete(m_chain);
        }
    }
}